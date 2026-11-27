//! High-level lock / unlock orchestration.
//!
//! Lock flow (commit-then-cleanup; the previous design deleted plaintext
//! before the vault was durable on disk — that's the v0.1 data-loss bug
//! this fixes):
//!
//!   1. Generate vault UUID, salt, random DEK.
//!   2. Derive password-KEK via Argon2id.
//!   3. Stream profile → tar → zstd → chunked AEAD → vault.tmp.
//!   4. Patch chunk_count into the header, write footer, fsync.
//!   5. Atomic rename vault.tmp → vault.pvlt.
//!   6. Write a `pending_delete` record naming the plaintext to remove.
//!   7. Update the encrypted index.
//!   8. Delete the plaintext profile directory.
//!   9. Clear the pending_delete record.
//!
//! Crashes between (5) and (9) are recoverable: the vault file is valid,
//! pending_delete tells us what's left to clean up.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::browser::{Browser, ProfileInfo};
use crate::crypto::{
    derive_kek_argon2, derive_kek_hkdf, make_kek_check, random_salt, random_uuid_bytes, unwrap_dek,
    verify_kek_check, wrap_dek, Key,
};
use crate::error::{Result, VaultError};
use crate::format::{
    read_header, verify_footer, write_footer, Header, KdfParams, AEAD_ID_AES256_GCM, CHUNK_SIZE,
    FLAG_HAS_RECOVERY, HEADER_SIZE, KDF_ID_ARGON2ID, VERSION,
};
use crate::index::{Index, LockedProfile};
use crate::pipeline::{ChunkedDecryptReader, ChunkedEncryptWriter};
use crate::process::is_profile_in_use;
use crate::recovery::{self, Recovery};

const ZSTD_LEVEL: i32 = 3;

pub struct LockResult {
    pub recovery: Option<Recovery>,
}

pub struct Vault {
    index: Index,
    _guard: File,
}

impl Vault {
    pub fn new() -> Result<Self> {
        let lock_path = Index::index_path()?.with_extension("lock");
        fs::create_dir_all(lock_path.parent().unwrap())?;
        let guard = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        guard
            .try_lock()
            .map_err(|_| VaultError::Config("Another archive operation is running".into()))?;
        let index = Index::load()?;
        // Best-effort: finish any plaintext deletion left dangling by a prior crash.
        reconcile_pending_delete(&index);
        Ok(Self {
            index,
            _guard: guard,
        })
    }

    pub fn is_locked(&self, browser: &Browser, profile_id: &str) -> bool {
        self.index.is_locked(browser.name(), profile_id)
    }

    pub fn list_locked(&self) -> Vec<&LockedProfile> {
        self.index.locked_profiles.values().collect()
    }

    /// Lock a profile. If `with_recovery` is true, generates a 24-word BIP39
    /// recovery phrase and returns it inside [`LockResult`] — the caller is
    /// responsible for displaying it to the user exactly once.
    pub fn lock_profile(
        &mut self,
        profile: &ProfileInfo,
        password: &Zeroizing<String>,
        with_recovery: bool,
    ) -> Result<LockResult> {
        let browser_name = profile.browser.name();
        if self.index.is_locked(browser_name, &profile.id) {
            return Err(VaultError::AlreadyLocked);
        }
        if !profile.path.exists() {
            return Err(VaultError::ProfileNotFound(profile.display()));
        }
        if is_profile_in_use(&profile.browser, &profile.path) {
            return Err(VaultError::ProfileInUse);
        }

        let vault_dir = Index::vault_dir()?;
        let vault_uuid = random_uuid_bytes();
        let vault_final = vault_dir.join(format!("{}.pvlt", uuid::Uuid::from_bytes(vault_uuid)));
        let temp = tempfile::Builder::new()
            .prefix(".archive-")
            .tempfile_in(&vault_dir)?;
        let vault_tmp = temp.into_temp_path();
        // write_archive creates its own file. The random name remains reserved
        // by this command's exclusive archive lock.
        fs::remove_file(&vault_tmp)?;
        let recovery = write_archive(
            &profile.path,
            &vault_tmp,
            password,
            with_recovery,
            vault_uuid,
            KdfParams::strong_default(),
        )?;

        // Atomic rename → vault is now durable.
        fs::rename(&vault_tmp, &vault_final)?;

        // Record what we're about to delete, BEFORE deleting it.
        record_pending_delete(&profile.path)?;

        // Update the index.
        let locked = LockedProfile {
            vault_id: uuid::Uuid::from_bytes(vault_uuid).to_string(),
            browser: browser_name.to_string(),
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            original_path: profile.path.clone(),
            vault_path: vault_final,
            locked_at: Utc::now().to_rfc3339(),
            has_recovery: with_recovery,
        };
        self.index.add(locked);
        self.index.save()?;

        // Now do the actual delete.
        fs::remove_dir_all(&profile.path)?;
        clear_pending_delete(&profile.path)?;

        Ok(LockResult { recovery })
    }

    pub fn unlock_with_password(
        &mut self,
        browser: &Browser,
        profile_id: &str,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        let locked = self.lookup(browser, profile_id)?.clone();
        let (header, _data_end) = open_and_validate(&locked.vault_path)?;
        let kek = derive_kek_argon2(password, &header.salt, &header.kdf)?;
        let aad = header.aad();
        verify_kek_check(&kek, &header.kek_check, &aad)?;
        let dek = unwrap_dek(&kek, &header.wrapped_dek, &aad)?;
        self.finish_unlock(&locked, &header, dek)
    }

    pub fn unlock_with_recovery(
        &mut self,
        browser: &Browser,
        profile_id: &str,
        phrase: &str,
    ) -> Result<()> {
        let locked = self.lookup(browser, profile_id)?.clone();
        let (header, _data_end) = open_and_validate(&locked.vault_path)?;
        let wrapped_rec = header
            .wrapped_recovery_dek
            .ok_or(VaultError::InvalidRecovery)?;
        let entropy = recovery::parse(phrase)?;
        let kek = derive_kek_hkdf(&entropy, &header.salt)?;
        let aad = header.aad();
        let dek = unwrap_dek(&kek, &wrapped_rec, &aad).map_err(|e| match e {
            VaultError::InvalidPassword => VaultError::InvalidRecovery,
            other => other,
        })?;
        self.finish_unlock(&locked, &header, dek)
    }

    fn lookup(&self, browser: &Browser, profile_id: &str) -> Result<&LockedProfile> {
        self.index
            .get(browser.name(), profile_id)
            .ok_or(VaultError::NotLocked)
    }

    fn finish_unlock(&mut self, locked: &LockedProfile, header: &Header, dek: Key) -> Result<()> {
        let browser = Browser::from_str(&locked.browser)?;
        if is_profile_in_use(&browser, &locked.original_path) {
            return Err(VaultError::ProfileInUse);
        }
        let parent = locked
            .original_path
            .parent()
            .ok_or_else(|| VaultError::Config("Profile has no parent directory".into()))?;
        fs::create_dir_all(parent)?;
        let staging = tempfile::Builder::new()
            .prefix(".pvault-restore-")
            .tempdir_in(parent)?;
        extract_archive(&locked.vault_path, header, dek, staging.path())?;
        if is_profile_in_use(&browser, &locked.original_path) {
            return Err(VaultError::ProfileInUse);
        }
        if locked.original_path.try_exists()? {
            let backup = parent.join(format!("pvault-backup-{}", uuid::Uuid::new_v4()));
            fs::rename(&locked.original_path, &backup)?;
            eprintln!(
                "Saved the browser-created replacement profile at {}",
                backup.display()
            );
        }
        fs::rename(staging.path(), &locked.original_path)?;

        clear_pending_delete(&locked.original_path)?;
        let key = (locked.browser.clone(), locked.profile_id.clone());
        self.index.remove(&key.0, &key.1);
        self.index.save()?;
        fs::remove_file(&locked.vault_path)?;

        Ok(())
    }
}

fn write_archive(
    source: &Path,
    vault_tmp: &Path,
    password: &Zeroizing<String>,
    with_recovery: bool,
    vault_uuid: [u8; 16],
    kdf: KdfParams,
) -> Result<Option<Recovery>> {
    let salt = random_salt();
    let dek = Key::random();
    let kek = derive_kek_argon2(password, &salt, &kdf)?;

    // Optional recovery slot: HKDF over mnemonic entropy.
    let recovery = if with_recovery {
        Some(recovery::generate()?)
    } else {
        None
    };
    // Every key slot authenticates the same immutable header fields,
    // including the creation timestamp. Only chunk_count changes later.
    let mut header = build_header(&vault_uuid, &salt, &kdf, with_recovery);
    let aad = header.aad();
    header.wrapped_dek = wrap_dek(&kek, &dek, &aad)?;
    header.kek_check = make_kek_check(&kek, &aad)?;
    if let Some(rec) = &recovery {
        let rec_kek = derive_kek_hkdf(&rec.entropy, &salt)?;
        header.wrapped_recovery_dek = Some(wrap_dek(&rec_kek, &dek, &aad)?);
    }

    // Open the .tmp, write a placeholder header, then stream chunks.
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(vault_tmp)?;
    file.write_all(&[0u8; HEADER_SIZE])?;

    let dek_for_stream = Key(*dek.as_bytes());
    let chunked = ChunkedEncryptWriter::new(file, dek_for_stream, vault_uuid);
    let zstd = zstd::Encoder::new(chunked, ZSTD_LEVEL)
        .map_err(|e| VaultError::EncryptionError(format!("zstd: {e}")))?;
    let mut tar = tar::Builder::new(zstd);
    // follow_symlinks=false: profiles can contain symlinks (rare); we
    // archive the link, not the target.
    tar.follow_symlinks(false);
    tar.append_dir_all(".", source)
        .map_err(|e| VaultError::EncryptionError(format!("tar append: {e}")))?;

    let zstd = tar
        .into_inner()
        .map_err(|e| VaultError::EncryptionError(format!("tar finish: {e}")))?;
    let chunked = zstd
        .finish()
        .map_err(|e| VaultError::EncryptionError(format!("zstd finish: {e}")))?;
    let (mut file, chunk_count) = chunked
        .finish()
        .map_err(|e| VaultError::EncryptionError(format!("encrypt finish: {e}")))?;

    header.chunk_count = chunk_count;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.to_bytes())?;
    file.seek(SeekFrom::End(0))?;
    write_footer(&mut file)?;
    file.sync_all()?;
    drop(file);

    Ok(recovery)
}

fn extract_archive(vault_path: &Path, header: &Header, dek: Key, extract_tmp: &Path) -> Result<()> {
    let mut chunk_reader = File::open(vault_path)?;
    let data_end = verify_footer(&mut chunk_reader)?;
    chunk_reader.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

    let decrypt = ChunkedDecryptReader::new(
        chunk_reader.take(data_end - HEADER_SIZE as u64),
        dek,
        header.vault_uuid,
        header.chunk_count,
    );
    let zstd = zstd::Decoder::new(decrypt)
        .map_err(|e| VaultError::DecryptionError(format!("zstd: {e}")))?;
    let mut archive = tar::Archive::new(zstd);
    archive.set_preserve_permissions(true);
    let entries = archive
        .entries()
        .map_err(|e| VaultError::DecryptionError(format!("tar entries: {e}")))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| VaultError::DecryptionError(format!("tar entry: {e}")))?;
        if !entry
            .unpack_in(extract_tmp)
            .map_err(|e| VaultError::DecryptionError(format!("tar unpack: {e}")))?
        {
            return Err(VaultError::Corrupt(
                "Archive entry escapes profile directory".into(),
            ));
        }
    }

    // tar can finish before zstd reaches its final authenticated chunk.
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    Ok(())
}

fn open_and_validate(path: &Path) -> Result<(Header, u64)> {
    let mut file = File::open(path)?;
    let data_end = verify_footer(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    let header = read_header(&mut file)?;
    if header.kdf_id != KDF_ID_ARGON2ID {
        return Err(VaultError::UnsupportedFormat(header.version));
    }
    if header.aead_id != AEAD_ID_AES256_GCM {
        return Err(VaultError::UnsupportedFormat(header.version));
    }
    let payload = data_end - HEADER_SIZE as u64;
    let full_chunk = CHUNK_SIZE as u64 + 28;
    if header.chunk_size != CHUNK_SIZE
        || header.chunk_count == 0
        || payload < 29
        || header.chunk_count != payload.div_ceil(full_chunk)
        || payload - (header.chunk_count - 1) * full_chunk < 29
    {
        return Err(VaultError::Corrupt("Invalid encrypted chunk layout".into()));
    }
    Ok((header, data_end))
}

fn build_header(
    vault_uuid: &[u8; 16],
    salt: &[u8; 32],
    kdf: &KdfParams,
    has_recovery: bool,
) -> Header {
    let flags = if has_recovery { FLAG_HAS_RECOVERY } else { 0 };
    Header {
        version: VERSION,
        flags,
        vault_uuid: *vault_uuid,
        created_at: Utc::now().timestamp(),
        kdf_id: KDF_ID_ARGON2ID,
        kdf: kdf.clone(),
        salt: *salt,
        aead_id: AEAD_ID_AES256_GCM,
        chunk_size: CHUNK_SIZE,
        chunk_count: 0,
        wrapped_dek: [0; 60],
        kek_check: [0; 41],
        wrapped_recovery_dek: None,
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PendingDeletes {
    paths: Vec<PathBuf>,
}

fn record_pending_delete(path: &Path) -> Result<()> {
    let p = Index::pending_delete_path()?;
    let mut current: PendingDeletes = if p.exists() {
        let bytes = fs::read(&p).unwrap_or_default();
        serde_json::from_slice(&bytes).unwrap_or_default()
    } else {
        PendingDeletes::default()
    };
    if !current.paths.iter().any(|x| x == path) {
        current.paths.push(path.to_path_buf());
    }
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = p.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec(&current).unwrap())?;
    fs::rename(&tmp, &p)?;
    Ok(())
}

fn clear_pending_delete(path: &Path) -> Result<()> {
    let p = Index::pending_delete_path()?;
    if !p.exists() {
        return Ok(());
    }
    let bytes = fs::read(&p)?;
    let mut current: PendingDeletes = serde_json::from_slice(&bytes).unwrap_or_default();
    current.paths.retain(|x| x != path);
    if current.paths.is_empty() {
        let _ = fs::remove_file(&p);
    } else {
        let tmp = p.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec(&current).unwrap())?;
        fs::rename(&tmp, &p)?;
    }
    Ok(())
}

/// Best-effort: finish any plaintext deletion left dangling by a prior crash.
/// Only deletes a path if a corresponding vault exists in the index, i.e. we
/// know the vault committed and the plaintext is now redundant.
fn reconcile_pending_delete(index: &Index) {
    let Ok(p) = Index::pending_delete_path() else {
        return;
    };
    if !p.exists() {
        return;
    }
    let Ok(bytes) = fs::read(&p) else { return };
    let pending: PendingDeletes = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut still_pending = PendingDeletes::default();
    for path in pending.paths {
        let Some(locked) = index
            .locked_profiles
            .values()
            .find(|l| l.original_path == path)
        else {
            still_pending.paths.push(path);
            continue;
        };
        let safe_to_clean = Browser::from_str(&locked.browser)
            .map(|browser| !is_profile_in_use(&browser, &path))
            .unwrap_or(false)
            && open_and_validate(&locked.vault_path)
                .map(|(header, _)| {
                    uuid::Uuid::from_bytes(header.vault_uuid).to_string() == locked.vault_id
                })
                .unwrap_or(false);
        if path.exists() && (!safe_to_clean || fs::remove_dir_all(&path).is_err()) {
            still_pending.paths.push(path);
        }
    }

    if still_pending.paths.is_empty() {
        let _ = fs::remove_file(&p);
    } else {
        let _ = fs::write(&p, serde_json::to_vec(&still_pending).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_archive_with_password_and_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let file = tmp.path().join("profile.pvlt");
        fs::create_dir(&source).unwrap();
        let bytes = b"disposable profile contents";
        fs::write(source.join("History"), bytes).unwrap();
        let password = Zeroizing::new("fixture password".to_string());
        let recovery = write_archive(
            &source,
            &file,
            &password,
            true,
            random_uuid_bytes(),
            KdfParams {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
        .unwrap();
        let (header, end) = open_and_validate(&file).unwrap();
        let kek = derive_kek_argon2(&password, &header.salt, &header.kdf).unwrap();
        let wrong =
            derive_kek_argon2(&Zeroizing::new("wrong".into()), &header.salt, &header.kdf).unwrap();
        assert!(verify_kek_check(&wrong, &header.kek_check, &header.aad()).is_err());
        let recovery_key = derive_kek_hkdf(&recovery.entropy, &header.salt).unwrap();
        for (slot, key, name) in [
            (header.wrapped_dek, &kek, "password"),
            (
                header.wrapped_recovery_dek.unwrap(),
                &recovery_key,
                "recovery",
            ),
        ] {
            let target = tmp.path().join(name);
            fs::create_dir(&target).unwrap();
            let dek = unwrap_dek(key, &slot, &header.aad()).unwrap();
            extract_archive(&file, &header, dek, &target).unwrap();
            assert_eq!(fs::read(target.join("History")).unwrap(), bytes);
        }
        let mut damaged = fs::read(&file).unwrap();
        damaged[end as usize - 1] ^= 1;
        fs::write(&file, damaged).unwrap();
        let dek = unwrap_dek(&kek, &header.wrapped_dek, &header.aad()).unwrap();
        assert!(extract_archive(&file, &header, dek, tmp.path()).is_err());
    }
}
