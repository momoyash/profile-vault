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
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::browser::{Browser, ProfileInfo};
use crate::crypto::{
    derive_kek_argon2, derive_kek_hkdf, make_kek_check, random_salt, random_uuid_bytes,
    unwrap_dek, verify_kek_check, wrap_dek, Key,
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
}

impl Vault {
    pub fn new() -> Result<Self> {
        let index = Index::load()?;
        // Best-effort: finish any plaintext deletion left dangling by a prior crash.
        reconcile_pending_delete(&index);
        Ok(Self { index })
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
        let vault_final = vault_dir.join(format!(
            "{}_{}.pvlt",
            browser_name.to_lowercase(),
            sanitize(&profile.id)
        ));
        let vault_tmp = vault_final.with_extension("pvlt.tmp");

        let salt = random_salt();
        let kdf = KdfParams::strong_default();
        let vault_uuid = random_uuid_bytes();
        let dek = Key::random();
        let kek = derive_kek_argon2(password, &salt, &kdf)?;

        // Optional recovery slot: HKDF over mnemonic entropy.
        let recovery = if with_recovery {
            Some(recovery::generate()?)
        } else {
            None
        };
        let wrapped_recovery_dek = if let Some(rec) = &recovery {
            let rec_kek = derive_kek_hkdf(&rec.entropy, &salt)?;
            // Build a temporary header to compute AAD. The AAD covers
            // everything in [0..AAD_END), which doesn't depend on chunk_count.
            let placeholder = build_header(
                &vault_uuid,
                &salt,
                &kdf,
                with_recovery,
                /*chunk_count=*/ 0,
                [0u8; 60],
                [0u8; 41],
                None,
            );
            let aad = placeholder.aad();
            Some(wrap_dek(&rec_kek, &dek, &aad)?)
        } else {
            None
        };

        // Open the .tmp, write a placeholder header, then stream chunks.
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&vault_tmp)?;
        file.write_all(&[0u8; HEADER_SIZE])?;

        let dek_for_stream = Key(*dek.as_bytes());
        let chunked = ChunkedEncryptWriter::new(file, dek_for_stream, vault_uuid);
        let zstd = zstd::Encoder::new(chunked, ZSTD_LEVEL)
            .map_err(|e| VaultError::EncryptionError(format!("zstd: {e}")))?;
        let mut tar = tar::Builder::new(zstd);
        // follow_symlinks=false: profiles can contain symlinks (rare); we
        // archive the link, not the target.
        tar.follow_symlinks(false);
        tar.append_dir_all(".", &profile.path).map_err(|e| {
            VaultError::EncryptionError(format!("tar append: {e}"))
        })?;

        let zstd = tar
            .into_inner()
            .map_err(|e| VaultError::EncryptionError(format!("tar finish: {e}")))?;
        let chunked = zstd
            .finish()
            .map_err(|e| VaultError::EncryptionError(format!("zstd finish: {e}")))?;
        let (mut file, chunk_count) = chunked
            .finish()
            .map_err(|e| VaultError::EncryptionError(format!("encrypt finish: {e}")))?;

        // Build the final header now that chunk_count is known.
        let placeholder = build_header(
            &vault_uuid,
            &salt,
            &kdf,
            with_recovery,
            chunk_count,
            [0; _],
            [0; _],
            wrapped_recovery_dek,
        );
        let aad = placeholder.aad();
        let wrapped_dek_bytes = wrap_dek(&kek, &dek, &aad)?;
        let kek_check_bytes = make_kek_check(&kek, &aad)?;

        let final_header = build_header(
            &vault_uuid,
            &salt,
            &kdf,
            with_recovery,
            chunk_count,
            wrapped_dek_bytes,
            kek_check_bytes,
            wrapped_recovery_dek,
        );

        // Patch in the real header.
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&final_header.to_bytes())?;
        file.seek(SeekFrom::End(0))?;
        write_footer(&mut file)?;
        file.sync_all()?;
        drop(file);

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

    fn finish_unlock(
        &mut self,
        locked: &LockedProfile,
        header: &Header,
        dek: Key,
    ) -> Result<()> {
        // If the target path still exists (browser may have recreated an
        // empty dir), wipe it before extraction. The user has authenticated;
        // overwriting is the desired behavior.
        if locked.original_path.exists() {
            fs::remove_dir_all(&locked.original_path)?;
        }
        if let Some(parent) = locked.original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let extract_tmp = locked.original_path.with_extension("pvault_unlock_tmp");
        if extract_tmp.exists() {
            fs::remove_dir_all(&extract_tmp)?;
        }
        fs::create_dir_all(&extract_tmp)?;

        let file = File::open(&locked.vault_path)?;
        let mut chunk_reader = file;
        chunk_reader.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        let dek_for_stream = Key(*dek.as_bytes());
        let decrypt =
            ChunkedDecryptReader::new(chunk_reader, dek_for_stream, header.vault_uuid, header.chunk_count);
        let zstd = zstd::Decoder::new(decrypt)
            .map_err(|e| VaultError::DecryptionError(format!("zstd: {e}")))?;
        let mut archive = tar::Archive::new(zstd);
        archive.set_preserve_permissions(true);
        archive
            .unpack(&extract_tmp)
            .map_err(|e| VaultError::DecryptionError(format!("tar unpack: {e}")))?;

        fs::rename(&extract_tmp, &locked.original_path)?;

        let key = (locked.browser.clone(), locked.profile_id.clone());
        self.index.remove(&key.0, &key.1);
        self.index.save()?;
        fs::remove_file(&locked.vault_path)?;

        Ok(())
    }
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
    Ok((header, data_end))
}

#[allow(clippy::too_many_arguments)]
fn build_header(
    vault_uuid: &[u8; 16],
    salt: &[u8; 32],
    kdf: &KdfParams,
    has_recovery: bool,
    chunk_count: u64,
    wrapped_dek: [u8; 60],
    kek_check: [u8; 41],
    wrapped_recovery_dek: Option<[u8; 60]>,
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
        chunk_count,
        wrapped_dek,
        kek_check,
        wrapped_recovery_dek,
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect()
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

    let known_paths: std::collections::HashSet<PathBuf> = index
        .locked_profiles
        .values()
        .map(|l| l.original_path.clone())
        .collect();

    let mut still_pending = PendingDeletes::default();
    for path in pending.paths {
        if known_paths.contains(&path) && path.exists() {
            let _ = fs::remove_dir_all(&path);
        } else if path.exists() {
            // Vault not in index but plaintext still here — leave it; the
            // user can decide. Don't auto-delete without index proof.
            still_pending.paths.push(path);
        }
    }

    if still_pending.paths.is_empty() {
        let _ = fs::remove_file(&p);
    } else {
        let _ = fs::write(&p, serde_json::to_vec(&still_pending).unwrap());
    }
}
