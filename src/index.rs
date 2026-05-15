//! Encrypted metadata index.
//!
//! Records which vaults exist and where they live. Encrypted at rest under a
//! per-install key kept in `<data_dir>/index.key` with restrictive
//! permissions. This is a v0.2 stopgap: a same-user attacker who can read the
//! data dir gets both halves. The intent here is just to keep cloud-sync /
//! backup software from snapshotting plaintext metadata.
//!
//! v0.5 will move this key into the OS keyring (Credential Manager / Keychain
//! / Secret Service).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use directories::ProjectDirs;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

const INDEX_MAGIC: &[u8; 4] = b"PIDX";
const INDEX_VERSION: u16 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedProfile {
    pub vault_id: String,
    pub browser: String,
    pub profile_id: String,
    pub profile_name: String,
    pub original_path: PathBuf,
    pub vault_path: PathBuf,
    pub locked_at: String,
    pub has_recovery: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Index {
    pub locked_profiles: HashMap<String, LockedProfile>,
}

impl Index {
    pub fn load() -> Result<Self> {
        let path = Self::index_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let blob = fs::read(&path)?;
        let key = load_or_init_key()?;
        let plaintext = decrypt(&blob, &key)?;
        let parsed: Index = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::Config(format!("index parse: {e}")))?;
        Ok(parsed)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::index_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let key = load_or_init_key()?;
        let plaintext = serde_json::to_vec(self)
            .map_err(|e| VaultError::Config(format!("index serialize: {e}")))?;
        let blob = encrypt(&plaintext, &key)?;

        // Atomic write: write to .tmp then rename.
        let tmp = path.with_extension("idx.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn index_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
            .ok_or_else(|| VaultError::Config("no project dirs".into()))?;
        Ok(dirs.data_dir().join("index.pvi"))
    }

    pub fn vault_dir() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
            .ok_or_else(|| VaultError::Config("no project dirs".into()))?;
        let vault_dir = dirs.data_dir().join("vaults");
        fs::create_dir_all(&vault_dir)?;
        Ok(vault_dir)
    }

    pub fn pending_delete_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
            .ok_or_else(|| VaultError::Config("no project dirs".into()))?;
        Ok(dirs.data_dir().join("pending_delete.json"))
    }

    fn key(browser: &str, profile_id: &str) -> String {
        format!("{}:{}", browser.to_lowercase(), profile_id)
    }

    pub fn add(&mut self, profile: LockedProfile) {
        let k = Self::key(&profile.browser, &profile.profile_id);
        self.locked_profiles.insert(k, profile);
    }

    pub fn remove(&mut self, browser: &str, profile_id: &str) -> Option<LockedProfile> {
        let k = Self::key(browser, profile_id);
        self.locked_profiles.remove(&k)
    }

    pub fn get(&self, browser: &str, profile_id: &str) -> Option<&LockedProfile> {
        let k = Self::key(browser, profile_id);
        self.locked_profiles.get(&k)
    }

    pub fn is_locked(&self, browser: &str, profile_id: &str) -> bool {
        self.get(browser, profile_id).is_some()
    }
}

fn key_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
        .ok_or_else(|| VaultError::Config("no project dirs".into()))?;
    Ok(dirs.data_dir().join("index.key"))
}

fn load_or_init_key() -> Result<[u8; KEY_LEN]> {
    let path = key_path()?;
    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() != KEY_LEN {
            return Err(VaultError::Config("index key file is wrong size".into()));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&bytes);
        return Ok(k);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut k = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut k);
    write_key_restricted(&path, &k)?;
    Ok(k)
}

#[cfg(unix)]
fn write_key_restricted(path: &std::path::Path, key: &[u8; KEY_LEN]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(key)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn write_key_restricted(path: &std::path::Path, key: &[u8; KEY_LEN]) -> Result<()> {
    // NTFS inherits ACLs from the parent dir, which for AppData\Roaming and
    // \Local is already restricted to the current user. A future hardening
    // step is to apply an explicit SDDL DACL here; for v0.2 we rely on the
    // inherited ACL.
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    f.write_all(key)?;
    f.sync_all()?;
    Ok(())
}

fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = build_aad();
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

    let mut out = Vec::with_capacity(aad.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(blob: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let aad_len = 4 + 2;
    if blob.len() < aad_len + NONCE_LEN {
        return Err(VaultError::Config("index blob too short".into()));
    }
    let aad = &blob[..aad_len];
    if &aad[..4] != INDEX_MAGIC {
        return Err(VaultError::Config("index magic mismatch".into()));
    }
    let version = u16::from_le_bytes(aad[4..6].try_into().unwrap());
    if version != INDEX_VERSION {
        return Err(VaultError::Config(format!("unsupported index version {version}")));
    }
    let nonce = Nonce::from_slice(&blob[aad_len..aad_len + NONCE_LEN]);
    let ct = &blob[aad_len + NONCE_LEN..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Config(e.to_string()))?;
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| VaultError::Config("index decryption failed — key or file corrupt".into()))
}

fn build_aad() -> [u8; 6] {
    let mut aad = [0u8; 6];
    aad[..4].copy_from_slice(INDEX_MAGIC);
    aad[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
    aad
}
