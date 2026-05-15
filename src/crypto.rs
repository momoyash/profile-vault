//! Key derivation and authenticated encryption primitives.
//!
//! Key hierarchy:
//!   password ──Argon2id──► KEK ──AES-GCM──► DEK (random per vault)
//!   recovery_entropy ──HKDF──► RecoveryKEK ──AES-GCM──► DEK
//!
//! `DEK` encrypts chunk data. Wrapping DEK separately from the password lets
//! us rotate passwords without re-encrypting the body, and lets us add a
//! recovery slot without giving the recovery code knowledge of the password.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};
use crate::format::{
    chunk_aad, KdfParams, KEK_CHECK_LEN, KEK_CHECK_PLAINTEXT, KEY_LEN, NONCE_LEN, SALT_LEN,
    TAG_LEN, WRAPPED_DEK_LEN,
};

const HKDF_RECOVERY_INFO: &[u8] = b"profile-vault recovery v2";

/// Wrapper for 32-byte symmetric keys that zeroes on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key(pub [u8; KEY_LEN]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([REDACTED])")
    }
}

impl Key {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn random_uuid_bytes() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

/// Derive the password-KEK using Argon2id with the parameters stored in the
/// vault header. The password is wiped on drop.
pub fn derive_kek_argon2(password: &Zeroizing<String>, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost as u32, Some(KEY_LEN))
        .map_err(|e| VaultError::EncryptionError(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::EncryptionError(format!("argon2 hash: {e}")))?;
    Ok(Key(out))
}

/// Derive the recovery-KEK from a high-entropy mnemonic. HKDF is correct here
/// (entropy is already uniform); we do NOT use Argon2 a second time.
pub fn derive_kek_hkdf(entropy: &[u8], salt: &[u8; SALT_LEN]) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(Some(salt), entropy);
    let mut out = [0u8; KEY_LEN];
    hk.expand(HKDF_RECOVERY_INFO, &mut out)
        .map_err(|e| VaultError::EncryptionError(format!("hkdf: {e}")))?;
    Ok(Key(out))
}

fn cipher(key: &Key) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| VaultError::EncryptionError(e.to_string()))
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Wrap the DEK under a KEK using AES-GCM. AAD ties the wrapping to the header
/// parameters so a swapped salt/KDF block fails to unwrap.
pub fn wrap_dek(kek: &Key, dek: &Key, aad: &[u8]) -> Result<[u8; WRAPPED_DEK_LEN]> {
    let c = cipher(kek)?;
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = c
        .encrypt(nonce, Payload { msg: dek.as_bytes(), aad })
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;
    debug_assert_eq!(ct.len(), KEY_LEN + TAG_LEN);

    let mut out = [0u8; WRAPPED_DEK_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce_bytes);
    out[NONCE_LEN..].copy_from_slice(&ct);
    Ok(out)
}

pub fn unwrap_dek(kek: &Key, wrapped: &[u8; WRAPPED_DEK_LEN], aad: &[u8]) -> Result<Key> {
    let c = cipher(kek)?;
    let nonce = Nonce::from_slice(&wrapped[..NONCE_LEN]);
    let pt = c
        .decrypt(nonce, Payload { msg: &wrapped[NONCE_LEN..], aad })
        .map_err(|_| VaultError::InvalidPassword)?;
    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&pt);
    let mut pt_z = pt;
    pt_z.zeroize();
    Ok(Key(dek))
}

/// Encrypt the fixed KEK_CHECK_PLAINTEXT so we can quickly tell a wrong
/// password from a corrupt vault.
pub fn make_kek_check(kek: &Key, aad: &[u8]) -> Result<[u8; KEK_CHECK_LEN]> {
    let c = cipher(kek)?;
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = c
        .encrypt(nonce, Payload { msg: KEK_CHECK_PLAINTEXT, aad })
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;
    let mut out = [0u8; KEK_CHECK_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce_bytes);
    out[NONCE_LEN..].copy_from_slice(&ct);
    Ok(out)
}

pub fn verify_kek_check(kek: &Key, block: &[u8; KEK_CHECK_LEN], aad: &[u8]) -> Result<()> {
    let c = cipher(kek)?;
    let nonce = Nonce::from_slice(&block[..NONCE_LEN]);
    let pt = c
        .decrypt(nonce, Payload { msg: &block[NONCE_LEN..], aad })
        .map_err(|_| VaultError::InvalidPassword)?;
    if pt != KEK_CHECK_PLAINTEXT {
        return Err(VaultError::InvalidPassword);
    }
    Ok(())
}

/// Encrypt one stream chunk. AAD binds the chunk to its vault and position.
pub fn encrypt_chunk(
    dek: &Key,
    vault_uuid: &[u8; 16],
    chunk_idx: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let c = cipher(dek)?;
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = chunk_aad(vault_uuid, chunk_idx);
    let ct = c
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_chunk(
    dek: &Key,
    vault_uuid: &[u8; 16],
    chunk_idx: u64,
    on_disk: &[u8],
) -> Result<Vec<u8>> {
    if on_disk.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Corrupt("chunk shorter than overhead".into()));
    }
    let c = cipher(dek)?;
    let nonce = Nonce::from_slice(&on_disk[..NONCE_LEN]);
    let aad = chunk_aad(vault_uuid, chunk_idx);
    c.decrypt(nonce, Payload { msg: &on_disk[NONCE_LEN..], aad: &aad })
        .map_err(|e| VaultError::DecryptionError(format!("chunk {chunk_idx}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::AAD_END;
    use zeroize::Zeroizing;

    fn fake_aad() -> [u8; AAD_END] {
        let mut a = [0u8; AAD_END];
        for (i, b) in a.iter_mut().enumerate() {
            *b = i as u8;
        }
        a
    }

    #[test]
    fn argon2_kek_is_deterministic() {
        let pw = Zeroizing::new(String::from("hunter2"));
        let salt = [9u8; SALT_LEN];
        let p = KdfParams { m_cost_kib: 19 * 1024, t_cost: 2, p_cost: 1 };
        let k1 = derive_kek_argon2(&pw, &salt, &p).unwrap();
        let k2 = derive_kek_argon2(&pw, &salt, &p).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = Key([1u8; KEY_LEN]);
        let dek = Key([2u8; KEY_LEN]);
        let aad = fake_aad();
        let wrapped = wrap_dek(&kek, &dek, &aad).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped, &aad).unwrap();
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let kek = Key([1u8; KEY_LEN]);
        let bad = Key([7u8; KEY_LEN]);
        let dek = Key([2u8; KEY_LEN]);
        let aad = fake_aad();
        let wrapped = wrap_dek(&kek, &dek, &aad).unwrap();
        let err = unwrap_dek(&bad, &wrapped, &aad).unwrap_err();
        assert!(matches!(err, VaultError::InvalidPassword));
    }

    #[test]
    fn changed_aad_fails_unwrap() {
        let kek = Key([1u8; KEY_LEN]);
        let dek = Key([2u8; KEY_LEN]);
        let aad = fake_aad();
        let wrapped = wrap_dek(&kek, &dek, &aad).unwrap();
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        let err = unwrap_dek(&kek, &wrapped, &bad_aad).unwrap_err();
        assert!(matches!(err, VaultError::InvalidPassword));
    }

    #[test]
    fn kek_check_distinguishes_password() {
        let kek = Key([1u8; KEY_LEN]);
        let bad = Key([2u8; KEY_LEN]);
        let aad = fake_aad();
        let block = make_kek_check(&kek, &aad).unwrap();
        verify_kek_check(&kek, &block, &aad).unwrap();
        assert!(matches!(
            verify_kek_check(&bad, &block, &aad).unwrap_err(),
            VaultError::InvalidPassword
        ));
    }

    #[test]
    fn chunk_aad_binds_position() {
        let dek = Key([3u8; KEY_LEN]);
        let vault_uuid = [42u8; 16];
        let ct = encrypt_chunk(&dek, &vault_uuid, 5, b"hello").unwrap();
        // Same bytes, wrong index -> decryption fails.
        let err = decrypt_chunk(&dek, &vault_uuid, 6, &ct).unwrap_err();
        assert!(matches!(err, VaultError::DecryptionError(_)));
        // Correct index -> ok.
        let pt = decrypt_chunk(&dek, &vault_uuid, 5, &ct).unwrap();
        assert_eq!(pt, b"hello");
    }
}
