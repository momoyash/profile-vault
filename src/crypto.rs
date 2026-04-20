use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::{rngs::OsRng, RngCore};

use crate::error::{Result, VaultError};

const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 22;

pub struct Crypto;

impl Crypto {
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let hash_bytes = hash
            .hash
            .ok_or_else(|| VaultError::EncryptionError("Failed to get hash bytes".to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        Ok(key)
    }

    pub fn generate_salt() -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
        let salt = Self::generate_salt();
        let nonce_bytes = Self::generate_nonce();
        let key = Self::derive_key(password, &salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        // Format: salt || nonce || ciphertext
        let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
        if encrypted.len() < SALT_SIZE + NONCE_SIZE {
            return Err(VaultError::DecryptionError("Data too short".to_string()));
        }

        let salt = &encrypted[..SALT_SIZE];
        let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
        let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

        let key = Self::derive_key(password, salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::InvalidPassword)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, World!";
        let password = "test_password";

        let encrypted = Crypto::encrypt(data, password).unwrap();
        let decrypted = Crypto::decrypt(&encrypted, password).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Hello, World!";
        let encrypted = Crypto::encrypt(data, "correct").unwrap();
        let result = Crypto::decrypt(&encrypted, "wrong");

        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }
}
