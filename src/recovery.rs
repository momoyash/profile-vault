//! BIP39 recovery codes.
//!
//! On vault creation we (optionally) generate a 24-word mnemonic representing
//! 256 bits of entropy. The mnemonic's entropy bytes are run through HKDF to
//! produce a second KEK which wraps the same DEK as the password KEK does.
//!
//! Forgotten password → user types the 24 words → DEK is unwrapped via the
//! recovery KEK → user sets a new password (which re-wraps the DEK).

use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub struct Recovery {
    pub mnemonic: Zeroizing<String>,
    pub entropy: Zeroizing<Vec<u8>>,
}

/// Generate a fresh 24-word recovery phrase (256 bits of entropy).
pub fn generate() -> Result<Recovery> {
    let mut entropy = vec![0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let m = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| VaultError::EncryptionError(format!("mnemonic: {e}")))?;
    Ok(Recovery {
        mnemonic: Zeroizing::new(m.to_string()),
        entropy: Zeroizing::new(entropy),
    })
}

/// Parse a user-supplied recovery phrase and return its entropy bytes.
pub fn parse(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let m = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
        .map_err(|_| VaultError::InvalidRecovery)?;
    Ok(Zeroizing::new(m.to_entropy()))
}
