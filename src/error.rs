use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Profile is already locked")]
    AlreadyLocked,

    #[error("Profile is not locked")]
    NotLocked,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid recovery phrase")]
    InvalidRecovery,

    #[error("Browser not supported: {0}")]
    UnsupportedBrowser(String),

    #[error("Profile is in use. Close the browser first.")]
    ProfileInUse,

    #[error("Vault file is corrupt: {0}")]
    Corrupt(String),

    #[error("Unsupported vault format version: {0}")]
    UnsupportedFormat(u16),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Walk error: {0}")]
    Walk(#[from] walkdir::Error),

    #[error("Config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
