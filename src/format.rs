//! Vault file format v2.
//!
//! Layout (single .pvlt file):
//!
//!   [0..512)    Header block (fixed size, see Header)
//!   [512..N)    Encrypted chunks (per-chunk AES-256-GCM)
//!   [N..N+8)    Footer magic b"PVLT_END"
//!
//! Each chunk on disk: nonce(12) || ciphertext || tag(16)
//! Chunks encrypt plaintext drawn from a tar+zstd stream of the profile.
//!
//! AEAD AAD per chunk = vault_uuid(16) || chunk_idx_le(8) || version_le(2) = 26 bytes.
//!
//! The header's `header_hash` covers bytes [0..HASH_OFFSET) — every parameter
//! that affects key derivation, AEAD configuration, and chunk layout. Any bit
//! flip in those bytes is detected before we attempt the (slow) KDF.
//!
//! The wrapped DEK and KEK-check blocks use AAD = header[0..AAD_END) which
//! excludes only the chunk_count (so chunk_count can be patched in after the
//! stream finishes without invalidating AEAD).

use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::{Result, VaultError};

pub const MAGIC: &[u8; 4] = b"PVLT";
pub const FOOTER_MAGIC: &[u8; 8] = b"PVLT_END";
pub const VERSION: u16 = 2;

pub const HEADER_SIZE: usize = 512;
pub const CHUNK_SIZE: u32 = 1 << 20; // 1 MiB
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Plaintext used by the KEK self-check.
pub const KEK_CHECK_PLAINTEXT: &[u8] = b"PVLT-CHECKv2_";

/// AEAD wrapped DEK: nonce + 32B ciphertext + tag.
pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN; // 60
/// KEK check: nonce + plaintext + tag.
pub const KEK_CHECK_LEN: usize = NONCE_LEN + KEK_CHECK_PLAINTEXT.len() + TAG_LEN; // 41

// Byte offsets inside the header.
// Keep these stable — they're part of the format.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_FLAGS: usize = 6;
const OFF_UUID: usize = 8;
const OFF_CREATED: usize = 24;
const OFF_KDF_ID: usize = 32;
const OFF_KDF_M: usize = 33;
const OFF_KDF_T: usize = 37;
const OFF_KDF_P: usize = 41;
const OFF_RESERVED1: usize = 42;
const OFF_SALT: usize = 43;
const OFF_AEAD_ID: usize = 75;
const OFF_CHUNK_SIZE: usize = 76;
/// AAD for wrapped DEK / KEK-check spans [0..AAD_END). Excludes chunk_count
/// so we can patch chunk_count after streaming without re-wrapping the DEK.
pub const AAD_END: usize = 80;
const OFF_CHUNK_COUNT: usize = 80;
const OFF_HASH_INPUT_END: usize = 88;
const OFF_HEADER_HASH: usize = 88;
const OFF_WRAPPED_DEK: usize = 120;
const OFF_KEK_CHECK: usize = OFF_WRAPPED_DEK + WRAPPED_DEK_LEN; // 180
const OFF_HAS_RECOVERY: usize = OFF_KEK_CHECK + KEK_CHECK_LEN; // 221
const OFF_WRAPPED_RECOVERY: usize = OFF_HAS_RECOVERY + 1; // 222
const RECOVERY_END: usize = OFF_WRAPPED_RECOVERY + WRAPPED_DEK_LEN; // 282

pub const FLAG_HAS_RECOVERY: u16 = 0b0001;

pub const KDF_ID_ARGON2ID: u8 = 1;
pub const AEAD_ID_AES256_GCM: u8 = 1;

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u8,
}

impl KdfParams {
    /// Defaults tuned for ~1s on a modern CPU. Bumped well past `Argon2::default()`.
    pub fn strong_default() -> Self {
        Self {
            m_cost_kib: 256 * 1024, // 256 MiB
            t_cost: 4,
            p_cost: std::thread::available_parallelism()
                .map(|n| n.get().min(8) as u8)
                .unwrap_or(2),
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub version: u16,
    pub flags: u16,
    pub vault_uuid: [u8; 16],
    pub created_at: i64,
    pub kdf_id: u8,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub aead_id: u8,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub kek_check: [u8; KEK_CHECK_LEN],
    pub wrapped_recovery_dek: Option<[u8; WRAPPED_DEK_LEN]>,
}

impl Header {
    /// Serialize into a fixed [`HEADER_SIZE`] byte buffer.
    /// Computes `header_hash` over bytes that mutate key derivation.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(MAGIC);
        buf[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&self.version.to_le_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        buf[OFF_UUID..OFF_UUID + 16].copy_from_slice(&self.vault_uuid);
        buf[OFF_CREATED..OFF_CREATED + 8].copy_from_slice(&self.created_at.to_le_bytes());
        buf[OFF_KDF_ID] = self.kdf_id;
        buf[OFF_KDF_M..OFF_KDF_M + 4].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        buf[OFF_KDF_T..OFF_KDF_T + 4].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        buf[OFF_KDF_P] = self.kdf.p_cost;
        buf[OFF_RESERVED1] = 0;
        buf[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(&self.salt);
        buf[OFF_AEAD_ID] = self.aead_id;
        buf[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        buf[OFF_CHUNK_COUNT..OFF_CHUNK_COUNT + 8].copy_from_slice(&self.chunk_count.to_le_bytes());

        let hash = blake3::hash(&buf[..OFF_HASH_INPUT_END]);
        buf[OFF_HEADER_HASH..OFF_HEADER_HASH + 32].copy_from_slice(hash.as_bytes());

        buf[OFF_WRAPPED_DEK..OFF_WRAPPED_DEK + WRAPPED_DEK_LEN]
            .copy_from_slice(&self.wrapped_dek);
        buf[OFF_KEK_CHECK..OFF_KEK_CHECK + KEK_CHECK_LEN].copy_from_slice(&self.kek_check);

        if let Some(rec) = &self.wrapped_recovery_dek {
            buf[OFF_HAS_RECOVERY] = 1;
            buf[OFF_WRAPPED_RECOVERY..RECOVERY_END].copy_from_slice(rec);
        }

        buf
    }

    /// Bytes used as AEAD AAD for wrapped DEK and KEK-check.
    pub fn aad(&self) -> [u8; AAD_END] {
        let full = self.to_bytes();
        let mut aad = [0u8; AAD_END];
        aad.copy_from_slice(&full[..AAD_END]);
        aad
    }

    pub fn parse(buf: &[u8; HEADER_SIZE]) -> Result<Self> {
        if &buf[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(VaultError::Corrupt("bad magic".into()));
        }
        let version = u16::from_le_bytes(buf[OFF_VERSION..OFF_VERSION + 2].try_into().unwrap());
        if version != VERSION {
            return Err(VaultError::UnsupportedFormat(version));
        }

        let computed = blake3::hash(&buf[..OFF_HASH_INPUT_END]);
        if computed.as_bytes() != &buf[OFF_HEADER_HASH..OFF_HEADER_HASH + 32] {
            return Err(VaultError::Corrupt("header hash mismatch".into()));
        }

        let flags = u16::from_le_bytes(buf[OFF_FLAGS..OFF_FLAGS + 2].try_into().unwrap());
        let mut vault_uuid = [0u8; 16];
        vault_uuid.copy_from_slice(&buf[OFF_UUID..OFF_UUID + 16]);
        let created_at = i64::from_le_bytes(buf[OFF_CREATED..OFF_CREATED + 8].try_into().unwrap());
        let kdf_id = buf[OFF_KDF_ID];
        let kdf = KdfParams {
            m_cost_kib: u32::from_le_bytes(buf[OFF_KDF_M..OFF_KDF_M + 4].try_into().unwrap()),
            t_cost: u32::from_le_bytes(buf[OFF_KDF_T..OFF_KDF_T + 4].try_into().unwrap()),
            p_cost: buf[OFF_KDF_P],
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[OFF_SALT..OFF_SALT + SALT_LEN]);
        let aead_id = buf[OFF_AEAD_ID];
        let chunk_size =
            u32::from_le_bytes(buf[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].try_into().unwrap());
        let chunk_count =
            u64::from_le_bytes(buf[OFF_CHUNK_COUNT..OFF_CHUNK_COUNT + 8].try_into().unwrap());

        let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
        wrapped_dek.copy_from_slice(&buf[OFF_WRAPPED_DEK..OFF_WRAPPED_DEK + WRAPPED_DEK_LEN]);
        let mut kek_check = [0u8; KEK_CHECK_LEN];
        kek_check.copy_from_slice(&buf[OFF_KEK_CHECK..OFF_KEK_CHECK + KEK_CHECK_LEN]);

        let wrapped_recovery_dek = if buf[OFF_HAS_RECOVERY] == 1 {
            let mut rec = [0u8; WRAPPED_DEK_LEN];
            rec.copy_from_slice(&buf[OFF_WRAPPED_RECOVERY..RECOVERY_END]);
            Some(rec)
        } else {
            None
        };

        Ok(Header {
            version,
            flags,
            vault_uuid,
            created_at,
            kdf_id,
            kdf,
            salt,
            aead_id,
            chunk_size,
            chunk_count,
            wrapped_dek,
            kek_check,
            wrapped_recovery_dek,
        })
    }
}

/// Reads the header from the start of a file. Caller must seek to 0 first.
pub fn read_header<R: Read>(reader: &mut R) -> Result<Header> {
    let mut buf = [0u8; HEADER_SIZE];
    reader.read_exact(&mut buf)?;
    Header::parse(&buf)
}

/// Verifies the trailing footer magic. Returns the offset where the footer
/// begins (file_len - 8) so callers know where chunk data ends.
pub fn verify_footer<R: Read + Seek>(reader: &mut R) -> Result<u64> {
    let end = reader.seek(SeekFrom::End(0))?;
    if end < (HEADER_SIZE + FOOTER_MAGIC.len()) as u64 {
        return Err(VaultError::Corrupt("file too small".into()));
    }
    reader.seek(SeekFrom::End(-(FOOTER_MAGIC.len() as i64)))?;
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    if &buf != FOOTER_MAGIC {
        return Err(VaultError::Corrupt(
            "missing footer marker — file truncated or corrupt".into(),
        ));
    }
    Ok(end - FOOTER_MAGIC.len() as u64)
}

pub fn write_footer<W: Write>(writer: &mut W) -> Result<()> {
    writer.write_all(FOOTER_MAGIC)?;
    Ok(())
}

/// 26-byte AAD attached to every chunk: uuid || chunk_idx || version.
pub fn chunk_aad(vault_uuid: &[u8; 16], chunk_idx: u64) -> [u8; 26] {
    let mut aad = [0u8; 26];
    aad[..16].copy_from_slice(vault_uuid);
    aad[16..24].copy_from_slice(&chunk_idx.to_le_bytes());
    aad[24..26].copy_from_slice(&VERSION.to_le_bytes());
    aad
}
