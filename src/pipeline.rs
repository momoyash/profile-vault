//! Streaming encrypt / decrypt pipeline.
//!
//! Lock:    profile dir → tar → zstd → ChunkedEncryptWriter → .pvlt
//! Unlock:  .pvlt → ChunkedDecryptReader → zstd → tar → profile dir
//!
//! Chunks are 1 MiB (see [`format::CHUNK_SIZE`]). Each on-disk chunk is
//! `nonce(12) || ciphertext || tag(16)` and is AEAD-bound to its chunk index
//! and the vault UUID, so reordering, swapping between vaults, or truncating
//! the file all surface as decryption errors.

use std::io::{self, Read, Write};

use crate::crypto::{decrypt_chunk, encrypt_chunk, Key};
use crate::format::{CHUNK_SIZE, NONCE_LEN, TAG_LEN};

/// Buffers writes until a full chunk is available, then encrypts and emits it
/// downstream. Owns the chunk counter so callers never have to track indices.
pub struct ChunkedEncryptWriter<W: Write> {
    inner: W,
    dek: Key,
    vault_uuid: [u8; 16],
    buffer: Vec<u8>,
    chunk_size: usize,
    chunk_idx: u64,
    finished: bool,
}

impl<W: Write> ChunkedEncryptWriter<W> {
    pub fn new(inner: W, dek: Key, vault_uuid: [u8; 16]) -> Self {
        Self {
            inner,
            dek,
            vault_uuid,
            buffer: Vec::with_capacity(CHUNK_SIZE as usize),
            chunk_size: CHUNK_SIZE as usize,
            chunk_idx: 0,
            finished: false,
        }
    }

    fn emit_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        let out = encrypt_chunk(&self.dek, &self.vault_uuid, self.chunk_idx, data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.inner.write_all(&out)?;
        self.chunk_idx += 1;
        Ok(())
    }

    /// Flushes the trailing partial chunk (if any) and returns the inner
    /// writer along with the total chunk count written.
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        if self.finished {
            return Err(io::Error::new(io::ErrorKind::Other, "already finished"));
        }
        if !self.buffer.is_empty() {
            let buf = std::mem::take(&mut self.buffer);
            self.emit_chunk(&buf)?;
        }
        self.finished = true;
        Ok((self.inner, self.chunk_idx))
    }
}

impl<W: Write> Write for ChunkedEncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        while self.buffer.len() >= self.chunk_size {
            let rest = self.buffer.split_off(self.chunk_size);
            let chunk = std::mem::replace(&mut self.buffer, rest);
            self.emit_chunk(&chunk)?;
        }
        Ok(buf.len())
    }

    /// `flush` does NOT release a partial chunk. The zstd encoder above us
    /// flushes during normal operation and we mustn't emit short chunks until
    /// the stream is truly done. Use [`finish`] for that.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Pulls a fixed number of encrypted chunks from `inner`, decrypts them, and
/// exposes the plaintext stream as `Read`.
pub struct ChunkedDecryptReader<R: Read> {
    inner: R,
    dek: Key,
    vault_uuid: [u8; 16],
    chunk_size: usize,
    chunk_count: u64,
    chunk_idx: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    exhausted: bool,
}

impl<R: Read> ChunkedDecryptReader<R> {
    pub fn new(inner: R, dek: Key, vault_uuid: [u8; 16], chunk_count: u64) -> Self {
        Self {
            inner,
            dek,
            vault_uuid,
            chunk_size: CHUNK_SIZE as usize,
            chunk_count,
            chunk_idx: 0,
            buffer: Vec::new(),
            buffer_pos: 0,
            exhausted: false,
        }
    }

    fn pull_chunk(&mut self) -> io::Result<bool> {
        if self.chunk_idx >= self.chunk_count {
            self.exhausted = true;
            return Ok(false);
        }

        let mut nonce = [0u8; NONCE_LEN];
        self.inner.read_exact(&mut nonce)?;

        // We don't know ciphertext length up front because the last chunk can
        // be short. Read up to chunk_size + TAG_LEN; ciphertext length =
        // bytes_read - 0 (nonce already consumed). Use take + read_to_end.
        let mut body = Vec::with_capacity(self.chunk_size + TAG_LEN);
        let max = (self.chunk_size + TAG_LEN) as u64;
        (&mut self.inner).take(max).read_to_end(&mut body)?;
        if body.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short chunk body",
            ));
        }

        // Stitch nonce + body back into the on-disk layout expected by
        // `decrypt_chunk`.
        let mut on_disk = Vec::with_capacity(NONCE_LEN + body.len());
        on_disk.extend_from_slice(&nonce);
        on_disk.extend_from_slice(&body);

        let plain = decrypt_chunk(&self.dek, &self.vault_uuid, self.chunk_idx, &on_disk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        self.buffer = plain;
        self.buffer_pos = 0;
        self.chunk_idx += 1;
        Ok(true)
    }
}

impl<R: Read> Read for ChunkedDecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.exhausted && self.buffer_pos >= self.buffer.len() {
            return Ok(0);
        }
        if self.buffer_pos >= self.buffer.len() {
            if !self.pull_chunk()? {
                return Ok(0);
            }
        }
        let n = std::cmp::min(out.len(), self.buffer.len() - self.buffer_pos);
        out[..n].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + n]);
        self.buffer_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_streaming() {
        let dek = Key([7u8; 32]);
        let vault_uuid = [11u8; 16];

        // Generate a payload that crosses several chunk boundaries.
        let plaintext: Vec<u8> = (0..(3 * CHUNK_SIZE as usize + 1234))
            .map(|i| (i % 251) as u8)
            .collect();

        let mut out = Vec::new();
        let dek_clone = Key(*dek.as_bytes());
        let mut writer = ChunkedEncryptWriter::new(&mut out, dek_clone, vault_uuid);
        writer.write_all(&plaintext).unwrap();
        let (_, chunk_count) = writer.finish().unwrap();
        assert_eq!(chunk_count, 4);

        let dek_read = Key(*dek.as_bytes());
        let mut reader =
            ChunkedDecryptReader::new(Cursor::new(out), dek_read, vault_uuid, chunk_count);
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn tampered_chunk_fails() {
        let dek = Key([7u8; 32]);
        let vault_uuid = [11u8; 16];
        let mut out = Vec::new();
        let mut writer =
            ChunkedEncryptWriter::new(&mut out, Key(*dek.as_bytes()), vault_uuid);
        writer.write_all(b"hello world").unwrap();
        let (_, n) = writer.finish().unwrap();
        assert_eq!(n, 1);

        // Flip one byte in the chunk body.
        out[NONCE_LEN + 2] ^= 0xff;

        let mut reader =
            ChunkedDecryptReader::new(Cursor::new(out), Key(*dek.as_bytes()), vault_uuid, n);
        let mut decoded = Vec::new();
        let err = reader.read_to_end(&mut decoded).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
