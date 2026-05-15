# profile-vault

Password-protect browser profiles with strong authenticated encryption.

`profile-vault` takes a Chrome / Edge / Firefox / Brave / Chromium profile
directory, encrypts it into a single vault file, and removes the plaintext
from disk. When you want it back, you unlock it with your password (or a
24-word recovery phrase) and the profile is restored to its original location.

## Features

- AES-256-GCM authenticated encryption with per-chunk nonces and AAD binding
- Argon2id key derivation (memory-hard, GPU-resistant)
- Streaming tar + zstd pipeline — large profiles do not have to fit in RAM
- 24-word BIP39 recovery phrase (optional, on by default) for password loss
- Encrypted metadata index — vault contents are not enumerable from disk
- Commit-then-cleanup ordering — a crash mid-lock cannot lose the profile
- Passwords and keys zeroed from memory on drop
- Cross-platform: Windows, macOS, Linux

## Installation

```bash
cargo install --path .
```

Or download a pre-built binary from
[Releases](https://github.com/momoyash/profile-vault/releases).

## Usage

### List profiles

```bash
profile-vault list
profile-vault list --browser chrome
```

### Lock a profile

```bash
profile-vault lock chrome "Profile 1"
```

You will be prompted for a password (minimum 8 characters). On success a
24-word recovery phrase is printed once — **write it down**. The recovery
phrase can unlock the vault if the password is ever forgotten; it is the
only second factor and is not stored anywhere.

To skip recovery phrase generation (not recommended):

```bash
profile-vault lock chrome "Profile 1" --no-recovery
```

### Unlock a profile

```bash
profile-vault unlock chrome "Profile 1"
profile-vault unlock chrome "Profile 1" --launch
profile-vault unlock chrome "Profile 1" --auto-lock
```

`--launch` opens the browser against the restored profile.
`--auto-lock` launches the browser and re-locks the profile as soon as the
browser process exits.

To unlock using the recovery phrase instead of a password:

```bash
profile-vault unlock chrome "Profile 1" --recovery
```

### Status

```bash
profile-vault status     # show all locked profiles
profile-vault browsers   # show supported and detected browsers
```

## Security model

| Property            | Value                                                 |
| ------------------- | ----------------------------------------------------- |
| Cipher              | AES-256-GCM (AEAD)                                    |
| KDF                 | Argon2id, m = 256 MiB, t = 4, p = cores (max 8)       |
| Salt                | 32 bytes, random per vault                            |
| Nonce               | 12 bytes, random per chunk                            |
| Chunk size          | 1 MiB                                                 |
| Chunk AAD           | `vault_uuid || chunk_index || format_version`         |
| Header integrity    | BLAKE3 hash over header fields                        |
| Key hierarchy       | password → KEK (Argon2id) → wraps random DEK          |
|                     | recovery entropy → KEK (HKDF-SHA256) → wraps same DEK |
| Memory hygiene      | passwords / keys zeroed on drop                       |

Per-chunk AAD prevents reorder, splice, and cross-vault swap attacks: a
chunk encrypted at position *N* of vault *A* will not authenticate at any
other position or in any other vault.

A small `kek_check` block lets the CLI distinguish a wrong password from a
corrupt vault before paying the full Argon2 cost on the body.

### Vault file locations

- Windows: `%APPDATA%\profile-vault\vaults\`
- macOS: `~/Library/Application Support/profile-vault/vaults/`
- Linux: `~/.local/share/profile-vault/vaults/`

The encrypted metadata index lives in the same data directory under a
per-install key file with restrictive permissions (`0600` on Unix).

## How it works

**Lock**

1. Generate a per-vault UUID, salt, and random DEK
2. Derive the password-KEK via Argon2id
3. Stream the profile through `tar` → `zstd` → chunked AEAD into a `.tmp`
   vault file
4. Write the final header (with `wrapped_dek`, `kek_check`, optional
   `wrapped_recovery_dek`), write footer magic, fsync
5. Atomically rename `.tmp` → `.pvlt`
6. Record a `pending_delete` journal entry
7. Update the encrypted metadata index
8. Delete the original profile directory and clear the journal entry

A crash at any point leaves either the original profile intact, or a
durable vault plus a journal entry that finishes the cleanup on next run.

**Unlock**

1. Read and verify the vault header (BLAKE3 hash)
2. Derive the KEK from password (or recovery phrase)
3. Verify the `kek_check` block — fast failure on wrong password
4. Unwrap the DEK
5. Stream chunks through AEAD → `zstd` → `tar` → original location
6. Update the index and remove the vault file

## License

MIT
