# profile-vault

Password-protect browser profiles with real AES-256 encryption.

## Features

- Lock/unlock individual browser profiles with a password
- AES-256-GCM encryption with Argon2 key derivation
- Support for Chrome, Edge, Firefox, Brave, and Chromium
- Encrypted profiles can't be bypassed without the password
- Cross-platform (Windows, macOS, Linux)

## Installation

### From source

```bash
cargo install --path .
```

### Pre-built binaries

Download from [Releases](https://github.com/momoyash/profile-vault/releases).

## Usage

### List profiles

```bash
# List all browser profiles
profile-vault list

# Filter by browser
profile-vault list --browser chrome
```

### Lock a profile

```bash
profile-vault lock chrome "Profile 1"
```

You'll be prompted for a password. The profile will be:
1. Compressed into a zip archive
2. Encrypted with AES-256-GCM
3. Original profile folder removed

### Unlock a profile

```bash
profile-vault unlock chrome "Profile 1"

# Unlock and launch browser
profile-vault unlock chrome "Profile 1" --launch
```

### Check status

```bash
profile-vault status
```

### List supported browsers

```bash
profile-vault browsers
```

## Security

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key derivation**: Argon2id (memory-hard, resistant to GPU attacks)
- **Salt**: Random 22-byte salt per profile
- **Nonce**: Random 12-byte nonce per encryption

The encrypted vault files are stored in:
- Windows: `%APPDATA%\profile-vault\vaults\`
- macOS: `~/Library/Application Support/profile-vault/vaults/`
- Linux: `~/.local/share/profile-vault/vaults/`

## How it works

1. **Lock**: Profile folder is zipped, encrypted with your password, and the original is deleted
2. **Unlock**: Vault file is decrypted, unzipped to original location, vault file deleted

Without the correct password, the profile data is cryptographically inaccessible.

## License

MIT
