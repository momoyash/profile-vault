# Implementation notes

## Desktop lifecycle

`src/bin/profile-vault-desktop.rs` provides the Windows GUI entry point. `src/windows_launcher.rs` handles browser discovery, registry policy checks, drive ownership, authentication, process waiting, and dismount. `src/windows_setup.ps1` is embedded into the executable and builds shortcuts with Windows Forms.

Setup discovers Brave and Chrome in Program Files and LocalAppData. Each shortcut records an absolute container path, a drive letter, and a browser name. Two-argument shortcuts from the initial Chrome setup remain supported.

On opening a shortcut, the launcher validates its arguments and checks for browser policies that redirect storage. It obtains an operating-system file lock for the drive letter and refuses an occupied drive. It clears the shared VeraCrypt password cache, invokes VeraCrypt's password dialog, and checks that Windows maps the selected drive to a VeraCrypt device.

The browser receives a separate `--user-data-dir` on the mounted drive and `--disable-background-mode`. The launcher blocks on the browser process. A normal exit triggers a regular dismount. Failed dismounts retry briefly, then ask the user to close applications holding files open. Force dismount is avoided to protect browser writes.

Drive mapping checks reduce accidental use of an unrelated drive. They provide no isolation against malicious software running in the same Windows account. The launcher cannot guarantee cleanup after process termination.

## Archive lifecycle

`Vault` holds an exclusive file lock while accessing the archive index. Archives use random UUID filenames to avoid collisions between profile names. Temporary files receive unique names and are removed on ordinary failures.

Lock derives a password key with Argon2id and generates a random AES-256-GCM data key. A single immutable header supplies authenticated data for every wrapped key slot. The profile streams through tar, zstd, and 1 MiB encrypted chunks. A complete archive is committed before recording deletion intent, saving the index, and removing plaintext.

Unlock checks the footer, header hash, KDF bounds, and chunk layout. It authenticates the key slot and extracts into a temporary sibling directory. It drains the compressed stream to authenticate the remaining data before publishing the restored directory. A browser-created replacement directory is moved to a unique backup directory. The index entry and encrypted archive are removed after restoration.

Pending cleanup retries require a matching index entry, a structurally valid archive, and a stopped browser. Failed deletions remain journaled. A structurally valid archive is not a substitute for a verified backup.

## Archive format

The existing version 2 format remains readable. A 512-byte header precedes encrypted chunks and an eight-byte footer. Each chunk carries a 12-byte nonce, ciphertext, and a 16-byte GCM tag. Associated data binds its UUID, chunk index, and format version.

The header includes Argon2id parameters, salt, chunk count, wrapped data key, password check, and optional recovery slot. BLAKE3 detects accidental header corruption. The unkeyed header hash alone does not authenticate attacker-controlled metadata. AES-GCM authenticates the wrapped keys and chunk bodies.

The recovery phrase derives a separate wrapping key through HKDF-SHA256. It is an alternative credential. Password authentication still performs Argon2id before checking the key.

The encrypted index uses a local key file in the application data directory. Anyone who can read both can recover profile metadata. Profile content uses its separate password-derived key.

## Development

CI checks formatting, Clippy, release compilation, and tests on Windows, Linux, and macOS. Tagging a version with `v` runs the release workflow. Windows ZIPs include both executables. Unix archives contain the CLI.

Useful regression checks cover chunk boundary round trips, tampering, password and recovery restoration, and corrupted archive rejection. GUI and mount validation require Windows with VeraCrypt installed.
