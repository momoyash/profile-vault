# Profile Vault

Open a protected Brave or Chrome profile with a password. Close its last window to lock it again.

The Windows desktop launcher keeps the browser's complete user data directory inside a VeraCrypt file container. Your everyday browser can stay open in a separate session. Profile Vault starts when you click the protected shortcut, waits for that browser process to exit, then dismounts the container and exits.

## Windows setup

1. Install [VeraCrypt](https://veracrypt.io/en/Downloads.html) and Brave or Chrome in their standard Windows locations.
2. Download the Windows ZIP from [Releases](https://github.com/momoyash/profile-vault/releases) and extract both executables into a permanent folder.
3. Double-click **profile-vault-desktop.exe**. Select your browser.
4. Choose **Yes** to open the VeraCrypt creation wizard, or **No** to select an existing dedicated container.
5. In VeraCrypt choose **Create an encrypted file container**, then **Standard VeraCrypt volume**. Select a new filename such as `PrivateBrowser.hc`, allow room for the profile to grow, and choose a password. A few GB provides room for ordinary profile data and caches.
6. After finishing the wizard, select the container file in Profile Vault and save your desktop shortcut.
7. Open **Protected Brave** or **Protected Chrome** and enter your password in VeraCrypt.

VeraCrypt's **Format** button creates a filesystem inside the selected container file. An existing file selected as the container will be overwritten. Check the full filename in the wizard before proceeding. The file-container option leaves the containing drive's filesystem intact.

The first launch creates a fresh browser profile. For existing history and bookmarks, follow the [migration guide](docs/migration.md).

## Everyday use

- Open the protected desktop shortcut and enter your volume password.
- Close every window belonging to that protected session to lock it.
- Keep the launcher running until it finishes dismounting the volume.
- If the volume is busy, close applications using its mounted drive and click **Retry**.
- After an interrupted launcher session, close its browser and dismount that drive in VeraCrypt.

A background Profile Vault service is unnecessary. During a session the launcher waits on a process handle. The desktop workflow currently supports Windows with Brave and Chrome. VeraCrypt's installed driver has its own operating-system lifecycle.

Passwords are entered through VeraCrypt. The launcher clears VeraCrypt's shared password cache before mounting and after authentication. This also clears cached credentials for other VeraCrypt volumes.

## Build and check

Requires Rust 1.89 or later and the native C/C++ build tools used by zstd. On Windows install the MSVC toolchain and Visual Studio C++ build tools.

```sh
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The desktop executable is `target/release/profile-vault-desktop.exe`. Keep it in place after saving shortcuts, or recreate the shortcuts after moving it.

## Archive commands

The separate `profile-vault` executable retains the encrypted archive workflow for Brave, Chrome, Edge, Chromium, and Firefox. It runs on Windows, macOS, and Linux.

```sh
profile-vault list
profile-vault browsers
profile-vault lock brave "Profile 1"
profile-vault status
profile-vault unlock brave "Profile 1"
profile-vault unlock brave "Profile 1" --recovery
profile-vault unlock brave "Profile 1" --launch
```

Lock prompts for a password and confirmation, encrypts the directory into a `.pvlt` archive, then deletes the source directory. It displays an optional 24-word recovery phrase once. Store that phrase securely. Unlock restores plaintext into the original location. Close that browser before locking or restoring.

`--no-recovery` disables phrase generation. `--password` accepts a command-line password, which can be visible in process arguments and shell history. Interactive entry avoids those exposures.

`unlock --auto-lock` waits for all processes of that browser type to exit before creating a new archive. It requires password authentication. That new archive has no recovery phrase, so the previous phrase expires. The desktop workflow locks its dedicated container when its own browser session exits.

## Protection and limits

The container protects its contents while dismounted. Someone with filesystem access can delete or replace the container. While mounted, applications running as your Windows user can access the profile.

Downloads saved outside the mounted drive, cloud sync, backups, page files, and crash reports have separate storage. Copies left in the original browser directory remain readable. A strong password, a trustworthy Windows session, and current backups matter.

The launcher can leave a volume mounted if it is terminated, Windows interrupts it, or another application prevents dismount. An occupied drive letter causes an error. Use VeraCrypt to dismount an interrupted session before reopening the shortcut.

Read the [implementation notes](docs/architecture.md) for the launch lifecycle and archive format.

## License

MIT. See [LICENSE](LICENSE).
