use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
    Storage::FileSystem::QueryDosDeviceW,
    System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_ANY, RRF_SUBKEY_WOW6432KEY,
        RRF_SUBKEY_WOW6464KEY,
    },
    UI::WindowsAndMessaging::{MessageBoxW, IDRETRY, MB_ICONERROR, MB_ICONWARNING, MB_RETRYCANCEL},
};

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn dialog(message: &str, flags: u32) -> i32 {
    let title = wide(OsStr::new("Profile Vault"));
    let message = wide(OsStr::new(message));
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            flags,
        )
    }
}

pub fn alert(message: &str) {
    dialog(message, MB_ICONERROR);
}

fn installed(relative: &str, roots: &[&str]) -> Result<PathBuf, String> {
    roots
        .iter()
        .filter_map(std::env::var_os)
        .map(|root| PathBuf::from(root).join(relative))
        .find(|p| p.is_file())
        .ok_or_else(|| {
            format!(
                "Install {} to use this shortcut.",
                relative.split('\\').next().unwrap_or(relative)
            )
        })
}

struct DesktopBrowser {
    name: &'static str,
    executable: &'static str,
    policy: &'static str,
}

const CHROME: DesktopBrowser = DesktopBrowser {
    name: "Chrome",
    executable: r"Google\Chrome\Application\chrome.exe",
    policy: r"Software\Policies\Google\Chrome",
};
const BRAVE: DesktopBrowser = DesktopBrowser {
    name: "Brave",
    executable: r"BraveSoftware\Brave-Browser\Application\brave.exe",
    policy: r"Software\Policies\BraveSoftware\Brave",
};

impl DesktopBrowser {
    fn locate(&self) -> Result<PathBuf, String> {
        installed(
            self.executable,
            &[
                "ProgramW6432",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "LOCALAPPDATA",
            ],
        )
        .map_err(|_| {
            format!(
                "Could not find {} in its standard Windows installation locations.",
                self.name
            )
        })
    }
}

pub fn run() -> Result<(), String> {
    let vc = installed(
        r"VeraCrypt\VeraCrypt.exe",
        &["ProgramW6432", "ProgramFiles"],
    )?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => {
            let chrome = CHROME.locate().ok();
            let brave = BRAVE.locate().ok();
            if chrome.is_none() && brave.is_none() {
                return Err(
                    "Install Brave or Chrome to create a protected profile shortcut.".into(),
                );
            }
            let ps = installed(
                r"System32\WindowsPowerShell\v1.0\powershell.exe",
                &["SystemRoot"],
            )?;
            let status = Command::new(ps)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-STA",
                    "-Command",
                    "& ([scriptblock]::Create($env:PV_SETUP))",
                ])
                .env("PV_SETUP", include_str!("windows_setup.ps1"))
                .env(
                    "PV_LAUNCHER",
                    std::env::current_exe().map_err(|e| e.to_string())?,
                )
                .env("PV_CHROME", chrome.unwrap_or_default())
                .env("PV_BRAVE", brave.unwrap_or_default())
                .env("PV_VC", vc)
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err("Desktop shortcut setup failed.".into());
            }
            Ok(())
        }
        // Shortcuts made by the original Chrome-only setup have two arguments.
        [volume, letter] => session(&vc, &CHROME, Path::new(volume), letter),
        [volume, letter, name] => {
            let browser = [&BRAVE, &CHROME]
                .into_iter()
                .find(|b| name == OsStr::new(b.name))
                .ok_or("Unknown browser in shortcut. Run shortcut setup again.")?;
            session(&vc, browser, Path::new(volume), letter)
        }
        _ => Err("Double-click profile-vault-desktop to set up your protected profile.".into()),
    }
}

// Query the DOS device namespace, including drives without readable media.
fn drive_target(letter: char) -> Result<Option<String>, String> {
    let name = wide(OsStr::new(&format!("{letter}:")));
    let mut buf = vec![0u16; 32768];
    let len = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(err.to_string())
        };
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(len as usize);
    Ok(Some(String::from_utf16_lossy(&buf[..end])))
}

// Managed storage settings can override the launch directory.
fn check_storage_policy(browser: &DesktopBrowser) -> Result<(), String> {
    let path = wide(OsStr::new(browser.policy));
    let name = browser.name;
    for setting in ["UserDataDir", "DiskCacheDir"] {
        let value = wide(OsStr::new(setting));
        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            for view in [RRF_SUBKEY_WOW6464KEY, RRF_SUBKEY_WOW6432KEY] {
                let result = unsafe {
                    RegGetValueW(
                        hive,
                        path.as_ptr(),
                        value.as_ptr(),
                        RRF_RT_ANY | view,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                match result {
                    ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => (),
                    ERROR_SUCCESS => return Err(format!("{name}'s {setting} policy controls where data is saved. This protected shortcut requires the browser to use its own encrypted drive.")),
                    code => return Err(format!("Could not check {name}'s {setting} policy (Windows error {code}).")),
                }
            }
        }
    }
    Ok(())
}

fn session(
    vc: &Path,
    browser: &DesktopBrowser,
    volume: &Path,
    letter: &OsStr,
) -> Result<(), String> {
    let letter = match letter.to_str().map(str::as_bytes) {
        Some([c @ b'D'..=b'Z']) => *c as char,
        _ => return Err("Invalid shortcut drive letter. Run shortcut setup again.".into()),
    };
    if !volume.is_absolute() || !volume.is_file() {
        return Err(
            "The encrypted container file is missing. If you moved it, run shortcut setup again."
                .into(),
        );
    }
    let exe = browser.locate()?;
    let name = browser.name;
    check_storage_policy(browser)?;
    let state = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("Missing LocalAppData")?)
        .join("profile-vault");
    fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let guard = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join(format!("session-{letter}.lock")))
        .map_err(|e| e.to_string())?;
    guard
        .try_lock()
        .map_err(|_| "A protected session is already opening or running on this drive.")?;
    if drive_target(letter)?.is_some() {
        return Err(format!("Drive {letter}: is in use. If a previous session was interrupted, close its browser and dismount the volume in VeraCrypt."));
    }

    // VeraCrypt tries its shared driver cache even with /cache n. Clear it
    // before mounting so an earlier session cannot satisfy this prompt.
    let command = |args: &[&str]| {
        Command::new(vc)
            .args(args)
            .status()
            .map(|s| s.success())
            .map_err(|e| e.to_string())
    };
    if !command(&["/q", "/s", "/w"])? {
        return Err("VeraCrypt could not clear its password cache.".into());
    }
    let drive = letter.to_string();
    let mounted = Command::new(vc)
        .args(["/q", "/v"])
        .arg(volume)
        .args([
            "/l",
            &drive,
            "/cache",
            "n",
            "/history",
            "n",
            "/tryemptypass",
            "n",
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if !mounted.success() {
        // VeraCrypt presents authentication and cancellation in its own dialog.
        return Ok(());
    }
    let expected = format!(r"\Device\VeraCryptVolume{letter}");
    if drive_target(letter)?.as_deref() != Some(&expected) {
        return Err(
            "Could not confirm the mounted VeraCrypt drive. Check the volume in VeraCrypt.".into(),
        );
    }

    let run = (|| {
        if !command(&["/q", "/s", "/w"])? {
            return Err("Could not clear the VeraCrypt password cache.".to_string());
        }
        let root = PathBuf::from(format!(r"{letter}:\{name} User Data"));
        fs::create_dir_all(&root).map_err(|e| {
            format!("Could not create the {name} profile on the encrypted drive: {e}")
        })?;
        let drive_root = fs::canonicalize(format!(r"{letter}:\")).map_err(|e| e.to_string())?;
        let resolved = root.canonicalize().map_err(|e| e.to_string())?;
        if !resolved.starts_with(drive_root) {
            return Err("The profile directory points outside the encrypted volume.".into());
        }
        let mut dir = OsString::from("--user-data-dir=");
        dir.push(root);
        let status = Command::new(exe)
            .arg(dir)
            .args([
                "--disable-background-mode",
                "--no-first-run",
                "--no-default-browser-check",
            ])
            .status()
            .map_err(|e| format!("Could not run {name}: {e}"))?;
        if !status.success() {
            return Err(format!("{name} exited with {status}."));
        }
        Ok(())
    })();

    // Never force a dismount while the browser or another application holds files.
    let mut attempts = 0;
    loop {
        match drive_target(letter)? {
            None => break,
            Some(target) if target == expected => {}
            _ => {
                return Err(
                    "Drive assignment changed. Check the protected volume in VeraCrypt.".into(),
                )
            }
        }
        if command(&["/q", "/s", "/d", &drive])? && drive_target(letter)?.is_none() {
            break;
        }
        attempts += 1;
        if attempts == 4 {
            if dialog(&format!("The profile is still unlocked. Close any windows using {letter}: and click Retry to lock it. If you cancel, dismount it yourself in VeraCrypt."), MB_RETRYCANCEL | MB_ICONWARNING) != IDRETRY {
                return Err("Automatic locking did not finish. The volume is still mounted.".into());
            }
            attempts = 0;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    run
}
