#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
#[path = "../windows_launcher.rs"]
mod launcher;

#[cfg(windows)]
fn main() {
    if let Err(message) = launcher::run() {
        launcher::alert(&message);
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "The desktop launcher currently requires Windows. Use profile-vault for archive commands."
    );
    std::process::exit(1);
}
