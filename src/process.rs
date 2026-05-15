//! Browser-process detection.
//!
//! Two-step check:
//!   1. Look for browser-managed singleton/lock files inside the profile dir.
//!      If those are live, the browser owns the profile RIGHT NOW.
//!   2. Fall back to platform process listing in case the browser was killed
//!      uncleanly and left stale singleton files behind.

use std::path::Path;
use std::process::Command;

use crate::browser::Browser;

/// True if the browser appears to be using the given profile directory.
pub fn is_profile_in_use(browser: &Browser, profile_path: &Path) -> bool {
    if profile_in_use_via_singleton(browser, profile_path) {
        return true;
    }
    browser_process_running(browser)
}

/// Chromium drops `SingletonLock` (Unix) / `lockfile` (Firefox) into the
/// profile dir when a browser is using it. On Windows Chromium uses a kernel
/// mutex which we can't probe directly, so this only contributes signal on
/// Unix and for Firefox.
fn profile_in_use_via_singleton(browser: &Browser, profile_path: &Path) -> bool {
    match browser {
        Browser::Chrome | Browser::Edge | Browser::Brave | Browser::Chromium => {
            // POSIX-only file; on Windows it's never present.
            profile_path.join("SingletonLock").exists()
        }
        Browser::Firefox => {
            // Firefox uses `lock` (Unix) or `parent.lock` (Windows).
            profile_path.join("lock").exists() || profile_path.join("parent.lock").exists()
        }
    }
}

#[cfg(windows)]
fn browser_process_running(browser: &Browser) -> bool {
    let exe = browser.executable_name();
    let output = Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", exe), "/NH"])
        .output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // tasklist prints "INFO: No tasks are running..." when nothing matches.
            stdout.contains(exe)
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn browser_process_running(browser: &Browser) -> bool {
    let exe = browser.executable_name();
    let bare = exe.trim_end_matches(".exe");
    let output = Command::new("pgrep").arg("-x").arg(bare).output();
    matches!(output, Ok(out) if out.status.success() && !out.stdout.is_empty())
}

/// Block until the browser process has exited. Polls every 2 seconds.
/// (Event-driven waiting via `WaitForSingleObject` / `pidfd_open` is on the
/// v0.5 roadmap.)
pub fn wait_for_close(browser: &Browser) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if !browser_process_running(browser) {
            return;
        }
    }
}
