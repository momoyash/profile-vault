mod browser;
mod cli;
mod crypto;
mod error;
mod format;
mod index;
mod pipeline;
mod process;
mod recovery;
mod vault;

use clap::Parser;
use colored::Colorize;
use zeroize::Zeroizing;

use browser::{detect_browsers, Browser};
use cli::{Cli, Commands};
use error::Result;
use vault::Vault;

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { browser } => cmd_list(browser),
        Commands::Lock {
            browser,
            profile,
            password,
            no_recovery,
        } => cmd_lock(&browser, &profile, password, !no_recovery),
        Commands::Unlock {
            browser,
            profile,
            password,
            recovery,
            launch,
            auto_lock,
        } => cmd_unlock(&browser, &profile, password, recovery, launch, auto_lock),
        Commands::Status => cmd_status(),
        Commands::Browsers => cmd_browsers(),
    }
}

fn cmd_list(browser_filter: Option<String>) -> Result<()> {
    let vault = Vault::new()?;
    let browsers = detect_browsers();

    if browsers.is_empty() {
        println!("{}", "No supported browsers found.".yellow());
        return Ok(());
    }

    for browser in browsers {
        if let Some(ref filter) = browser_filter {
            if browser.name().to_lowercase() != filter.to_lowercase() {
                continue;
            }
        }

        println!("\n{} {}", "Browser:".bold(), browser.name().cyan());

        let profiles = browser.list_profiles()?;
        if profiles.is_empty() {
            println!("  {}", "No profiles found".dimmed());
            continue;
        }

        for profile in profiles {
            let locked = vault.is_locked(&browser, &profile.id);
            let status = if locked {
                "LOCKED".red().bold()
            } else {
                "unlocked".green()
            };

            println!(
                "  {} [{}]",
                profile.display(),
                status
            );
        }
    }

    Ok(())
}

fn cmd_lock(
    browser_name: &str,
    profile_id: &str,
    password_arg: Option<String>,
    with_recovery: bool,
) -> Result<()> {
    let browser = Browser::from_str(browser_name)?;
    let profiles = browser.list_profiles()?;

    let profile = profiles
        .into_iter()
        .find(|p| p.id.eq_ignore_ascii_case(profile_id))
        .ok_or_else(|| error::VaultError::ProfileNotFound(profile_id.to_string()))?;

    println!(
        "{} {} profile: {}",
        "Locking".yellow().bold(),
        browser.name(),
        profile.display()
    );

    let password = match password_arg {
        Some(p) => Zeroizing::new(p),
        None => {
            let p = Zeroizing::new(
                rpassword::prompt_password("Enter password: ")
                    .map_err(|e| error::VaultError::Config(e.to_string()))?,
            );
            let confirm = Zeroizing::new(
                rpassword::prompt_password("Confirm password: ")
                    .map_err(|e| error::VaultError::Config(e.to_string()))?,
            );
            if *p != *confirm {
                return Err(error::VaultError::Config(
                    "Passwords do not match".to_string(),
                ));
            }
            p
        }
    };

    if password.len() < 8 {
        return Err(error::VaultError::Config(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let mut vault = Vault::new()?;
    let result = vault.lock_profile(&profile, &password, with_recovery)?;

    println!(
        "\n{} Profile '{}' is now locked.",
        "✓".green().bold(),
        profile.display()
    );

    if let Some(rec) = result.recovery {
        println!();
        println!("{}", "RECOVERY PHRASE — write this down NOW".red().bold());
        println!("{}", "This is the ONLY way to unlock the vault without your password.".dimmed());
        println!("{}", "It will not be shown again.".dimmed());
        println!();
        for (i, word) in rec.mnemonic.split_whitespace().enumerate() {
            print!("{:>2}. {:<12}", i + 1, word);
            if (i + 1) % 4 == 0 {
                println!();
            }
        }
        println!();
    }

    println!(
        "{}",
        "The encrypted vault is stored safely. Use 'unlock' to restore it.".dimmed()
    );

    Ok(())
}

fn cmd_unlock(
    browser_name: &str,
    profile_id: &str,
    password_arg: Option<String>,
    use_recovery: bool,
    launch: bool,
    auto_lock: bool,
) -> Result<()> {
    let browser = Browser::from_str(browser_name)?;

    println!(
        "{} {} profile: {}",
        "Unlocking".yellow().bold(),
        browser.name(),
        profile_id
    );

    let mut vault = Vault::new()?;

    // Hold onto the password so we can reuse it for auto-lock without re-prompting.
    let password_for_relock: Option<Zeroizing<String>> = if use_recovery {
        let phrase = Zeroizing::new(
            rpassword::prompt_password("Enter 24-word recovery phrase: ")
                .map_err(|e| error::VaultError::Config(e.to_string()))?,
        );
        vault.unlock_with_recovery(&browser, profile_id, &phrase)?;
        None
    } else {
        let password = match password_arg {
            Some(p) => Zeroizing::new(p),
            None => Zeroizing::new(
                rpassword::prompt_password("Enter password: ")
                    .map_err(|e| error::VaultError::Config(e.to_string()))?,
            ),
        };
        vault.unlock_with_password(&browser, profile_id, &password)?;
        Some(password)
    };

    println!(
        "\n{} Profile '{}' is now unlocked.",
        "✓".green().bold(),
        profile_id
    );

    if auto_lock {
        let password = match password_for_relock {
            Some(p) => p,
            None => {
                println!(
                    "{}",
                    "Cannot auto-lock when unlocking via recovery — set a new password first."
                        .yellow()
                );
                return Ok(());
            }
        };

        println!(
            "{}",
            "Launching browser (will auto-lock when closed)...".dimmed()
        );
        launch_browser(&browser, profile_id)?;

        std::thread::sleep(std::time::Duration::from_secs(3));

        println!("{}", "Waiting for browser to close...".dimmed());
        process::wait_for_close(&browser);

        println!("{}", "Browser closed. Re-locking profile...".dimmed());
        let profiles = browser.list_profiles()?;
        if let Some(profile) = profiles
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(profile_id))
        {
            let mut vault = Vault::new()?;
            vault.lock_profile(&profile, &password, /*with_recovery=*/ false)?;
            println!(
                "{} Profile '{}' is now locked again.",
                "✓".green().bold(),
                profile_id
            );
        }
    } else if launch {
        println!("{}", "Launching browser...".dimmed());
        launch_browser(&browser, profile_id)?;
    }

    Ok(())
}

fn cmd_status() -> Result<()> {
    let vault = Vault::new()?;
    let locked = vault.list_locked();

    if locked.is_empty() {
        println!("{}", "No locked profiles.".dimmed());
        return Ok(());
    }

    println!("{}", "Locked profiles:".bold());
    for profile in locked {
        let rec_tag = if profile.has_recovery {
            "recovery".green()
        } else {
            "no recovery".red()
        };
        println!(
            "  {} / {} [{}] (locked at {})",
            profile.browser.cyan(),
            profile.profile_name,
            rec_tag,
            profile.locked_at.dimmed()
        );
    }

    Ok(())
}

fn cmd_browsers() -> Result<()> {
    println!("{}", "Supported browsers:".bold());
    println!("  - chrome");
    println!("  - edge");
    println!("  - firefox");
    println!("  - brave");
    println!("  - chromium");

    println!("\n{}", "Detected on this system:".bold());
    let detected = detect_browsers();
    if detected.is_empty() {
        println!("  {}", "None".dimmed());
    } else {
        for b in detected {
            println!("  {} {}", "*".green(), b.name());
        }
    }

    Ok(())
}

fn launch_browser(browser: &Browser, profile_id: &str) -> Result<()> {
    use std::process::Command;

    let exe = match browser {
        Browser::Chrome => {
            let paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            ];
            paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
                .copied()
        }
        Browser::Edge => Some(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Browser::Brave => {
            let paths = [
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
            ];
            paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
                .copied()
        }
        Browser::Firefox => {
            let paths = [
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            ];
            paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
                .copied()
        }
        Browser::Chromium => None,
    };

    if let Some(exe_path) = exe {
        let mut cmd = Command::new(exe_path);

        if browser.is_chromium_based() {
            cmd.arg(format!("--profile-directory={}", profile_id));
        } else if *browser == Browser::Firefox {
            cmd.args(["-P", profile_id]);
        }

        cmd.spawn().map_err(error::VaultError::Io)?;
    } else {
        println!(
            "{}",
            "Could not find browser executable. Please launch manually.".yellow()
        );
    }

    Ok(())
}
