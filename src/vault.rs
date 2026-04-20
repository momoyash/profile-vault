use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use chrono::Utc;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::browser::{Browser, ProfileInfo};
use crate::config::{Config, LockedProfile};
use crate::crypto::Crypto;
use crate::error::{Result, VaultError};

pub struct Vault {
    config: Config,
}

impl Vault {
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: Config::load()?,
        })
    }

    pub fn lock_profile(&mut self, profile: &ProfileInfo, password: &str) -> Result<()> {
        let browser_name = profile.browser.name();

        // Check if already locked
        if self.config.is_locked(browser_name, &profile.id) {
            return Err(VaultError::AlreadyLocked);
        }

        // Check if profile exists
        if !profile.path.exists() {
            return Err(VaultError::ProfileNotFound(profile.display()));
        }

        // Check if browser is running
        if is_browser_running(&profile.browser) {
            return Err(VaultError::ProfileInUse);
        }

        // Create vault directory
        let vault_dir = Config::vault_dir()?;
        let vault_file = vault_dir.join(format!(
            "{}_{}.vault",
            browser_name.to_lowercase(),
            profile.id.replace(" ", "_")
        ));

        // Zip the profile directory
        let zip_data = zip_directory(&profile.path)?;

        // Encrypt the zip data
        let encrypted = Crypto::encrypt(&zip_data, password)?;

        // Write to vault file
        fs::write(&vault_file, &encrypted)?;

        // Remove original profile directory (send to recycle bin conceptually, but for reliability we'll just remove)
        fs::remove_dir_all(&profile.path)?;

        // Update config
        let locked_profile = LockedProfile {
            browser: browser_name.to_string(),
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            original_path: profile.path.clone(),
            vault_path: vault_file,
            locked_at: Utc::now().to_rfc3339(),
        };
        self.config.add_locked_profile(locked_profile);
        self.config.save()?;

        Ok(())
    }

    pub fn unlock_profile(&mut self, browser: &Browser, profile_id: &str, password: &str) -> Result<()> {
        let browser_name = browser.name();

        // Get locked profile info
        let locked_profile = self.config
            .get_locked_profile(browser_name, profile_id)
            .ok_or(VaultError::NotLocked)?
            .clone();

        // Read vault file
        let encrypted = fs::read(&locked_profile.vault_path)?;

        // Decrypt
        let zip_data = Crypto::decrypt(&encrypted, password)?;

        // Ensure parent directory exists
        if let Some(parent) = locked_profile.original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Unzip to original location
        unzip_to_directory(&zip_data, &locked_profile.original_path)?;

        // Remove vault file
        fs::remove_file(&locked_profile.vault_path)?;

        // Update config
        self.config.remove_locked_profile(browser_name, profile_id);
        self.config.save()?;

        Ok(())
    }

    pub fn list_locked(&self) -> Vec<&LockedProfile> {
        self.config.locked_profiles.values().collect()
    }

    pub fn is_locked(&self, browser: &Browser, profile_id: &str) -> bool {
        self.config.is_locked(browser.name(), profile_id)
    }
}

fn zip_directory(path: &Path) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buffer);
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for entry in WalkDir::new(path) {
            let entry = entry?;
            let entry_path = entry.path();
            let relative_path = entry_path.strip_prefix(path).unwrap();

            if entry_path.is_file() {
                let path_str = relative_path.to_string_lossy().replace("\\", "/");
                zip.start_file(&path_str, options)
                    .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

                let mut file = File::open(entry_path)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                zip.write_all(&contents)?;
            } else if entry_path.is_dir() && entry_path != path {
                let path_str = format!("{}/", relative_path.to_string_lossy().replace("\\", "/"));
                zip.add_directory(&path_str, options)
                    .map_err(|e| VaultError::EncryptionError(e.to_string()))?;
            }
        }

        zip.finish().map_err(|e| VaultError::EncryptionError(e.to_string()))?;
    }
    Ok(buffer)
}

fn unzip_to_directory(data: &[u8], dest: &Path) -> Result<()> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

    fs::create_dir_all(dest)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

        let outpath = dest.join(file.name());

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn is_browser_running(browser: &Browser) -> bool {
    let exe_name = browser.executable_name();

    #[cfg(windows)]
    {
        use std::process::Command;
        let output = Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", exe_name)])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains(exe_name)
            }
            Err(_) => false,
        }
    }

    #[cfg(not(windows))]
    {
        use std::process::Command;
        let output = Command::new("pgrep")
            .arg("-x")
            .arg(exe_name.trim_end_matches(".exe"))
            .output();

        matches!(output, Ok(out) if out.status.success())
    }
}
