use std::collections::HashMap;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub locked_profiles: HashMap<String, LockedProfile>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedProfile {
    pub browser: String,
    pub profile_id: String,
    pub profile_name: String,
    pub original_path: PathBuf,
    pub vault_path: PathBuf,
    pub locked_at: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            serde_json::from_str(&content)
                .map_err(|e| VaultError::Config(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| VaultError::Config(e.to_string()))?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
            .ok_or_else(|| VaultError::Config("Could not determine config directory".to_string()))?;
        Ok(proj_dirs.config_dir().join("config.json"))
    }

    pub fn vault_dir() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "profile-vault", "profile-vault")
            .ok_or_else(|| VaultError::Config("Could not determine data directory".to_string()))?;
        let vault_dir = proj_dirs.data_dir().join("vaults");
        std::fs::create_dir_all(&vault_dir)?;
        Ok(vault_dir)
    }

    pub fn profile_key(browser: &str, profile_id: &str) -> String {
        format!("{}:{}", browser.to_lowercase(), profile_id)
    }

    pub fn add_locked_profile(&mut self, profile: LockedProfile) {
        let key = Self::profile_key(&profile.browser, &profile.profile_id);
        self.locked_profiles.insert(key, profile);
    }

    pub fn remove_locked_profile(&mut self, browser: &str, profile_id: &str) -> Option<LockedProfile> {
        let key = Self::profile_key(browser, profile_id);
        self.locked_profiles.remove(&key)
    }

    pub fn get_locked_profile(&self, browser: &str, profile_id: &str) -> Option<&LockedProfile> {
        let key = Self::profile_key(browser, profile_id);
        self.locked_profiles.get(&key)
    }

    pub fn is_locked(&self, browser: &str, profile_id: &str) -> bool {
        self.get_locked_profile(browser, profile_id).is_some()
    }
}
