use std::path::PathBuf;

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
    Brave,
    Chromium,
}

impl Browser {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(Browser::Chrome),
            "edge" => Ok(Browser::Edge),
            "firefox" => Ok(Browser::Firefox),
            "brave" => Ok(Browser::Brave),
            "chromium" => Ok(Browser::Chromium),
            _ => Err(VaultError::UnsupportedBrowser(s.to_string())),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Firefox => "Firefox",
            Browser::Brave => "Brave",
            Browser::Chromium => "Chromium",
        }
    }

    pub fn profiles_dir(&self) -> Result<PathBuf> {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .map_err(|_| VaultError::Config("LOCALAPPDATA not set".to_string()))?;
        let app_data = std::env::var("APPDATA")
            .map_err(|_| VaultError::Config("APPDATA not set".to_string()))?;

        let path = match self {
            Browser::Chrome => PathBuf::from(&local_app_data).join("Google/Chrome/User Data"),
            Browser::Edge => PathBuf::from(&local_app_data).join("Microsoft/Edge/User Data"),
            Browser::Brave => PathBuf::from(&local_app_data).join("BraveSoftware/Brave-Browser/User Data"),
            Browser::Chromium => PathBuf::from(&local_app_data).join("Chromium/User Data"),
            Browser::Firefox => PathBuf::from(&app_data).join("Mozilla/Firefox/Profiles"),
        };

        Ok(path)
    }

    pub fn executable_name(&self) -> &'static str {
        match self {
            Browser::Chrome => "chrome.exe",
            Browser::Edge => "msedge.exe",
            Browser::Firefox => "firefox.exe",
            Browser::Brave => "brave.exe",
            Browser::Chromium => "chromium.exe",
        }
    }

    pub fn is_chromium_based(&self) -> bool {
        matches!(self, Browser::Chrome | Browser::Edge | Browser::Brave | Browser::Chromium)
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>> {
        let profiles_dir = self.profiles_dir()?;

        if !profiles_dir.exists() {
            return Ok(vec![]);
        }

        let mut profiles = Vec::new();

        if self.is_chromium_based() {
            // Chromium-based browsers: look for "Default", "Profile 1", etc.
            for entry in std::fs::read_dir(&profiles_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();

                if entry.path().is_dir() && (name == "Default" || name.starts_with("Profile ")) {
                    let display_name = self.get_chromium_profile_name(&entry.path())?;
                    profiles.push(ProfileInfo {
                        id: name.clone(),
                        name: display_name,
                        path: entry.path(),
                        browser: *self,
                    });
                }
            }
        } else {
            // Firefox: each folder is a profile
            for entry in std::fs::read_dir(&profiles_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    profiles.push(ProfileInfo {
                        id: name.clone(),
                        name: name.clone(),
                        path: entry.path(),
                        browser: *self,
                    });
                }
            }
        }

        Ok(profiles)
    }

    fn get_chromium_profile_name(&self, profile_path: &PathBuf) -> Result<String> {
        let prefs_path = profile_path.join("Preferences");
        if prefs_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&prefs_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(name) = json["profile"]["name"].as_str() {
                        return Ok(name.to_string());
                    }
                }
            }
        }
        Ok(profile_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub browser: Browser,
}

impl ProfileInfo {
    pub fn display(&self) -> String {
        if self.id == self.name {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.id)
        }
    }
}

pub fn detect_browsers() -> Vec<Browser> {
    let all = [Browser::Chrome, Browser::Edge, Browser::Firefox, Browser::Brave, Browser::Chromium];
    all.into_iter()
        .filter(|b| b.profiles_dir().map(|p| p.exists()).unwrap_or(false))
        .collect()
}
