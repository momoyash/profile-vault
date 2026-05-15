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
        #[cfg(windows)]
        {
            let local_app_data = std::env::var("LOCALAPPDATA")
                .map_err(|_| VaultError::Config("LOCALAPPDATA not set".to_string()))?;
            let app_data = std::env::var("APPDATA")
                .map_err(|_| VaultError::Config("APPDATA not set".to_string()))?;

            let path = match self {
                Browser::Chrome => PathBuf::from(&local_app_data).join("Google/Chrome/User Data"),
                Browser::Edge => PathBuf::from(&local_app_data).join("Microsoft/Edge/User Data"),
                Browser::Brave => {
                    PathBuf::from(&local_app_data).join("BraveSoftware/Brave-Browser/User Data")
                }
                Browser::Chromium => PathBuf::from(&local_app_data).join("Chromium/User Data"),
                Browser::Firefox => PathBuf::from(&app_data).join("Mozilla/Firefox/Profiles"),
            };
            Ok(path)
        }

        #[cfg(target_os = "linux")]
        {
            let home = std::env::var("HOME")
                .map_err(|_| VaultError::Config("HOME not set".to_string()))?;
            let path = match self {
                Browser::Chrome => PathBuf::from(&home).join(".config/google-chrome"),
                Browser::Edge => PathBuf::from(&home).join(".config/microsoft-edge"),
                Browser::Brave => PathBuf::from(&home).join(".config/BraveSoftware/Brave-Browser"),
                Browser::Chromium => PathBuf::from(&home).join(".config/chromium"),
                Browser::Firefox => PathBuf::from(&home).join(".mozilla/firefox"),
            };
            Ok(path)
        }

        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME")
                .map_err(|_| VaultError::Config("HOME not set".to_string()))?;
            let path = match self {
                Browser::Chrome => {
                    PathBuf::from(&home).join("Library/Application Support/Google/Chrome")
                }
                Browser::Edge => {
                    PathBuf::from(&home).join("Library/Application Support/Microsoft Edge")
                }
                Browser::Brave => PathBuf::from(&home)
                    .join("Library/Application Support/BraveSoftware/Brave-Browser"),
                Browser::Chromium => {
                    PathBuf::from(&home).join("Library/Application Support/Chromium")
                }
                Browser::Firefox => {
                    PathBuf::from(&home).join("Library/Application Support/Firefox/Profiles")
                }
            };
            Ok(path)
        }
    }

    pub fn executable_name(&self) -> &'static str {
        #[cfg(windows)]
        {
            match self {
                Browser::Chrome => "chrome.exe",
                Browser::Edge => "msedge.exe",
                Browser::Firefox => "firefox.exe",
                Browser::Brave => "brave.exe",
                Browser::Chromium => "chromium.exe",
            }
        }
        #[cfg(not(windows))]
        {
            match self {
                Browser::Chrome => "chrome",
                Browser::Edge => "msedge",
                Browser::Firefox => "firefox",
                Browser::Brave => "brave",
                Browser::Chromium => "chromium",
            }
        }
    }

    pub fn is_chromium_based(&self) -> bool {
        matches!(
            self,
            Browser::Chrome | Browser::Edge | Browser::Brave | Browser::Chromium
        )
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>> {
        let profiles_dir = self.profiles_dir()?;

        if !profiles_dir.exists() {
            return Ok(vec![]);
        }

        let mut profiles = Vec::new();

        if self.is_chromium_based() {
            let local_state_path = profiles_dir.join("Local State");
            if local_state_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&local_state_path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(cache) = json["profile"]["info_cache"].as_object() {
                            for (id, info) in cache {
                                let name = info["name"].as_str().unwrap_or(id).to_string();
                                let path = profiles_dir.join(id);
                                if path.is_dir() {
                                    profiles.push(ProfileInfo {
                                        id: id.clone(),
                                        name,
                                        path,
                                        browser: *self,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Firefox: each subdirectory of the Profiles dir is a profile,
            // except for non-profile siblings the installer leaves behind.
            let skip = ["Crash Reports", "Pending Pings"];
            for entry in std::fs::read_dir(&profiles_dir)? {
                let entry = entry?;
                if !entry.path().is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if skip.contains(&name.as_str()) {
                    continue;
                }
                profiles.push(ProfileInfo {
                    id: name.clone(),
                    name: name.clone(),
                    path: entry.path(),
                    browser: *self,
                });
            }
        }

        Ok(profiles)
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
    let all = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Firefox,
        Browser::Brave,
        Browser::Chromium,
    ];
    all.into_iter()
        .filter(|b| b.profiles_dir().map(|p| p.exists()).unwrap_or(false))
        .collect()
}
