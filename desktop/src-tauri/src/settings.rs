//! Desktop settings and the per-install JWT secret.
//!
//! Settings live in `<app config dir>/settings.json`. Every field is optional;
//! environment variables override the file so a developer can point the app at
//! a checkout without editing anything:
//!
//! | Field        | Env override     | Meaning                                      |
//! |--------------|------------------|----------------------------------------------|
//! | `server`     | `LSADRA_SERVER`  | An installed `lsadra-server` executable      |
//! | `server_dir` | `LSADRA_HOME`    | Folder holding `server.py` and `lsadra/`     |
//! | `python`     | `LSADRA_PYTHON`  | Python interpreter that has LSADRA installed |
//! | `port`       | `LSADRA_API_PORT`| API port on 127.0.0.1 (default 8000)         |
//! | `autostart`  | —                | Start the server when the app starts         |

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 8000;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SettingsFile {
    pub server: Option<PathBuf>,
    pub server_dir: Option<PathBuf>,
    pub python: Option<String>,
    pub port: Option<u16>,
    pub autostart: Option<bool>,
}

/// Settings after the environment has been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub server: Option<PathBuf>,
    pub server_dir: Option<PathBuf>,
    pub python: Option<String>,
    pub port: u16,
    pub autostart: bool,
}

impl Settings {
    /// Merge the settings file with environment overrides. `env` is injected
    /// so tests do not depend on the real process environment.
    pub fn resolve(file: SettingsFile, env: impl Fn(&str) -> Option<String>) -> Self {
        let non_empty = |key: &str| env(key).filter(|v| !v.trim().is_empty());
        let port = non_empty("LSADRA_API_PORT")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .or(file.port)
            .unwrap_or(DEFAULT_PORT);
        Settings {
            server: non_empty("LSADRA_SERVER")
                .map(PathBuf::from)
                .or(file.server),
            server_dir: non_empty("LSADRA_HOME")
                .map(PathBuf::from)
                .or(file.server_dir),
            python: non_empty("LSADRA_PYTHON").or(file.python),
            port,
            autostart: file.autostart.unwrap_or(true),
        }
    }
}

/// Read `settings.json`, writing a commented default on first run. A broken
/// file is reported and treated as empty rather than stopping the app.
pub fn load_file(config_dir: &Path) -> SettingsFile {
    let path = config_dir.join("settings.json");
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
            eprintln!("lsadra-desktop: ignoring {}: {err}", path.display());
            SettingsFile::default()
        }),
        Err(_) => {
            let _ = fs::create_dir_all(config_dir);
            if let Ok(text) = serde_json::to_string_pretty(&SettingsFile::default()) {
                let _ = fs::write(&path, text);
            }
            SettingsFile::default()
        }
    }
}

/// The JWT signing secret for this install. Created once with 32 random bytes
/// and kept in the app data folder (owner-only on Unix), so sessions survive a
/// restart and no placeholder secret is ever used. An `LSADRA_JWT_SECRET`
/// already in the environment wins and is never written to disk.
pub fn jwt_secret(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join("jwt_secret");
    if let Ok(existing) = fs::read_to_string(&path) {
        let existing = existing.trim().to_string();
        if existing.len() >= 32 {
            return Ok(existing);
        }
    }
    fs::create_dir_all(data_dir)?;
    let secret = random_hex()?;
    let mut file = open_private(&path)?;
    file.write_all(secret.as_bytes())?;
    Ok(secret)
}

/// 32 random bytes as 64 hex characters.
pub fn random_hex() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    // The app data folder is already per-user on Windows (%APPDATA%).
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let s = Settings::resolve(SettingsFile::default(), env_of(&[]));
        assert_eq!(s.port, DEFAULT_PORT);
        assert!(s.autostart);
        assert!(s.server.is_none());
        assert!(s.server_dir.is_none());
        assert!(s.python.is_none());
    }

    #[test]
    fn environment_overrides_file() {
        let file = SettingsFile {
            server: Some("/file/lsadra-server".into()),
            server_dir: Some("/from/file".into()),
            python: Some("py-file".into()),
            port: Some(9000),
            autostart: Some(false),
        };
        let s = Settings::resolve(
            file,
            env_of(&[
                ("LSADRA_SERVER", "/env/lsadra-server"),
                ("LSADRA_HOME", "/from/env"),
                ("LSADRA_PYTHON", "py-env"),
                ("LSADRA_API_PORT", "8123"),
            ]),
        );
        assert_eq!(s.server, Some(PathBuf::from("/env/lsadra-server")));
        assert_eq!(s.server_dir, Some(PathBuf::from("/from/env")));
        assert_eq!(s.python.as_deref(), Some("py-env"));
        assert_eq!(s.port, 8123);
        assert!(!s.autostart);
    }

    #[test]
    fn bad_or_empty_env_values_fall_back() {
        let file = SettingsFile {
            port: Some(9000),
            ..Default::default()
        };
        let s = Settings::resolve(
            file,
            env_of(&[("LSADRA_API_PORT", "not-a-port"), ("LSADRA_HOME", "  ")]),
        );
        assert_eq!(s.port, 9000);
        assert!(s.server_dir.is_none());
    }

    #[test]
    fn settings_file_round_trips_and_tolerates_garbage() {
        let dir = std::env::temp_dir().join(format!("lsadra-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(load_file(&dir), SettingsFile::default());
        assert!(dir.join("settings.json").exists());
        fs::write(dir.join("settings.json"), r#"{"port": 8555}"#).unwrap();
        assert_eq!(load_file(&dir).port, Some(8555));
        fs::write(dir.join("settings.json"), "{not json").unwrap();
        assert_eq!(load_file(&dir), SettingsFile::default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn jwt_secret_is_random_stable_and_private() {
        let dir = std::env::temp_dir().join(format!("lsadra-secret-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = jwt_secret(&dir).unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            jwt_secret(&dir).unwrap(),
            first,
            "secret must survive restarts"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("jwt_secret"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let other = std::env::temp_dir().join(format!("lsadra-secret2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&other);
        assert_ne!(
            jwt_secret(&other).unwrap(),
            first,
            "each install gets its own secret"
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&other);
    }
}
