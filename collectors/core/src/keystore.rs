//! Device API key storage.
//!
//! The key never goes in the config file. On macOS it lives in the Keychain
//! and on Windows in the Credential Manager (through the `keyring` crate). On
//! Linux the agent runs as a headless root service with no user keyring, so it
//! uses a file in the state directory that only its owner can read, and it
//! refuses to load a key file that anyone else could read.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SERVICE: &str = "lsadra-agent";
pub const KEY_FILE: &str = "device.key";

pub trait KeyStore: Send + Sync {
    fn get(&self) -> io::Result<String>;
    fn set(&self, key: &str) -> io::Result<()>;
    fn describe(&self) -> String;
}

/// The platform's store for `device_id`: keychain on macOS/Windows, a
/// root-only file under `state_dir` elsewhere.
pub fn platform_store(device_id: &str, state_dir: &Path) -> Box<dyn KeyStore> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let _ = state_dir;
        Box::new(OsKeychain {
            account: device_id.to_string(),
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = device_id;
        Box::new(FileKeyStore::new(state_dir.join(KEY_FILE)))
    }
}

fn check_key(key: &str) -> io::Result<()> {
    if key.is_empty() || key.len() > 512 || key.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device key must be 1-512 printable characters",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub struct OsKeychain {
    account: String,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl KeyStore for OsKeychain {
    fn get(&self) -> io::Result<String> {
        keyring::Entry::new(SERVICE, &self.account)
            .and_then(|e| e.get_password())
            .map_err(io::Error::other)
    }

    fn set(&self, key: &str) -> io::Result<()> {
        check_key(key)?;
        keyring::Entry::new(SERVICE, &self.account)
            .and_then(|e| e.set_password(key))
            .map_err(io::Error::other)
    }

    fn describe(&self) -> String {
        format!("OS keychain ({SERVICE}/{})", self.account)
    }
}

/// A key file readable and writable only by its owner (mode 0600 on Unix).
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        FileKeyStore { path }
    }
}

impl KeyStore for FileKeyStore {
    fn get(&self) -> io::Result<String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&self.path)?;
            if meta.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is readable by group or others; run chmod 600 on it",
                        self.path.display()
                    ),
                ));
            }
            // SAFETY: geteuid has no preconditions and cannot fail.
            let euid = unsafe { libc_geteuid() };
            if meta.uid() != euid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is not owned by the agent's user", self.path.display()),
                ));
            }
        }
        let key = fs::read_to_string(&self.path)?.trim().to_string();
        check_key(&key)?;
        Ok(key)
    }

    fn set(&self, key: &str) -> io::Result<()> {
        check_key(key)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            let mut f = opts.open(&tmp)?;
            f.write_all(key.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }

    fn describe(&self) -> String {
        format!("owner-only key file {}", self.path.display())
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file_store_round_trip_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("device.key"));
        store.set("k3y-demo").unwrap();
        let mode = fs::metadata(dir.path().join("device.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(store.get().unwrap(), "k3y-demo");
    }

    #[test]
    fn world_readable_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        fs::write(&path, "k3y-demo").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = FileKeyStore::new(path).get().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn bad_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("device.key"));
        for bad in ["", "has space", "line\nbreak"] {
            assert!(store.set(bad).is_err(), "{bad:?}");
        }
    }
}
