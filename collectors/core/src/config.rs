//! Agent configuration (TOML). The device key is not part of it.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of the LSADRA core, e.g. `https://lsadra.example:8443`.
    pub server_url: String,
    /// Registered device id (sent as `X-Device-Id`).
    pub device_id: String,
    /// Where the spool, cursors and (on Linux) the key file live.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Hard cap on spool size on disk.
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    /// Events per request, at most 100 (the core's limit).
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Ship a partial batch after this many seconds.
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// PEM file with the CA that signed the core's certificate, for a
    /// self-hosted core with a private CA. Public roots are used otherwise.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Plain `http://` sends the device key in clear text, so it is refused
    /// unless the server is on loopback or this is set.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Keep the device key in this owner-only file instead of the OS
    /// keychain (headless hosts, containers, tests). Linux always uses a file.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub journald: JournaldConfig,
    #[serde(default)]
    pub wineventlog: WinEventLogConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournaldConfig {
    /// `SYSLOG_IDENTIFIER`s to follow.
    #[serde(default = "default_identifiers")]
    pub identifiers: Vec<String>,
}

impl Default for JournaldConfig {
    fn default() -> Self {
        JournaldConfig {
            identifiers: default_identifiers(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WinEventLogConfig {
    /// Override the built-in XPath query list (advanced).
    #[serde(default)]
    pub query: Option<String>,
}

fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\LSADRA\agent")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/LSADRA/agent")
    } else {
        PathBuf::from("/var/lib/lsadra-agent")
    }
}
fn default_spool_max_bytes() -> u64 {
    64 * 1024 * 1024
}
fn default_batch_size() -> usize {
    100
}
fn default_flush_interval_secs() -> u64 {
    3
}
fn default_identifiers() -> Vec<String> {
    ["sshd", "sshd-session", "sudo", "su"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.batch_size = cfg.batch_size.clamp(1, crate::event::MAX_EVENTS_PER_BATCH);
        cfg.flush_interval_secs = cfg.flush_interval_secs.clamp(1, 300);
        if cfg.device_id.is_empty() || cfg.device_id.len() > 128 {
            return Err("device_id must be 1-128 characters".into());
        }
        cfg.check_transport()?;
        Ok(cfg)
    }

    fn check_transport(&self) -> Result<(), String> {
        let url = self.server_url.trim_end_matches('/');
        if url.starts_with("https://") {
            return Ok(());
        }
        let Some(rest) = url.strip_prefix("http://") else {
            return Err("server_url must start with https:// or http://".into());
        };
        let host = rest.split('/').next().unwrap_or("");
        let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if loopback || self.allow_insecure_http {
            Ok(())
        } else {
            Err(
                "server_url is plain http:// to a non-loopback host; use https:// \
                 (or set allow_insecure_http = true for a lab)"
                    .into(),
            )
        }
    }

    pub fn batch_url(&self) -> String {
        format!("{}/api/events/batch", self.server_url.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse("server_url = \"https://core.demo\"\ndevice_id = \"dev-1\"\n").unwrap();
        assert_eq!(c.batch_size, 100);
        assert_eq!(c.batch_url(), "https://core.demo/api/events/batch");
        assert!(c.journald.identifiers.contains(&"sshd".to_string()));
    }

    #[test]
    fn batch_size_clamped_to_contract() {
        let c =
            Config::parse("server_url = \"https://c.demo\"\ndevice_id = \"d\"\nbatch_size = 500\n").unwrap();
        assert_eq!(c.batch_size, 100);
    }

    #[test]
    fn cleartext_to_remote_host_refused() {
        assert!(Config::parse("server_url = \"http://192.0.2.10:8000\"\ndevice_id = \"d\"\n").is_err());
        assert!(Config::parse("server_url = \"http://127.0.0.1:8000\"\ndevice_id = \"d\"\n").is_ok());
        assert!(Config::parse(
            "server_url = \"http://192.0.2.10:8000\"\ndevice_id = \"d\"\nallow_insecure_http = true\n"
        )
        .is_ok());
    }

    #[test]
    fn api_key_in_config_is_rejected() {
        let e = Config::parse("server_url = \"https://c.demo\"\ndevice_id = \"d\"\napi_key = \"k\"\n");
        assert!(e.is_err(), "unknown keys (like a pasted api_key) are refused");
    }
}
