//! Starting, watching and stopping the local LSADRA server.
//!
//! The tray app never exposes the server beyond this machine: it always binds
//! 127.0.0.1, and the dashboard window talks to it over loopback. If a server
//! is already answering on the port (for example one started by hand), the
//! app uses it and leaves it running on quit.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use crate::settings::Settings;

/// Origins the dashboard window has inside the desktop app: `tauri://localhost`
/// on macOS and Linux, `http(s)://tauri.localhost` on Windows. The API's CORS
/// allowlist must include them or every request from the window is refused.
pub const DESKTOP_ORIGINS: [&str; 3] = [
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];

/// Name of a self-contained server build shipped next to the app executable.
#[cfg(windows)]
pub const BUNDLED_SERVER: &str = "lsadra-server.exe";
#[cfg(not(windows))]
pub const BUNDLED_SERVER: &str = "lsadra-server";

const LOG_LIMIT_BYTES: u64 = 5 * 1024 * 1024;

/// How the server will be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// A self-contained server executable next to the app.
    Bundled { program: PathBuf },
    /// `python -m lsadra.serve` (or uvicorn on older checkouts) in a source folder.
    Python {
        program: OsString,
        dir: PathBuf,
        args: Vec<String>,
    },
    /// Nothing to start: no bundled server and no LSADRA folder found.
    NotConfigured,
}

/// True if `dir` looks like an LSADRA source folder.
pub fn is_server_dir(dir: &Path) -> bool {
    dir.join("server.py").is_file() && dir.join("lsadra").is_dir()
}

/// Walk up from the executable to find a checkout, so `npm run dev` inside
/// `desktop/` works with no settings at all.
pub fn find_checkout(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| is_server_dir(d))
        .map(Path::to_path_buf)
}

/// Prefer the checkout's own virtual environment, then the system Python.
pub fn default_python(dir: &Path) -> OsString {
    let venv = if cfg!(windows) {
        [".venv", "Scripts", "python.exe"]
    } else {
        [".venv", "bin", "python"]
    };
    let candidate: PathBuf = venv.iter().fold(dir.to_path_buf(), |p, part| p.join(part));
    if candidate.is_file() {
        return candidate.into_os_string();
    }
    OsString::from(if cfg!(windows) { "python" } else { "python3" })
}

/// Decide how to start the server.
pub fn resolve_launch(settings: &Settings, exe_dir: Option<&Path>) -> Launch {
    if let Some(exe_dir) = exe_dir {
        let bundled = exe_dir.join(BUNDLED_SERVER);
        if bundled.is_file() {
            return Launch::Bundled { program: bundled };
        }
    }
    let dir = match settings
        .server_dir
        .clone()
        .or_else(|| exe_dir.and_then(find_checkout))
    {
        Some(dir) if is_server_dir(&dir) => dir,
        _ => return Launch::NotConfigured,
    };
    let program = settings
        .python
        .clone()
        .map(OsString::from)
        .unwrap_or_else(|| default_python(&dir));
    // `lsadra.serve` applies the listener policy (loopback default, TLS rules).
    // Checkouts that predate it fall back to plain uvicorn on loopback.
    let args = if dir.join("lsadra").join("serve.py").is_file() {
        vec!["-m".into(), "lsadra.serve".into()]
    } else {
        let port = settings.port.to_string();
        [
            "-m",
            "uvicorn",
            "server:app",
            "--host",
            "127.0.0.1",
            "--port",
            &port,
        ]
        .map(String::from)
        .to_vec()
    };
    Launch::Python { program, dir, args }
}

/// Environment for the server process. `inherited` is the app's own
/// environment lookup, injected for tests.
pub fn server_env(
    port: u16,
    secret: &str,
    inherited: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut origins: Vec<String> = inherited("LSADRA_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .collect();
    for origin in DESKTOP_ORIGINS {
        if !origins.iter().any(|o| o == origin) {
            origins.push(origin.to_string());
        }
    }
    let mut env = vec![
        ("LSADRA_API_HOST".to_string(), "127.0.0.1".to_string()),
        ("LSADRA_API_PORT".to_string(), port.to_string()),
        // Loopback only, so the API's HTTPS requirement (meant for agents that
        // send keys across the network) is not needed: nothing leaves this
        // machine. The server still refuses plain HTTP on any other address.
        ("LSADRA_REQUIRE_TLS".to_string(), "false".to_string()),
        ("LSADRA_CORS_ORIGINS".to_string(), origins.join(",")),
        ("PYTHONUTF8".to_string(), "1".to_string()),
        ("PYTHONUNBUFFERED".to_string(), "1".to_string()),
    ];
    if inherited("LSADRA_JWT_SECRET")
        .filter(|s| !s.is_empty())
        .is_none()
    {
        env.push(("LSADRA_JWT_SECRET".to_string(), secret.to_string()));
    }
    env
}

/// Parse `HTTP/1.x 200 OK` into 200.
pub fn parse_status_line(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// True if `GET /api/health` on 127.0.0.1:`port` answers 200. Plain HTTP over
/// loopback, no extra dependencies, one second budget.
pub fn probe(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let request =
        format!("GET /api/health HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 64];
    let n = stream.read(&mut head).unwrap_or(0);
    let text = String::from_utf8_lossy(&head[..n]);
    matches!(text.lines().next().and_then(parse_status_line), Some(200))
}

/// What the tray shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    NotConfigured,
    Stopped,
    Starting,
    Running { owned: bool },
    Exited(String),
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Status::NotConfigured => "Server: not set up (see README)".into(),
            Status::Stopped => "Server: stopped".into(),
            Status::Starting => "Server: starting…".into(),
            Status::Running { owned: true } => "Server: running".into(),
            Status::Running { owned: false } => "Server: running (started outside the app)".into(),
            Status::Exited(why) => format!("Server: stopped ({why})"),
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Status::Running { .. } | Status::Starting)
    }
}

/// Owns the server process, if the app started one.
pub struct Server {
    launch: Launch,
    port: u16,
    env: Vec<(String, String)>,
    log_path: PathBuf,
    child: Mutex<Option<Child>>,
    last_exit: Mutex<Option<String>>,
}

impl Server {
    pub fn new(launch: Launch, port: u16, env: Vec<(String, String)>, log_path: PathBuf) -> Self {
        Server {
            launch,
            port,
            env,
            log_path,
            child: Mutex::new(None),
            last_exit: Mutex::new(None),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Start the server unless one is already answering on the port.
    pub fn start(&self) -> Result<(), String> {
        if probe(self.port) {
            return Ok(());
        }
        let mut guard = self.child.lock().map_err(|_| "server lock poisoned")?;
        if let Some(child) = guard.as_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                return Ok(());
            }
        }
        let mut cmd = match &self.launch {
            Launch::NotConfigured => {
                return Err("no LSADRA server found; set server_dir in settings.json".into())
            }
            Launch::Bundled { program } => {
                let mut cmd = Command::new(program);
                if let Some(dir) = program.parent() {
                    cmd.current_dir(dir);
                }
                cmd
            }
            Launch::Python { program, dir, args } => {
                let mut cmd = Command::new(program);
                cmd.args(args).current_dir(dir);
                cmd
            }
        };
        let log = open_log(&self.log_path)
            .map_err(|e| format!("cannot open {}: {e}", self.log_path.display()))?;
        let log_err = log.try_clone().map_err(|e| e.to_string())?;
        cmd.envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        hide_console(&mut cmd);
        let child = cmd
            .spawn()
            .map_err(|e| format!("could not start the server: {e}"))?;
        *guard = Some(child);
        if let Ok(mut last) = self.last_exit.lock() {
            *last = None;
        }
        Ok(())
    }

    /// Stop the server if this app started it. A server started elsewhere is
    /// left alone.
    pub fn stop(&self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    pub fn status(&self) -> Status {
        let mut owned_alive = false;
        if let Ok(mut guard) = self.child.lock() {
            if let Some(child) = guard.as_mut() {
                match child.try_wait() {
                    Ok(None) => owned_alive = true,
                    Ok(Some(code)) => {
                        let why = match code.code() {
                            Some(c) => format!("exit code {c}, see server.log"),
                            None => "terminated, see server.log".into(),
                        };
                        if let Ok(mut last) = self.last_exit.lock() {
                            *last = Some(why);
                        }
                        *guard = None;
                    }
                    Err(_) => {}
                }
            }
        }
        let healthy = probe(self.port);
        match (owned_alive, healthy) {
            (true, true) => Status::Running { owned: true },
            (true, false) => Status::Starting,
            (false, true) => Status::Running { owned: false },
            (false, false) => {
                if let Some(why) = self.last_exit.lock().ok().and_then(|l| l.clone()) {
                    Status::Exited(why)
                } else if self.launch == Launch::NotConfigured {
                    Status::NotConfigured
                } else {
                    Status::Stopped
                }
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Append to the server log, starting it over once it passes 5 MB.
fn open_log(path: &Path) -> std::io::Result<fs::File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let too_big = fs::metadata(path)
        .map(|m| m.len() > LOG_LIMIT_BYTES)
        .unwrap_or(false);
    fs::OpenOptions::new()
        .create(true)
        .append(!too_big)
        .write(true)
        .truncate(too_big)
        .open(path)
}

#[cfg(windows)]
fn hide_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_cmd: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::DEFAULT_PORT;
    use std::collections::HashMap;
    use std::net::TcpListener;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn settings(dir: Option<PathBuf>) -> Settings {
        Settings {
            server_dir: dir,
            python: None,
            port: DEFAULT_PORT,
            autostart: true,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lsadra-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_checkout(name: &str, with_serve: bool) -> PathBuf {
        let dir = temp_dir(name);
        fs::create_dir_all(dir.join("lsadra")).unwrap();
        fs::write(dir.join("server.py"), "").unwrap();
        if with_serve {
            fs::write(dir.join("lsadra").join("serve.py"), "").unwrap();
        }
        dir
    }

    #[test]
    fn env_binds_loopback_and_allows_desktop_origins() {
        let env: HashMap<_, _> = server_env(8123, "s3cret", env_of(&[]))
            .into_iter()
            .collect();
        assert_eq!(env["LSADRA_API_HOST"], "127.0.0.1");
        assert_eq!(env["LSADRA_API_PORT"], "8123");
        assert_eq!(env["LSADRA_JWT_SECRET"], "s3cret");
        for origin in DESKTOP_ORIGINS {
            assert!(
                env["LSADRA_CORS_ORIGINS"].split(',').any(|o| o == origin),
                "{origin} missing"
            );
        }
        assert!(
            !env.contains_key("LSADRA_DEV_MODE"),
            "the desktop app must not turn on dev mode"
        );
        // Plain HTTP is allowed only because the bind address is loopback.
        assert_eq!(env["LSADRA_REQUIRE_TLS"], "false");
        assert_eq!(env["LSADRA_API_HOST"], "127.0.0.1");
    }

    #[test]
    fn env_keeps_existing_origins_and_secret() {
        let env: HashMap<_, _> = server_env(
            8000,
            "generated",
            env_of(&[
                (
                    "LSADRA_CORS_ORIGINS",
                    "http://localhost:5173, tauri://localhost",
                ),
                ("LSADRA_JWT_SECRET", "mine"),
            ]),
        )
        .into_iter()
        .collect();
        let origins: Vec<&str> = env["LSADRA_CORS_ORIGINS"].split(',').collect();
        assert_eq!(origins[0], "http://localhost:5173");
        assert_eq!(
            origins
                .iter()
                .filter(|o| **o == "tauri://localhost")
                .count(),
            1
        );
        assert!(
            !env.contains_key("LSADRA_JWT_SECRET"),
            "an operator-set secret is inherited, not replaced"
        );
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(
            parse_status_line("HTTP/1.0 503 Service Unavailable"),
            Some(503)
        );
        assert_eq!(parse_status_line("SSH-2.0-OpenSSH"), None);
        assert_eq!(parse_status_line(""), None);
    }

    #[test]
    fn resolve_prefers_bundled_server() {
        let exe_dir = temp_dir("bundled");
        fs::write(exe_dir.join(BUNDLED_SERVER), "").unwrap();
        let checkout = fake_checkout("bundled-co", true);
        let launch = resolve_launch(&settings(Some(checkout.clone())), Some(&exe_dir));
        assert_eq!(
            launch,
            Launch::Bundled {
                program: exe_dir.join(BUNDLED_SERVER)
            }
        );
        let _ = fs::remove_dir_all(&exe_dir);
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn resolve_uses_serve_module_when_present() {
        let checkout = fake_checkout("serve", true);
        match resolve_launch(&settings(Some(checkout.clone())), None) {
            Launch::Python { dir, args, .. } => {
                assert_eq!(dir, checkout);
                assert_eq!(args, vec!["-m", "lsadra.serve"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn resolve_falls_back_to_uvicorn_on_loopback() {
        let checkout = fake_checkout("uvicorn", false);
        match resolve_launch(&settings(Some(checkout.clone())), None) {
            Launch::Python { args, .. } => {
                assert!(args.windows(2).any(|w| w == ["--host", "127.0.0.1"]));
                assert!(args.windows(2).any(|w| w == ["--port", "8000"]));
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn resolve_finds_checkout_above_the_executable() {
        let checkout = fake_checkout("walk", true);
        let exe_dir = checkout
            .join("desktop")
            .join("src-tauri")
            .join("target")
            .join("debug");
        fs::create_dir_all(&exe_dir).unwrap();
        match resolve_launch(&settings(None), Some(&exe_dir)) {
            Launch::Python { dir, .. } => assert_eq!(dir, checkout),
            other => panic!("unexpected {other:?}"),
        }
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn resolve_reports_not_configured() {
        let nowhere = temp_dir("nowhere");
        assert_eq!(
            resolve_launch(&settings(Some(nowhere.clone())), Some(&nowhere)),
            Launch::NotConfigured
        );
        let _ = fs::remove_dir_all(&nowhere);
    }

    #[test]
    fn venv_python_is_preferred() {
        let checkout = fake_checkout("venv", true);
        assert!(!PathBuf::from(default_python(&checkout)).is_absolute());
        let venv = if cfg!(windows) {
            checkout.join(".venv/Scripts")
        } else {
            checkout.join(".venv/bin")
        };
        fs::create_dir_all(&venv).unwrap();
        let exe = venv.join(if cfg!(windows) {
            "python.exe"
        } else {
            "python"
        });
        fs::write(&exe, "").unwrap();
        assert_eq!(PathBuf::from(default_python(&checkout)), exe);
        let _ = fs::remove_dir_all(&checkout);
    }

    /// A tiny one-shot HTTP responder on a free loopback port.
    fn serve_once(status: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                );
            }
        });
        port
    }

    #[test]
    fn probe_reports_health() {
        assert!(probe(serve_once("200 OK")));
        assert!(!probe(serve_once("503 Service Unavailable")));
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(!probe(closed));
    }

    #[test]
    fn not_configured_server_refuses_to_start() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let server = Server::new(
            Launch::NotConfigured,
            closed,
            vec![],
            temp_dir("nc").join("server.log"),
        );
        assert!(server.start().is_err());
        assert_eq!(server.status(), Status::NotConfigured);
        assert!(!server.status().is_running());
    }

    #[cfg(unix)]
    #[test]
    fn owned_process_is_tracked_and_stopped() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = temp_dir("owned");
        let launch = Launch::Python {
            program: "sleep".into(),
            dir: dir.clone(),
            args: vec!["30".into()],
        };
        let server = Server::new(launch, closed, vec![], dir.join("server.log"));
        server.start().unwrap();
        assert_eq!(
            server.status(),
            Status::Starting,
            "alive but not answering health yet"
        );
        server.stop();
        assert_eq!(server.status(), Status::Stopped);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn crashed_process_is_reported() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = temp_dir("crash");
        let launch = Launch::Python {
            program: "sh".into(),
            dir: dir.clone(),
            args: vec!["-c".into(), "exit 3".into()],
        };
        let server = Server::new(launch, closed, vec![], dir.join("server.log"));
        server.start().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            server.status(),
            Status::Exited("exit code 3, see server.log".into())
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
