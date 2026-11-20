//! Starting, watching and stopping the local LSADRA server.
//!
//! The tray app never exposes the server beyond this machine: it always binds
//! 127.0.0.1, and the dashboard window talks to it over loopback. If a server
//! is already answering on the port (for example one started by hand), the
//! app uses it and leaves it running on quit.
//!
//! A bundled or installed `lsadra-server` keeps its database, models and logs
//! in this user's app data folder (`LSADRA_DATA_DIR`, `LSADRA_LOG_DIR`), never
//! in the folder it happens to be started from. A source checkout keeps its
//! own `data/` folder, as it does when run by hand.

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

/// Name of the server command: a self-contained build shipped next to the
/// app executable, or the console script `pip install lsadra` puts on PATH.
#[cfg(windows)]
pub const BUNDLED_SERVER: &str = "lsadra-server.exe";
#[cfg(not(windows))]
pub const BUNDLED_SERVER: &str = "lsadra-server";

/// The only address the app ever asks the server to listen on.
pub const LOOPBACK_HOST: &str = "127.0.0.1";

const LOG_LIMIT_BYTES: u64 = 5 * 1024 * 1024;

/// How the server will be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// A self-contained server executable next to the app.
    Bundled { program: PathBuf },
    /// An installed `lsadra-server` (pip or pipx), from settings or PATH.
    Installed { program: PathBuf },
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

impl Launch {
    /// True for a server that is not run from a source checkout, so its data
    /// belongs in the per-user app data folder.
    pub fn is_packaged(&self) -> bool {
        matches!(self, Launch::Bundled { .. } | Launch::Installed { .. })
    }
}

/// Find an installed `lsadra-server`: each folder in `path` (the PATH
/// variable), then `~/.local/bin`, where pipx installs it. Apps started from
/// a desktop menu often get a short PATH that leaves pipx's folder out.
pub fn find_installed(path: Option<OsString>, home: Option<PathBuf>) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = path
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(home) = home {
        dirs.push(home.join(".local").join("bin"));
    }
    dirs.into_iter()
        .filter(|d| d.is_absolute())
        .map(|d| d.join(BUNDLED_SERVER))
        .find(|p| p.is_file())
}

/// Folder the installers put the self-contained server in, inside the app's
/// resource folder (see `tauri.sidecar.conf.json`).
pub const BUNDLED_SERVER_DIR: &str = "lsadra-server";

/// Find the self-contained server the installer ships: in the app's resource
/// folder (`lsadra-server/lsadra-server`), or directly next to the executable.
pub fn find_bundled(exe_dir: Option<&Path>, resource_dir: Option<&Path>) -> Option<PathBuf> {
    let in_resources = resource_dir.map(|d| d.join(BUNDLED_SERVER_DIR).join(BUNDLED_SERVER));
    let beside_exe = exe_dir.map(|d| d.join(BUNDLED_SERVER));
    [in_resources, beside_exe]
        .into_iter()
        .flatten()
        .find(|p| p.is_file())
}

/// Decide how to start the server, in this order:
///
/// 1. `bundled`, the self-contained server found by [`find_bundled`];
/// 2. the `server` setting (`LSADRA_SERVER`), an installed `lsadra-server`;
/// 3. the `server_dir` setting (`LSADRA_HOME`), a source checkout;
/// 4. a checkout above the app executable (`npm run dev`);
/// 5. `installed`, the `lsadra-server` found on PATH by [`find_installed`].
pub fn resolve_launch(
    settings: &Settings,
    exe_dir: Option<&Path>,
    bundled: Option<PathBuf>,
    installed: Option<PathBuf>,
) -> Launch {
    if let Some(program) = bundled {
        return Launch::Bundled { program };
    }
    if let Some(program) = settings.server.clone().filter(|p| p.is_file()) {
        return Launch::Installed { program };
    }
    let checkout = settings
        .server_dir
        .clone()
        .filter(|d| is_server_dir(d))
        .or_else(|| exe_dir.and_then(find_checkout));
    let dir = match (checkout, installed) {
        (Some(dir), _) => dir,
        (None, Some(program)) => return Launch::Installed { program },
        (None, None) => return Launch::NotConfigured,
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
            LOOPBACK_HOST,
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
        ("LSADRA_API_HOST".to_string(), LOOPBACK_HOST.to_string()),
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

/// Hand the server a first-run setup token (`LSADRA_SETUP_TOKEN`), so the
/// dashboard can create the first admin account without a shell. The token is
/// new at every app start and only goes to the server this app launches and
/// to its own window. A token already in the environment is kept.
pub fn setup_env(token: &str, inherited: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    match inherited("LSADRA_SETUP_TOKEN").filter(|v| !v.trim().is_empty()) {
        Some(_) => Vec::new(),
        None => vec![("LSADRA_SETUP_TOKEN".to_string(), token.to_string())],
    }
}

/// The dashboard address the window opens: the start page, carrying the setup
/// token the frontend keeps for first-run setup (frontend/src/services/setupToken.ts).
pub fn dashboard_path(
    env: &[(String, String)],
    inherited: impl Fn(&str) -> Option<String>,
) -> String {
    let token = env
        .iter()
        .rev()
        .find(|(k, _)| k == "LSADRA_SETUP_TOKEN")
        .map(|(_, v)| v.clone())
        .or_else(|| inherited("LSADRA_SETUP_TOKEN"))
        .filter(|t| {
            !t.is_empty()
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
    match token {
        // "/" (not "index.html"): the dashboard router has no /index.html route.
        Some(t) => format!("/?setup_token={t}"),
        None => "index.html".to_string(),
    }
}

/// Where a packaged server keeps its data: `LSADRA_DATA_DIR` and
/// `LSADRA_LOG_DIR` in this user's app folders, unless the user already set
/// them. Empty for a checkout, which keeps its own `data/` and `logs/`.
pub fn data_env(
    launch: &Launch,
    data_dir: &Path,
    log_dir: &Path,
    inherited: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    if !launch.is_packaged() {
        return Vec::new();
    }
    [("LSADRA_DATA_DIR", data_dir), ("LSADRA_LOG_DIR", log_dir)]
        .into_iter()
        .filter(|(key, _)| inherited(key).filter(|v| !v.trim().is_empty()).is_none())
        .map(|(key, dir)| (key.to_string(), dir.to_string_lossy().into_owned()))
        .collect()
}

/// The data folder the server will use, if the app or the user chose one.
pub fn data_dir_of(
    env: &[(String, String)],
    inherited: impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    env.iter()
        .rev()
        .find(|(k, _)| k == "LSADRA_DATA_DIR")
        .map(|(_, v)| v.clone())
        .or_else(|| inherited("LSADRA_DATA_DIR"))
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// The HTTPS waiver (`LSADRA_REQUIRE_TLS=false`) is only acceptable for a
/// server bound to loopback. Returns an error if the waiver is present and
/// the environment or a `--host` argument would bind anything else.
pub fn check_tls_waiver(env: &[(String, String)], launch: &Launch) -> Result<(), String> {
    let get = |key: &str| {
        env.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let waived = get("LSADRA_REQUIRE_TLS").is_some_and(|v| v.trim().eq_ignore_ascii_case("false"));
    if !waived {
        return Ok(());
    }
    let mut hosts = vec![get("LSADRA_API_HOST").unwrap_or("")];
    if let Launch::Python { args, .. } = launch {
        for pair in args.windows(2) {
            if pair[0] == "--host" {
                hosts.push(&pair[1]);
            }
        }
        for arg in args {
            if let Some(host) = arg.strip_prefix("--host=") {
                hosts.push(host);
            }
        }
    }
    match hosts.iter().find(|h| !is_loopback(h)) {
        None => Ok(()),
        Some(host) => Err(format!(
            "refusing to start: HTTPS is only switched off for a loopback server, \
             but the server would listen on {host:?}"
        )),
    }
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
        check_tls_waiver(&self.env, &self.launch)?;
        let mut cmd = match &self.launch {
            Launch::NotConfigured => {
                return Err("no LSADRA server found; set server_dir in settings.json".into())
            }
            Launch::Bundled { program } | Launch::Installed { program } => {
                // Run from the data folder so nothing lands in whatever
                // folder the app was started from.
                let mut cmd = Command::new(program);
                if let Some(dir) = data_dir_of(&self.env, |_| None) {
                    fs::create_dir_all(&dir)
                        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
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
            server: None,
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
    fn tls_waiver_only_with_loopback() {
        let python = |args: &[&str]| Launch::Python {
            program: "python3".into(),
            dir: PathBuf::from("."),
            args: args.iter().map(|a| a.to_string()).collect(),
        };
        let serve = python(&["-m", "lsadra.serve"]);
        let uvicorn = |host: &str| python(&["-m", "uvicorn", "server:app", "--host", host]);
        let with_host = |host: &str| {
            let mut env = server_env(8000, "s", env_of(&[]));
            env.retain(|(k, _)| k != "LSADRA_API_HOST");
            env.push(("LSADRA_API_HOST".into(), host.into()));
            env
        };

        // What the app builds is always accepted, for both launch styles.
        let env = server_env(8000, "s", env_of(&[]));
        assert!(check_tls_waiver(&env, &serve).is_ok());
        assert!(check_tls_waiver(&env, &uvicorn(LOOPBACK_HOST)).is_ok());
        assert!(check_tls_waiver(&with_host("::1"), &serve).is_ok());
        assert!(check_tls_waiver(&with_host("[::1]"), &serve).is_ok());

        // Waiver plus any non-loopback bind is refused.
        for host in ["0.0.0.0", "::", "192.0.2.10", "localhost.example", ""] {
            assert!(
                check_tls_waiver(&with_host(host), &serve).is_err(),
                "env host {host:?}"
            );
        }
        assert!(check_tls_waiver(&env, &uvicorn("0.0.0.0")).is_err());
        assert!(check_tls_waiver(
            &env,
            &python(&["-m", "uvicorn", "server:app", "--host=0.0.0.0"])
        )
        .is_err());

        // Without the waiver the server's own TLS policy applies, so no check.
        let mut tls_on = with_host("0.0.0.0");
        tls_on.retain(|(k, _)| k != "LSADRA_REQUIRE_TLS");
        assert!(check_tls_waiver(&tls_on, &serve).is_ok());
    }

    #[test]
    fn start_refuses_tls_waiver_on_a_public_bind() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = temp_dir("waiver");
        let launch = Launch::Python {
            program: "python3".into(),
            dir: dir.clone(),
            args: vec![
                "-m".into(),
                "uvicorn".into(),
                "server:app".into(),
                "--host".into(),
                "0.0.0.0".into(),
            ],
        };
        let env = server_env(closed, "s", env_of(&[]));
        let server = Server::new(launch, closed, env, dir.join("server.log"));
        let err = server.start().unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        assert!(!dir.join("server.log").exists(), "nothing may be spawned");
        let _ = fs::remove_dir_all(&dir);
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
        let launch = resolve_launch(
            &settings(Some(checkout.clone())),
            Some(&exe_dir),
            find_bundled(Some(&exe_dir), None),
            None,
        );
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
    fn bundled_server_is_found_in_the_resource_folder_first() {
        let resources = temp_dir("bundled-res");
        let exe_dir = temp_dir("bundled-exe");
        assert_eq!(find_bundled(Some(&exe_dir), Some(&resources)), None);
        fs::write(exe_dir.join(BUNDLED_SERVER), "").unwrap();
        assert_eq!(
            find_bundled(Some(&exe_dir), Some(&resources)),
            Some(exe_dir.join(BUNDLED_SERVER))
        );
        let in_resources = resources.join(BUNDLED_SERVER_DIR).join(BUNDLED_SERVER);
        fs::create_dir_all(in_resources.parent().unwrap()).unwrap();
        fs::write(&in_resources, "").unwrap();
        assert_eq!(
            find_bundled(Some(&exe_dir), Some(&resources)),
            Some(in_resources.clone())
        );
        // The bundled server beats an installed one and any checkout.
        let checkout = fake_checkout("bundled-res-co", true);
        assert_eq!(
            resolve_launch(
                &settings(Some(checkout.clone())),
                Some(&exe_dir),
                Some(in_resources.clone()),
                Some(PathBuf::from("/usr/bin/lsadra-server"))
            ),
            Launch::Bundled {
                program: in_resources
            }
        );
        for dir in [resources, exe_dir, checkout] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn resolve_uses_serve_module_when_present() {
        let checkout = fake_checkout("serve", true);
        match resolve_launch(&settings(Some(checkout.clone())), None, None, None) {
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
        match resolve_launch(&settings(Some(checkout.clone())), None, None, None) {
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
        match resolve_launch(&settings(None), Some(&exe_dir), None, None) {
            Launch::Python { dir, .. } => assert_eq!(dir, checkout),
            other => panic!("unexpected {other:?}"),
        }
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn resolve_reports_not_configured() {
        let nowhere = temp_dir("nowhere");
        assert_eq!(
            resolve_launch(&settings(Some(nowhere.clone())), Some(&nowhere), None, None),
            Launch::NotConfigured
        );
        let _ = fs::remove_dir_all(&nowhere);
    }

    fn fake_installed(name: &str) -> PathBuf {
        let bin = temp_dir(name);
        let program = bin.join(BUNDLED_SERVER);
        fs::write(&program, "").unwrap();
        program
    }

    #[test]
    fn resolve_uses_installed_server_when_no_checkout() {
        let program = fake_installed("installed");
        let nowhere = temp_dir("installed-nowhere");
        assert_eq!(
            resolve_launch(&settings(None), Some(&nowhere), None, Some(program.clone())),
            Launch::Installed {
                program: program.clone()
            }
        );
        // A checkout above the executable (development) still wins over PATH.
        let checkout = fake_checkout("installed-co", true);
        assert!(matches!(
            resolve_launch(
                &settings(Some(checkout.clone())),
                None,
                None,
                Some(program.clone())
            ),
            Launch::Python { .. }
        ));
        for dir in [program.parent().unwrap().to_path_buf(), nowhere, checkout] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn server_setting_beats_checkout_and_path() {
        let program = fake_installed("server-setting");
        let checkout = fake_checkout("server-setting-co", true);
        let mut s = settings(Some(checkout.clone()));
        s.server = Some(program.clone());
        assert_eq!(
            resolve_launch(&s, None, None, Some(PathBuf::from("/elsewhere"))),
            Launch::Installed {
                program: program.clone()
            }
        );
        // A setting that points at nothing is ignored, not fatal.
        s.server = Some(checkout.join("missing"));
        assert!(matches!(
            resolve_launch(&s, None, None, None),
            Launch::Python { .. }
        ));
        let _ = fs::remove_dir_all(program.parent().unwrap());
        let _ = fs::remove_dir_all(&checkout);
    }

    #[test]
    fn installed_server_is_found_on_path_then_pipx_folder() {
        let first = temp_dir("path-a");
        let program = fake_installed("path-b");
        let second = program.parent().unwrap().to_path_buf();
        let path = std::env::join_paths([&first, &second]).unwrap();
        assert_eq!(find_installed(Some(path), None), Some(program.clone()));
        assert_eq!(find_installed(None, None), None);
        // Relative PATH entries are skipped: they depend on the current folder.
        let relative = std::env::join_paths(["."]).unwrap();
        assert_eq!(find_installed(Some(relative), None), None);

        let home = temp_dir("pipx-home");
        let pipx_bin = home.join(".local").join("bin");
        fs::create_dir_all(&pipx_bin).unwrap();
        fs::write(pipx_bin.join(BUNDLED_SERVER), "").unwrap();
        let path = std::env::join_paths([&first]).unwrap();
        assert_eq!(
            find_installed(Some(path), Some(home.clone())),
            Some(pipx_bin.join(BUNDLED_SERVER))
        );
        for dir in [first, second, home] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn packaged_servers_keep_data_in_the_user_folder() {
        let data = PathBuf::from("/users/demo/lsadra/server");
        let logs = PathBuf::from("/users/demo/lsadra/logs");
        for launch in [
            Launch::Installed {
                program: "lsadra-server".into(),
            },
            Launch::Bundled {
                program: "lsadra-server".into(),
            },
        ] {
            let env: HashMap<_, _> = data_env(&launch, &data, &logs, env_of(&[]))
                .into_iter()
                .collect();
            assert_eq!(PathBuf::from(&env["LSADRA_DATA_DIR"]), data);
            assert_eq!(PathBuf::from(&env["LSADRA_LOG_DIR"]), logs);
        }
        // A checkout keeps its own data/ folder.
        let checkout = Launch::Python {
            program: "python3".into(),
            dir: PathBuf::from("."),
            args: vec![],
        };
        assert!(data_env(&checkout, &data, &logs, env_of(&[])).is_empty());
        // A folder the user chose is inherited, not replaced.
        let installed = Launch::Installed {
            program: "lsadra-server".into(),
        };
        let env = data_env(
            &installed,
            &data,
            &logs,
            env_of(&[("LSADRA_DATA_DIR", "/srv/lsadra")]),
        );
        assert_eq!(
            env,
            vec![(
                "LSADRA_LOG_DIR".to_string(),
                logs.to_string_lossy().into_owned()
            )]
        );
        assert_eq!(
            data_dir_of(&env, env_of(&[("LSADRA_DATA_DIR", "/srv/lsadra")])),
            Some(PathBuf::from("/srv/lsadra"))
        );
        assert_eq!(data_dir_of(&[], env_of(&[])), None);
    }

    #[test]
    fn setup_token_reaches_server_and_window_only_when_safe() {
        let token = "ab".repeat(32);
        let env = setup_env(&token, env_of(&[]));
        assert_eq!(env, vec![("LSADRA_SETUP_TOKEN".to_string(), token.clone())]);
        assert_eq!(
            dashboard_path(&env, env_of(&[])),
            format!("/?setup_token={token}")
        );
        // A token the user set is kept, and the window gets that one.
        let mine = "cd".repeat(32);
        let inherited = [("LSADRA_SETUP_TOKEN", mine.as_str())];
        assert!(setup_env(&token, env_of(&inherited)).is_empty());
        assert_eq!(
            dashboard_path(&[], env_of(&inherited)),
            format!("/?setup_token={mine}")
        );
        // Anything that could change the URL is never put in it.
        let odd = [("LSADRA_SETUP_TOKEN", "x&y=1#z")];
        assert_eq!(dashboard_path(&[], env_of(&odd)), "index.html");
        assert_eq!(dashboard_path(&[], env_of(&[])), "index.html");
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
    fn installed_server_runs_in_its_data_folder() {
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = temp_dir("installed-run");
        let program = dir.join(BUNDLED_SERVER);
        fs::write(
            &program,
            "#!/bin/sh\npwd > where\necho \"$LSADRA_DATA_DIR\" >> where\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let data = dir.join("user-data");
        let mut env = server_env(closed, "s", env_of(&[]));
        let launch = Launch::Installed { program };
        env.extend(data_env(&launch, &data, &dir.join("logs"), env_of(&[])));
        let server = Server::new(launch, closed, env, dir.join("server.log"));
        server.start().unwrap();
        let written = data.join("where");
        for _ in 0..50 {
            if fs::read_to_string(&written).is_ok_and(|t| t.lines().count() == 2) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let text = fs::read_to_string(&written).expect("server ran in the data folder");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            fs::canonicalize(lines[0]).unwrap(),
            fs::canonicalize(&data).unwrap()
        );
        assert_eq!(PathBuf::from(lines[1]), data);
        server.stop();
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
