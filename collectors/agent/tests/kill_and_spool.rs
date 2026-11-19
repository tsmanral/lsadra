//! Kill-and-spool: events taken in while the core is unreachable survive the
//! agent being killed outright, and all of them reach the core exactly once
//! after a restart.
//!
//! Runs the real binary with `--source stdin`, a key file, and a tiny HTTP
//! server standing in for the core.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const N: usize = 300;

fn event(i: usize) -> String {
    format!(
        "{{\"schema_version\":\"1\",\"timestamp\":\"2026-01-15T02:01:12Z\",\"event_type\":\"ssh_failed_password\",\
         \"source_ip\":\"192.0.2.45\",\"raw_message\":\"line {i}\"}}"
    )
}

fn spooled_lines(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "seg"))
        .map(|e| {
            std::fs::read_to_string(e.path())
                .unwrap_or_default()
                .lines()
                .count()
        })
        .sum()
}

fn write_config(dir: &Path, port: u16) -> std::path::PathBuf {
    let cfg = dir.join("agent.toml");
    let state = dir.join("state");
    let key = dir.join("device.key");
    std::fs::write(
        &cfg,
        format!(
            "server_url = \"http://127.0.0.1:{port}\"\ndevice_id = \"dev-kill.demo\"\n\
             state_dir = {state:?}\nkey_file = {key:?}\nflush_interval_secs = 1\n"
        ),
    )
    .unwrap();
    cfg
}

fn agent() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lsadra-agent"));
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        c.env_remove(var);
    }
    c
}

/// A one-request-per-connection HTTP server that records every event it is sent.
fn fake_core(listener: TcpListener, seen: Arc<Mutex<Vec<Value>>>, headers: Arc<Mutex<Vec<String>>>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let seen = seen.clone();
        let headers = headers.clone();
        thread::spawn(move || handle(&mut stream, &seen, &headers));
    }
}

fn handle(stream: &mut TcpStream, seen: &Mutex<Vec<Value>>, headers: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let l = line.trim_end().to_string();
        if l.is_empty() {
            break;
        }
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
        headers.lock().unwrap().push(l);
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).unwrap();
    let batch: Value = serde_json::from_slice(&body).unwrap();
    let events = batch["events"].as_array().unwrap().clone();
    assert!(events.len() <= 100, "batch over the core's limit");
    let n = events.len();
    seen.lock().unwrap().extend(events);
    let reply = format!("{{\"accepted\":{n}}}");
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
}

#[test]
fn events_survive_a_kill_and_ship_once_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    // Reserve a port, then free it: phase 1 talks to a core that is down.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = write_config(dir.path(), port);

    let mut set_key = agent()
        .args(["set-key", "--config"])
        .arg(&cfg)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    set_key.stdin.take().unwrap().write_all(b"k3y-demo\n").unwrap();
    assert!(set_key.wait().unwrap().success());

    // Phase 1: feed N events, wait until they are on disk, then kill -9.
    let mut child = agent()
        .args(["run", "--source", "stdin", "--config"])
        .arg(&cfg)
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for i in 0..N {
        writeln!(stdin, "{}", event(i)).unwrap();
    }
    writeln!(stdin, "{{\"not\":\"an event\"}}").unwrap();
    stdin.flush().unwrap();
    let spool_dir = dir.path().join("state").join("spool");
    let deadline = Instant::now() + Duration::from_secs(30);
    while spooled_lines(&spool_dir) < N {
        assert!(Instant::now() < deadline, "events never reached the spool");
        thread::sleep(Duration::from_millis(50));
    }
    child.kill().unwrap(); // SIGKILL / TerminateProcess: no chance to clean up
    child.wait().unwrap();
    drop(stdin);
    assert_eq!(spooled_lines(&spool_dir), N, "the invalid line was never spooled");

    // Phase 2: the core is back. A fresh agent with no new input drains the spool.
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let headers = Arc::new(Mutex::new(Vec::new()));
    {
        let (seen, headers) = (seen.clone(), headers.clone());
        thread::spawn(move || fake_core(listener, seen, headers));
    }
    let status = agent()
        .args(["run", "--source", "stdin", "--config"])
        .arg(&cfg)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let seen = seen.lock().unwrap();
    let mut lines: Vec<usize> = seen
        .iter()
        .map(|e| {
            e["raw_message"]
                .as_str()
                .unwrap()
                .trim_start_matches("line ")
                .parse()
                .unwrap()
        })
        .collect();
    lines.sort_unstable();
    assert_eq!(lines, (0..N).collect::<Vec<_>>(), "every event exactly once");
    for e in seen.iter() {
        assert!(
            e.get("device_id").is_none(),
            "identity travels in headers, not events"
        );
    }
    let headers = headers.lock().unwrap();
    assert!(headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-device-id: dev-kill.demo")));
    assert!(headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-api-key: k3y-demo")));
}
