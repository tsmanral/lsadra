//! Linux journald source.
//!
//! Follows `journalctl --follow --output=json` for a short list of
//! `SYSLOG_IDENTIFIER`s (sshd, sudo, su by default) and maps the records that
//! matter for detection to event-schema v1. Using `journalctl` instead of
//! linking libsystemd keeps the agent a static binary with no C dependency.
//!
//! The journal cursor of the last spooled record is saved in the state
//! directory, so a restart resumes where the agent stopped: nothing is skipped
//! and at most the last couple of seconds are read twice.

use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use lsadra_collector_core::time::rfc3339_from_unix_micros;
use lsadra_collector_core::Event;
use regex_lite::Regex;
use serde_json::Value;

/// A journal record longer than this is skipped (journald allows huge fields).
pub const MAX_RECORD_BYTES: usize = 1 << 20;
const CURSOR_FILE: &str = "journald.cursor";
const CURSOR_SAVE_EVERY: Duration = Duration::from_secs(2);

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

fn field<'a>(rec: &'a Value, name: &str) -> Option<std::borrow::Cow<'a, str>> {
    match rec.get(name)? {
        Value::String(s) => Some(std::borrow::Cow::Borrowed(s.as_str())),
        // journald encodes non-UTF-8 fields as an array of byte values.
        Value::Array(bytes) => {
            let raw: Vec<u8> = bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect();
            Some(std::borrow::Cow::Owned(
                String::from_utf8_lossy(&raw).into_owned(),
            ))
        }
        _ => None,
    }
}

/// Map one `journalctl -o json` record to an event, or `None` if it is not
/// one the detection core uses. Pure, so it is tested on every OS.
pub fn map_record(rec: &Value) -> Option<Event> {
    let ident = field(rec, "SYSLOG_IDENTIFIER")?;
    let msg = field(rec, "MESSAGE")?;
    let micros: i64 = field(rec, "__REALTIME_TIMESTAMP")?.parse().ok()?;
    let ts = rfc3339_from_unix_micros(micros)?;
    let host = field(rec, "_HOSTNAME").unwrap_or_default();

    let base = |event_type: &str| {
        let mut e = Event::new(ts.clone(), event_type)
            .host(&host)
            .raw(&msg)
            .attr("source", "journald")
            .attr("identifier", &ident);
        if let Some(pid) = field(rec, "_PID") {
            e = e.attr("pid", &pid);
        }
        e
    };

    let event = match ident.as_ref() {
        "sshd" | "sshd-session" => map_sshd(&msg, base),
        "sudo" => map_sudo(&msg, base),
        "su" => map_su(&msg, base),
        _ => None,
    }?;
    event.validate().ok()?;
    Some(event)
}

fn map_sshd(msg: &str, base: impl Fn(&str) -> Event) -> Option<Event> {
    static AUTH: OnceLock<Regex> = OnceLock::new();
    static INVALID: OnceLock<Regex> = OnceLock::new();
    static MAXAUTH: OnceLock<Regex> = OnceLock::new();
    let auth = re(
        &AUTH,
        r"^(Failed|Accepted) (password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for (invalid user )?(\S+) from (\S+) port (\d+)",
    );
    if let Some(c) = auth.captures(msg) {
        let status = c[1].to_ascii_lowercase();
        let method = match &c[2] {
            "keyboard-interactive/pam" => "keyboard_interactive",
            "gssapi-with-mic" => "gssapi",
            m => m,
        };
        let mut e = base(&format!("ssh_{status}_{method}"))
            .username(&c[4])
            .source_ip(&c[5])
            .attr("port", &c[6])
            .attr("auth_method", method)
            .attr("severity", if status == "failed" { "HIGH" } else { "INFO" });
        if c.get(3).is_some() {
            e = e.attr("invalid_user", "true");
        }
        return Some(e);
    }
    let invalid = re(&INVALID, r"^Invalid user (\S*) from (\S+) port (\d+)");
    if let Some(c) = invalid.captures(msg) {
        return Some(
            base("ssh_invalid_user")
                .username(&c[1])
                .source_ip(&c[2])
                .attr("port", &c[3])
                .attr("severity", "HIGH"),
        );
    }
    let maxauth = re(
        &MAXAUTH,
        r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)",
    );
    if let Some(c) = maxauth.captures(msg) {
        return Some(
            base("ssh_max_auth_exceeded")
                .username(&c[1])
                .source_ip(&c[2])
                .attr("port", &c[3])
                .attr("severity", "HIGH"),
        );
    }
    None
}

/// `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls`
fn sudo_fields(rest: &str) -> Vec<(&str, &str)> {
    rest.split(" ; ")
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect()
}

fn map_sudo(msg: &str, base: impl Fn(&str) -> Event) -> Option<Event> {
    let (user, rest) = msg.split_once(" : ")?;
    let user = user.trim();
    let fields = sudo_fields(rest);
    let get = |k: &str| {
        fields
            .iter()
            .find(|(f, _)| *f == k)
            .map(|(_, v)| *v)
            .unwrap_or("")
    };
    let event_type = if rest.contains("incorrect password attempt") {
        "sudo_auth_failure"
    } else if rest.contains("user NOT in sudoers") || rest.contains("command not allowed") {
        "sudo_denied"
    } else if !get("COMMAND").is_empty() {
        "sudo_command"
    } else {
        return None;
    };
    Some(
        base(event_type)
            .username(user)
            .attr("command", get("COMMAND"))
            .attr("target_user", get("USER"))
            .attr("tty", get("TTY"))
            .attr("cwd", get("PWD"))
            .attr("severity", "HIGH"),
    )
}

fn map_su(msg: &str, base: impl Fn(&str) -> Event) -> Option<Event> {
    static FAILED: OnceLock<Regex> = OnceLock::new();
    static OPENED: OnceLock<Regex> = OnceLock::new();
    static PAMFAIL: OnceLock<Regex> = OnceLock::new();
    if let Some(c) = re(&FAILED, r"^FAILED SU \(to (\S+)\) (\S+) on (\S+)").captures(msg) {
        return Some(
            base("su_failure")
                .username(&c[2])
                .attr("target_user", &c[1])
                .attr("tty", &c[3]),
        );
    }
    if let Some(c) = re(
        &PAMFAIL,
        r"^pam_unix\(su(?:-l)?:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)",
    )
    .captures(msg)
    {
        return Some(base("su_failure").username(&c[1]).attr("target_user", &c[2]));
    }
    if let Some(c) = re(
        &OPENED,
        r"^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]*)",
    )
    .captures(msg)
    {
        return Some(
            base("su_session_opened")
                .username(&c[2])
                .attr("target_user", &c[1]),
        );
    }
    None
}

/// Read one `\n`-terminated line of at most `max` bytes. Longer lines are
/// consumed and reported as `Ok(Some(None))` so memory stays bounded.
fn read_bounded_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>, max: usize) -> io::Result<Option<bool>> {
    buf.clear();
    let mut too_long = false;
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() && !too_long {
                None
            } else {
                Some(!too_long)
            });
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !too_long {
            if buf.len() + take > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&chunk[..take]);
            }
        }
        r.consume(take);
        if done {
            return Ok(Some(!too_long));
        }
    }
}

/// Feed every mapped event from a JSON-lines stream to `sink`, and every
/// cursor to `on_cursor` once its event (if any) has been accepted.
pub fn pump<R: Read>(
    input: R,
    sink: &mut dyn FnMut(Event) -> io::Result<()>,
    on_cursor: &mut dyn FnMut(&str) -> io::Result<()>,
) -> io::Result<u64> {
    let mut reader = BufReader::with_capacity(64 * 1024, input);
    let mut buf = Vec::new();
    let mut mapped = 0;
    while let Some(fits) = read_bounded_line(&mut reader, &mut buf, MAX_RECORD_BYTES)? {
        if !fits {
            continue;
        }
        let Ok(rec) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        if let Some(ev) = map_record(&rec) {
            sink(ev)?;
            mapped += 1;
        }
        if let Some(Value::String(c)) = rec.get("__CURSOR") {
            on_cursor(c)?;
        }
    }
    Ok(mapped)
}

/// Follows the journal and resumes from the saved cursor.
pub struct JournaldSource {
    identifiers: Vec<String>,
    cursor_path: PathBuf,
}

impl JournaldSource {
    pub fn new(identifiers: Vec<String>, state_dir: &Path) -> Self {
        JournaldSource {
            identifiers,
            cursor_path: state_dir.join(CURSOR_FILE),
        }
    }

    fn saved_cursor(&self) -> Option<String> {
        let c = fs::read_to_string(&self.cursor_path).ok()?;
        let c = c.trim();
        (!c.is_empty() && c.len() < 1024 && !c.contains(char::is_control)).then(|| c.to_string())
    }

    fn save_cursor(&self, cursor: &str) -> io::Result<()> {
        let tmp = self.cursor_path.with_extension("tmp");
        fs::write(&tmp, cursor)?;
        fs::rename(&tmp, &self.cursor_path)
    }

    /// The `journalctl` arguments for this run.
    pub fn args(&self, cursor: Option<&str>) -> Vec<String> {
        let mut args: Vec<String> = ["--follow", "--output=json", "--no-pager", "--quiet"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match cursor {
            Some(c) => args.push(format!("--after-cursor={c}")),
            None => args.push("--lines=0".into()), // first start: only new records
        }
        for id in &self.identifiers {
            args.push(format!("--identifier={id}"));
        }
        args
    }

    /// Run forever, restarting `journalctl` if it exits.
    pub fn run(&self, sink: &mut dyn FnMut(Event) -> io::Result<()>) -> io::Result<()> {
        loop {
            let cursor = self.saved_cursor();
            let started = Instant::now();
            let mut child = Command::new("journalctl")
                .args(self.args(cursor.as_deref()))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let stdout = child.stdout.take().expect("piped");

            let mut last_saved = Instant::now();
            let mut pending: Option<String> = None;
            let result = pump(stdout, sink, &mut |c| {
                pending = Some(c.to_string());
                if last_saved.elapsed() >= CURSOR_SAVE_EVERY {
                    last_saved = Instant::now();
                    if let Some(c) = pending.take() {
                        self.save_cursor(&c)?;
                    }
                }
                Ok(())
            });
            if let Some(c) = pending {
                self.save_cursor(&c)?;
            }
            let _ = child.kill();
            let status = child.wait()?;
            result?;
            eprintln!("lsadra-agent: journalctl exited ({status}), restarting");
            if cursor.is_some() && !status.success() && started.elapsed() < Duration::from_secs(5) {
                // A cursor journald no longer knows (vacuumed or a new machine id).
                eprintln!("lsadra-agent: dropping saved journal cursor");
                let _ = fs::remove_file(&self.cursor_path);
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(ident: &str, msg: &str) -> Value {
        json!({
            "__CURSOR": "s=demo;i=1",
            "__REALTIME_TIMESTAMP": "1768442472123456",
            "_HOSTNAME": "demo-host-01",
            "_PID": "18402",
            "SYSLOG_IDENTIFIER": ident,
            "MESSAGE": msg,
        })
    }

    #[test]
    fn ssh_failed_password() {
        let e = map_record(&rec(
            "sshd",
            "Failed password for alice.demo from 192.0.2.45 port 51422 ssh2",
        ))
        .unwrap();
        assert_eq!(e.event_type, "ssh_failed_password");
        assert_eq!(e.timestamp, "2026-01-15T02:01:12.123456Z");
        assert_eq!(e.host.as_deref(), Some("demo-host-01"));
        assert_eq!(e.effective_username.as_deref(), Some("alice.demo"));
        assert_eq!(e.source_ip.as_deref(), Some("192.0.2.45"));
        assert_eq!(e.attributes["port"], "51422");
        assert_eq!(e.attributes["pid"], "18402");
    }

    #[test]
    fn ssh_variants() {
        let e = map_record(&rec(
            "sshd-session",
            "Failed password for invalid user admin from 2001:db8::45 port 22 ssh2",
        ))
        .unwrap();
        assert_eq!(e.event_type, "ssh_failed_password");
        assert_eq!(e.attributes["invalid_user"], "true");
        assert_eq!(e.source_ip.as_deref(), Some("2001:db8::45"));

        let e = map_record(&rec(
            "sshd",
            "Accepted publickey for bob.demo from gw.demo port 22 ssh2",
        ))
        .unwrap();
        assert_eq!(e.event_type, "ssh_accepted_publickey");
        assert_eq!(e.source_ip, None, "hostnames are not addresses");

        let e = map_record(&rec("sshd", "Invalid user oracle from 198.51.100.7 port 4242")).unwrap();
        assert_eq!(e.event_type, "ssh_invalid_user");

        assert!(map_record(&rec("sshd", "Connection closed by 192.0.2.1 port 22 [preauth]")).is_none());
    }

    #[test]
    fn sudo_and_su() {
        let e = map_record(&rec(
            "sudo",
            "alice.demo : TTY=pts/0 ; PWD=/home/alice.demo ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        ))
        .unwrap();
        assert_eq!(e.event_type, "sudo_command");
        assert_eq!(e.attributes["command"], "/usr/bin/cat /etc/shadow");
        assert_eq!(e.attributes["target_user"], "root");

        let e = map_record(&rec(
            "sudo",
            "bob.demo : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
        ))
        .unwrap();
        assert_eq!(e.event_type, "sudo_auth_failure");

        let e = map_record(&rec("su", "FAILED SU (to root) bob.demo on pts/1")).unwrap();
        assert_eq!(e.event_type, "su_failure");
        let e = map_record(&rec(
            "su",
            "pam_unix(su-l:session): session opened for user root(uid=0) by alice.demo(uid=1000)",
        ))
        .unwrap();
        assert_eq!(e.event_type, "su_session_opened");
        assert_eq!(e.effective_username.as_deref(), Some("alice.demo"));
    }

    #[test]
    fn unrelated_or_broken_records_are_skipped() {
        assert!(map_record(&rec("cron", "Failed password for x from 192.0.2.1 port 1 ssh2")).is_none());
        let mut r = rec("sshd", "Failed password for x from 192.0.2.1 port 1 ssh2");
        r["__REALTIME_TIMESTAMP"] = json!("not-a-number");
        assert!(map_record(&r).is_none());
    }

    #[test]
    fn binary_message_field() {
        let mut r = rec("sshd", "");
        let bytes: Vec<u8> = b"Failed password for alice.demo from 192.0.2.45 port 1 ssh2\xff".to_vec();
        r["MESSAGE"] = json!(bytes);
        assert_eq!(map_record(&r).unwrap().event_type, "ssh_failed_password");
    }

    #[test]
    fn pump_maps_lines_skips_garbage_and_reports_cursors() {
        let mut input = String::new();
        input.push_str(&rec("sshd", "Failed password for a.demo from 192.0.2.1 port 1 ssh2").to_string());
        input.push('\n');
        input.push_str("not json\n");
        input.push_str(&format!(
            "{{\"MESSAGE\":\"{}\"}}\n",
            "x".repeat(MAX_RECORD_BYTES + 10)
        ));
        let mut r2 = rec("sudo", "a.demo : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id");
        r2["__CURSOR"] = json!("s=demo;i=2");
        input.push_str(&r2.to_string());
        input.push('\n');

        let mut events = vec![];
        let mut cursors = vec![];
        let n = pump(
            input.as_bytes(),
            &mut |e| {
                events.push(e);
                Ok(())
            },
            &mut |c| {
                cursors.push(c.to_string());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(events[1].event_type, "sudo_command");
        assert_eq!(cursors, vec!["s=demo;i=1", "s=demo;i=2"]);
    }

    #[test]
    fn journalctl_args() {
        let dir = std::env::temp_dir();
        let s = JournaldSource::new(vec!["sshd".into(), "sudo".into()], &dir);
        let first = s.args(None);
        assert!(first.contains(&"--lines=0".to_string()));
        assert!(first.contains(&"--identifier=sudo".to_string()));
        let resumed = s.args(Some("s=abc"));
        assert!(resumed.contains(&"--after-cursor=s=abc".to_string()));
        assert!(!resumed.contains(&"--lines=0".to_string()));
    }
}
