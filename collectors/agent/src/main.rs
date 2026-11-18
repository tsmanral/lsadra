//! `lsadra-agent`: reads this host's security log, checks each event against
//! event-schema v1, spools it to disk and ships it to the LSADRA core.
//!
//! ```text
//! lsadra-agent run     --config <file> [--source auto|journald|wineventlog|stdin]
//! lsadra-agent set-key --config <file>      # reads the device key from stdin
//! lsadra-agent check   --config <file>
//! lsadra-agent --version
//! ```
//!
//! The process is crash-safe by design: events are on disk before the source
//! position (journal cursor, event-log bookmark) moves, and the spool is only
//! acked after the core answers. Stopping it with SIGTERM/SIGKILL or a service
//! stop loses nothing, so it has no shutdown handler.

use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lsadra_collector_core::config::Config;
use lsadra_collector_core::keystore::{self, FileKeyStore, KeyStore};
use lsadra_collector_core::ship::{sleep_unless, HttpTransport, Shipper};
use lsadra_collector_core::spool::Spool;
use lsadra_collector_core::Event;

const SEGMENT_BYTES: u64 = 1024 * 1024;
/// A stdin line longer than this is skipped (the contract caps an event far below it).
const MAX_STDIN_LINE: u64 = 64 * 1024;

fn usage() -> ExitCode {
    eprintln!(
        "usage: lsadra-agent run --config <file> [--source auto|journald|wineventlog|stdin]\n\
         \x20      lsadra-agent set-key --config <file>   (key on stdin)\n\
         \x20      lsadra-agent check --config <file>\n\
         \x20      lsadra-agent --version"
    );
    ExitCode::from(2)
}

struct Args {
    command: String,
    config: Option<PathBuf>,
    source: String,
}

fn parse_args() -> Option<Args> {
    let mut it = std::env::args().skip(1);
    let command = it.next()?;
    let mut args = Args {
        command,
        config: None,
        source: "auto".into(),
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => args.config = Some(PathBuf::from(it.next()?)),
            "--source" => args.source = it.next()?,
            _ => return None,
        }
    }
    Some(args)
}

fn key_store(cfg: &Config) -> Box<dyn KeyStore> {
    match &cfg.key_file {
        Some(path) => Box::new(FileKeyStore::new(path.clone())),
        None => keystore::platform_store(&cfg.device_id, &cfg.state_dir),
    }
}

fn main() -> ExitCode {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!("lsadra-agent {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let Some(args) = parse_args() else {
        return usage();
    };
    let Some(config_path) = args.config.clone() else {
        return usage();
    };
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("lsadra-agent: bad config: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match args.command.as_str() {
        "run" => run(&cfg, &args.source),
        "set-key" => set_key(&cfg),
        "check" => check(&cfg),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lsadra-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn set_key(cfg: &Config) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().take(1024).read_line(&mut line)?;
    let store = key_store(cfg);
    store.set(line.trim())?;
    eprintln!("lsadra-agent: device key saved to {}", store.describe());
    Ok(())
}

fn check(cfg: &Config) -> io::Result<()> {
    let store = key_store(cfg);
    store
        .get()
        .map_err(|e| io::Error::new(e.kind(), format!("device key ({}): {e}", store.describe())))?;
    println!(
        "config ok; device {}; key in {}; source {}",
        cfg.device_id,
        store.describe(),
        default_source()
    );
    Ok(())
}

fn default_source() -> &'static str {
    if cfg!(windows) {
        "wineventlog"
    } else if cfg!(target_os = "linux") {
        "journald"
    } else {
        "none"
    }
}

fn run(cfg: &Config, source: &str) -> io::Result<()> {
    let api_key = key_store(cfg).get().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("no device key ({e}); run `lsadra-agent set-key` first"),
        )
    })?;
    let ca = match &cfg.ca_file {
        Some(p) => Some(std::fs::read(p)?),
        None => None,
    };
    let transport = HttpTransport::new(cfg.batch_url(), cfg.device_id.clone(), api_key, ca.as_deref())
        .map_err(io::Error::other)?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    let spool = Arc::new(Spool::open(
        cfg.state_dir.join("spool"),
        cfg.spool_max_bytes,
        SEGMENT_BYTES,
    )?);

    let stop = Arc::new(AtomicBool::new(false));
    let flush = Duration::from_secs(cfg.flush_interval_secs);
    let shipper = {
        let (spool, stop) = (spool.clone(), stop.clone());
        let batch_size = cfg.batch_size;
        std::thread::Builder::new()
            .name("shipper".into())
            .spawn(move || {
                Shipper::new(spool, transport, batch_size).run(flush, &stop);
            })?
    };

    let mut rejected = 0u64;
    let mut sink = |e: Event| -> io::Result<()> {
        match e.validate() {
            Ok(()) => spool.append(&e.to_json()),
            Err(err) => {
                rejected += 1;
                eprintln!("lsadra-agent: not spooling an event that breaks the contract ({err})");
                Ok(())
            }
        }
    };

    let source = if source == "auto" {
        default_source()
    } else {
        source
    };
    eprintln!(
        "lsadra-agent {} shipping {} to {}",
        env!("CARGO_PKG_VERSION"),
        source,
        cfg.server_url
    );
    match source {
        "stdin" => {
            read_stdin(&mut sink)?;
            // Input is finished: drain the spool, then exit.
            let deadline = Instant::now() + Duration::from_secs(300);
            while spool.stats().pending_bytes > 0 && Instant::now() < deadline {
                sleep_unless(&stop, Duration::from_millis(200));
            }
        }
        #[cfg(not(windows))]
        "journald" => {
            lsadra_source_journald::JournaldSource::new(cfg.journald.identifiers.clone(), &cfg.state_dir)
                .run(&mut sink)?;
        }
        #[cfg(windows)]
        "wineventlog" => {
            lsadra_source_wineventlog::WinEventLogSource::new(cfg.wineventlog.query.clone(), &cfg.state_dir)
                .run(&mut sink)?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("source `{other}` is not available on this OS"),
            ))
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = shipper.join();
    let pending = spool.stats().pending_bytes;
    if pending > 0 {
        eprintln!("lsadra-agent: exiting with {pending} bytes still spooled; they ship on the next start");
    }
    Ok(())
}

/// One schema v1 event per line, for testing and for piping other tools in.
fn read_stdin(sink: &mut dyn FnMut(Event) -> io::Result<()>) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader).take(MAX_STDIN_LINE).read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') && n as u64 == MAX_STDIN_LINE {
            // Over-long line: skip the rest of it without holding it in memory.
            let mut rest = Vec::new();
            loop {
                rest.clear();
                let m = (&mut reader).take(MAX_STDIN_LINE).read_until(b'\n', &mut rest)?;
                if m == 0 || rest.ends_with(b"\n") {
                    break;
                }
            }
            eprintln!("lsadra-agent: skipping an over-long input line");
            continue;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        match lsadra_collector_core::event::parse_event(text) {
            Ok(e) => sink(e)?,
            Err(e) => eprintln!("lsadra-agent: skipping a line that is not a v1 event: {e}"),
        }
    }
}
