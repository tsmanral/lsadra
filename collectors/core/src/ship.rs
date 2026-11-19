//! Ships spooled events to `POST /api/events/batch`.
//!
//! The spool is only acked after the core answers for the batch:
//! - 2xx: delivered, ack.
//! - 422: the core rejected the batch whole. Events are validated before they
//!   are spooled, so this should not happen; if it does, the batch is halved
//!   until the bad event is alone, and only that one event is dropped.
//! - 429 / 503: wait for `Retry-After`, then resend.
//! - 401 / 403: the device key is wrong or revoked; keep the events and retry
//!   slowly, so nothing is lost while an operator re-enrolls the device.
//! - anything else (network down, 5xx): exponential backoff up to 5 minutes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::event::{Event, MAX_EVENTS_PER_BATCH};
use crate::spool::Spool;

pub const MAX_BACKOFF: Duration = Duration::from_secs(300);
const AUTH_RETRY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Rejected(String),
    RetryAfter(Duration),
    AuthFailed(u16),
    Failed(String),
}

pub trait Transport {
    fn post(&self, body: &[u8]) -> Outcome;
}

/// HTTPS transport (rustls). Device credentials go in headers, never the body.
#[cfg(feature = "http")]
pub struct HttpTransport {
    agent: ureq::Agent,
    url: String,
    device_id: String,
    api_key: String,
}

#[cfg(feature = "http")]
impl HttpTransport {
    pub fn new(
        url: String,
        device_id: String,
        api_key: String,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, String> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .user_agent(concat!("lsadra-agent/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = ca_pem {
            let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                return Err("ca_file holds no PEM certificate".into());
            }
            builder = builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            );
        }
        Ok(HttpTransport {
            agent: builder.build().into(),
            url,
            device_id,
            api_key,
        })
    }
}

#[cfg(any(feature = "http", test))]
fn retry_after(value: Option<&str>) -> Duration {
    let secs = value.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(5);
    Duration::from_secs(secs.clamp(1, MAX_BACKOFF.as_secs()))
}

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn post(&self, body: &[u8]) -> Outcome {
        let resp = self
            .agent
            .post(&self.url)
            .header("X-Device-Id", &self.device_id)
            .header("X-API-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .send(body);
        let resp = match resp {
            Ok(r) => r,
            Err(e) => return Outcome::Failed(e.to_string()),
        };
        let status = resp.status().as_u16();
        match status {
            200..=299 => Outcome::Accepted,
            422 => {
                use std::io::Read;
                let mut text = String::new();
                let _ = resp.into_body().into_reader().take(500).read_to_string(&mut text);
                Outcome::Rejected(text)
            }
            429 | 503 => Outcome::RetryAfter(retry_after(
                resp.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            )),
            401 | 403 => Outcome::AuthFailed(status),
            s => Outcome::Failed(format!("HTTP {s}")),
        }
    }
}

/// What one shipping step did, and how long to wait before the next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing pending.
    Idle,
    /// Delivered `n` events (or dropped them as invalid); `full` if the batch was full.
    Sent { n: usize, full: bool },
    /// Keep the batch and wait this long.
    Wait(Duration),
    /// The batch was rejected; it will be retried in smaller pieces at once.
    Split,
}

pub struct Shipper<T: Transport> {
    spool: Arc<Spool>,
    transport: T,
    batch_size: usize,
    limit: usize,
    backoff: Duration,
    pub dropped_invalid: u64,
}

impl<T: Transport> Shipper<T> {
    pub fn new(spool: Arc<Spool>, transport: T, batch_size: usize) -> Self {
        let batch_size = batch_size.clamp(1, MAX_EVENTS_PER_BATCH);
        Shipper {
            spool,
            transport,
            batch_size,
            limit: batch_size,
            backoff: Duration::from_secs(2),
            dropped_invalid: 0,
        }
    }

    pub fn step(&mut self) -> std::io::Result<Step> {
        let batch = self.spool.peek(self.limit)?;
        let Some(next) = batch.next else {
            return Ok(Step::Idle);
        };
        let read = batch.lines.len();

        // Re-check what comes off disk: a corrupted line must not cost a batch.
        let mut valid = Vec::with_capacity(read);
        for line in batch.lines {
            match serde_json::from_str::<Event>(&line)
                .map_err(|e| e.to_string())
                .and_then(|e| e.validate().map_err(|e| e.to_string()))
            {
                Ok(()) => valid.push(line),
                Err(e) => {
                    self.dropped_invalid += 1;
                    eprintln!("lsadra-agent: dropping invalid spooled event: {e}");
                }
            }
        }
        if valid.is_empty() {
            self.spool.ack(next)?;
            return Ok(Step::Sent {
                n: read,
                full: read >= self.batch_size,
            });
        }

        let mut body = Vec::with_capacity(valid.iter().map(|l| l.len() + 1).sum::<usize>() + 12);
        body.extend_from_slice(b"{\"events\":[");
        for (i, line) in valid.iter().enumerate() {
            if i > 0 {
                body.push(b',');
            }
            body.extend_from_slice(line.as_bytes());
        }
        body.extend_from_slice(b"]}");

        match self.transport.post(&body) {
            Outcome::Accepted => {
                self.spool.ack(next)?;
                self.backoff = Duration::from_secs(2);
                let full = read >= self.limit;
                self.limit = self.batch_size;
                Ok(Step::Sent { n: read, full })
            }
            Outcome::Rejected(why) => {
                if valid.len() > 1 {
                    self.limit = (read / 2).max(1);
                    Ok(Step::Split)
                } else {
                    eprintln!("lsadra-agent: core rejected an event (422), dropping it: {why}");
                    self.dropped_invalid += 1;
                    self.spool.ack(next)?;
                    self.limit = self.batch_size;
                    Ok(Step::Sent { n: read, full: false })
                }
            }
            Outcome::RetryAfter(d) => Ok(Step::Wait(d)),
            Outcome::AuthFailed(code) => {
                eprintln!("lsadra-agent: core refused the device key (HTTP {code}); keeping events, re-enroll the device");
                Ok(Step::Wait(AUTH_RETRY.max(self.backoff)))
            }
            Outcome::Failed(why) => {
                let wait = self.backoff;
                eprintln!(
                    "lsadra-agent: send failed ({why}), retrying in {}s",
                    wait.as_secs()
                );
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                Ok(Step::Wait(wait))
            }
        }
    }

    /// Ship until `stop` is set. Partial batches go out every `flush_interval`.
    pub fn run(&mut self, flush_interval: Duration, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            let wait = match self.step() {
                Ok(Step::Sent { full: true, .. }) | Ok(Step::Split) => continue,
                Ok(Step::Sent { .. }) | Ok(Step::Idle) => flush_interval,
                Ok(Step::Wait(d)) => d,
                Err(e) => {
                    eprintln!("lsadra-agent: spool error: {e}");
                    flush_interval
                }
            };
            sleep_unless(stop, wait);
        }
    }
}

/// Sleep in short slices so a stop request is noticed quickly.
pub fn sleep_unless(stop: &AtomicBool, total: Duration) {
    let slice = Duration::from_millis(200);
    let mut left = total;
    while !left.is_zero() && !stop.load(Ordering::Relaxed) {
        let d = left.min(slice);
        std::thread::sleep(d);
        left -= d;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        script: RefCell<Vec<Outcome>>,
        bodies: RefCell<Vec<serde_json::Value>>,
        reject_marker: Option<&'static str>,
    }

    impl Transport for Fake {
        fn post(&self, body: &[u8]) -> Outcome {
            let v: serde_json::Value = serde_json::from_slice(body).expect("body is JSON");
            self.bodies.borrow_mut().push(v);
            if let Some(m) = self.reject_marker {
                if String::from_utf8_lossy(body).contains(m) {
                    return Outcome::Rejected("{}".into());
                }
            }
            let mut s = self.script.borrow_mut();
            if s.is_empty() {
                Outcome::Accepted
            } else {
                s.remove(0)
            }
        }
    }

    fn fake(script: Vec<Outcome>, reject_marker: Option<&'static str>) -> Fake {
        Fake {
            script: RefCell::new(script),
            bodies: RefCell::new(vec![]),
            reject_marker,
        }
    }

    fn spool_with(n: usize) -> (tempfile::TempDir, Arc<Spool>) {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::open(dir.path(), 1 << 22, 1 << 16).unwrap());
        for i in 0..n {
            let e = Event::new("2026-01-15T02:01:12Z", "ssh_failed_password").raw(&format!("line {i}"));
            spool.append(&e.to_json()).unwrap();
        }
        (dir, spool)
    }

    #[test]
    fn delivers_in_batches_and_acks() {
        let (_d, spool) = spool_with(250);
        let mut s = Shipper::new(spool.clone(), fake(vec![], None), 100);
        assert_eq!(s.step().unwrap(), Step::Sent { n: 100, full: true });
        assert_eq!(s.step().unwrap(), Step::Sent { n: 100, full: true });
        assert_eq!(s.step().unwrap(), Step::Sent { n: 50, full: false });
        assert_eq!(s.step().unwrap(), Step::Idle);
        let first = &s.transport.bodies.borrow()[0];
        assert_eq!(first["events"].as_array().unwrap().len(), 100);
        assert_eq!(spool.stats().pending_bytes, 0);
    }

    #[test]
    fn outage_keeps_events_and_backs_off() {
        let (_d, spool) = spool_with(5);
        let mut s = Shipper::new(
            spool.clone(),
            fake(
                vec![
                    Outcome::Failed("down".into()),
                    Outcome::Failed("down".into()),
                    Outcome::RetryAfter(Duration::from_secs(7)),
                ],
                None,
            ),
            100,
        );
        assert_eq!(s.step().unwrap(), Step::Wait(Duration::from_secs(2)));
        assert_eq!(s.step().unwrap(), Step::Wait(Duration::from_secs(4)));
        assert_eq!(s.step().unwrap(), Step::Wait(Duration::from_secs(7)));
        assert!(
            spool.stats().pending_bytes > 0,
            "nothing acked while the core is away"
        );
        assert_eq!(s.step().unwrap(), Step::Sent { n: 5, full: false });
    }

    #[test]
    fn one_rejected_event_is_isolated_and_dropped_alone() {
        let (_d, spool) = spool_with(10);
        // The core rejects any batch holding "line 6".
        let mut s = Shipper::new(spool.clone(), fake(vec![], Some("\"line 6\"")), 100);
        let mut delivered = 0;
        for _ in 0..50 {
            match s.step().unwrap() {
                Step::Idle => break,
                Step::Sent { n, .. } => delivered += n,
                _ => {}
            }
        }
        assert_eq!(delivered, 10, "every line accounted for");
        assert_eq!(s.dropped_invalid, 1, "only the bad event dropped");
        let shipped: usize = s
            .transport
            .bodies
            .borrow()
            .iter()
            .filter(|b| !b.to_string().contains("\"line 6\""))
            .map(|b| b["events"].as_array().unwrap().len())
            .sum();
        assert_eq!(shipped, 9);
    }

    #[test]
    fn auth_failure_keeps_events() {
        let (_d, spool) = spool_with(3);
        let mut s = Shipper::new(spool.clone(), fake(vec![Outcome::AuthFailed(401)], None), 100);
        assert!(matches!(s.step().unwrap(), Step::Wait(_)));
        assert_eq!(s.step().unwrap(), Step::Sent { n: 3, full: false });
    }

    #[test]
    fn retry_after_parsing() {
        assert_eq!(retry_after(Some("7")), Duration::from_secs(7));
        assert_eq!(retry_after(Some("99999")), MAX_BACKOFF);
        assert_eq!(
            retry_after(Some("Wed, 21 Oct 2015 07:28:00 GMT")),
            Duration::from_secs(5)
        );
        assert_eq!(retry_after(None), Duration::from_secs(5));
    }
}
