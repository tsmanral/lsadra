//! The normalized event, event-schema v1 (`docs/contracts/event-schema.v1.json`).
//!
//! ADR 0006 freezes v1 and makes the core reject any batch that holds one
//! invalid event (HTTP 422). Collectors therefore check every event here,
//! before it is spooled, so a bad record is dropped alone instead of costing a
//! whole batch. The bounds below mirror the schema file; `tests/contract.rs`
//! fails if they drift from it.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The only `schema_version` the core accepts.
pub const SCHEMA_VERSION: &str = "1";
pub const MAX_HOST: usize = 255;
pub const MAX_USERNAME: usize = 128;
pub const MAX_SOURCE_IP: usize = 45;
pub const MAX_EVENT_TYPE: usize = 64;
pub const MAX_RAW_MESSAGE: usize = 4096;
pub const MAX_ATTRIBUTES: usize = 32;
/// `x-lsadra-maxValueLength`: strings by characters, other values as compact JSON.
pub const MAX_ATTRIBUTE_VALUE: usize = 1024;
/// `x-lsadra-maxSerializedBytes`: the whole `attributes` object as compact UTF-8 JSON.
pub const MAX_ATTRIBUTES_BYTES: usize = 8192;
/// The core takes at most this many events per batch (`MAX_EVENTS_PER_BATCH`).
pub const MAX_EVENTS_PER_BATCH: usize = 100;

/// The schema's `timestamp.pattern`, verbatim. RFC 3339 with a mandatory offset.
pub const TIMESTAMP_PATTERN: &str = r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$";

fn timestamp_re() -> &'static regex_lite::Regex {
    static RE: OnceLock<regex_lite::Regex> = OnceLock::new();
    RE.get_or_init(|| regex_lite::Regex::new(TIMESTAMP_PATTERN).expect("valid pattern"))
}

/// One normalized event. `device_id` and `user_id` are deliberately absent:
/// the core assigns both from the authenticated device and rejects an event
/// that carries either.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: String,
    pub timestamp: String,
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_message: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
}

/// Why an event breaks the contract. The field name matches the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub field: &'static str,
    pub reason: String,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ContractError {}

fn err(field: &'static str, reason: impl Into<String>) -> ContractError {
    ContractError {
        field,
        reason: reason.into(),
    }
}

/// Cut `s` to at most `max` characters (never splits a character).
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// The canonical text form of an IP literal, or `None` for anything else
/// (hostnames, `-`, zone-indexed IPv6). The contract takes only addresses.
pub fn ip_or_none(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.len() > MAX_SOURCE_IP || v.contains('%') {
        return None;
    }
    v.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

impl Event {
    /// A new event with the required fields. `event_type` is cut to its bound.
    pub fn new(timestamp: impl Into<String>, event_type: &str) -> Self {
        Event {
            schema_version: SCHEMA_VERSION.to_string(),
            timestamp: timestamp.into(),
            event_type: truncate_chars(event_type, MAX_EVENT_TYPE),
            host: None,
            effective_username: None,
            source_ip: None,
            raw_message: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn host(mut self, host: &str) -> Self {
        if !host.is_empty() {
            self.host = Some(truncate_chars(host, MAX_HOST));
        }
        self
    }

    pub fn username(mut self, user: &str) -> Self {
        if !user.is_empty() {
            self.effective_username = Some(truncate_chars(user, MAX_USERNAME));
        }
        self
    }

    /// Sets `source_ip` only when `ip` is an address literal.
    pub fn source_ip(mut self, ip: &str) -> Self {
        self.source_ip = ip_or_none(ip);
        self
    }

    pub fn raw(mut self, raw: &str) -> Self {
        self.raw_message = Some(truncate_chars(raw, MAX_RAW_MESSAGE));
        self
    }

    /// Adds a string attribute, cut to its bound. Empty values and keys past
    /// the 32-key limit are skipped rather than failing the event.
    pub fn attr(mut self, key: &str, value: &str) -> Self {
        if !value.is_empty() && (self.attributes.len() < MAX_ATTRIBUTES || self.attributes.contains_key(key))
        {
            self.attributes.insert(
                key.to_string(),
                Value::String(truncate_chars(value, MAX_ATTRIBUTE_VALUE)),
            );
        }
        self
    }

    /// Check every rule the core enforces at `POST /api/events/batch`.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(err("schema_version", "must be \"1\""));
        }
        validate_timestamp(&self.timestamp)?;
        bounded("event_type", &self.event_type, MAX_EVENT_TYPE)?;
        if let Some(h) = &self.host {
            bounded("host", h, MAX_HOST)?;
        }
        if let Some(u) = &self.effective_username {
            bounded("effective_username", u, MAX_USERNAME)?;
        }
        if let Some(ip) = &self.source_ip {
            if ip.len() > MAX_SOURCE_IP || ip.contains('%') || ip.parse::<IpAddr>().is_err() {
                return Err(err("source_ip", "not an IPv4 or IPv6 address"));
            }
        }
        if let Some(r) = &self.raw_message {
            bounded("raw_message", r, MAX_RAW_MESSAGE)?;
        }
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(err("attributes", format!("more than {MAX_ATTRIBUTES} keys")));
        }
        for v in self.attributes.values() {
            let len = match v {
                Value::String(s) => s.chars().count(),
                other => serde_json::to_string(other)
                    .map(|s| s.chars().count())
                    .unwrap_or(usize::MAX),
            };
            if len > MAX_ATTRIBUTE_VALUE {
                return Err(err(
                    "attributes",
                    format!("a value is over {MAX_ATTRIBUTE_VALUE} characters"),
                ));
            }
        }
        if !self.attributes.is_empty() {
            let bytes = serde_json::to_vec(&self.attributes)
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
            if bytes > MAX_ATTRIBUTES_BYTES {
                return Err(err(
                    "attributes",
                    format!("over {MAX_ATTRIBUTES_BYTES} bytes as JSON"),
                ));
            }
        }
        Ok(())
    }

    /// Compact JSON for the spool and the wire.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("event serializes")
    }
}

/// Parse one JSON event and check it against the contract.
pub fn parse_event(text: &str) -> Result<Event, String> {
    let e: Event = serde_json::from_str(text).map_err(|e| e.to_string())?;
    e.validate().map_err(|e| e.to_string())?;
    Ok(e)
}

fn bounded(field: &'static str, value: &str, max: usize) -> Result<(), ContractError> {
    if value.chars().count() > max {
        return Err(err(field, format!("longer than {max} characters")));
    }
    Ok(())
}

/// The schema pattern, plus a real-calendar check: the core parses the value
/// as a date-time, so `2026-02-30T…` passes the pattern but is still a 422.
pub fn validate_timestamp(ts: &str) -> Result<(), ContractError> {
    if !timestamp_re().is_match(ts) {
        return Err(err("timestamp", "not RFC 3339 with an offset"));
    }
    let year: i64 = ts[0..4].parse().map_err(|_| err("timestamp", "bad year"))?;
    let month: u32 = ts[5..7].parse().map_err(|_| err("timestamp", "bad month"))?;
    let day: u32 = ts[8..10].parse().map_err(|_| err("timestamp", "bad day"))?;
    if year < 1 || day > crate::time::days_in_month(year, month) {
        return Err(err("timestamp", "no such calendar date"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_event() -> Event {
        Event::new("2026-01-15T02:01:12Z", "ssh_failed_password")
            .host("demo-host-01")
            .username("alice.demo")
            .source_ip("192.0.2.45")
            .raw("Failed password for alice.demo")
            .attr("port", "51422")
    }

    #[test]
    fn a_built_event_is_valid() {
        ok_event().validate().unwrap();
    }

    #[test]
    fn builders_cut_to_bounds() {
        let e = Event::new("2026-01-15T02:01:12Z", &"t".repeat(100))
            .host(&"h".repeat(300))
            .username(&"ü".repeat(200))
            .raw(&"r".repeat(5000))
            .attr("k", &"v".repeat(2000));
        e.validate().unwrap();
        assert_eq!(e.effective_username.unwrap().chars().count(), MAX_USERNAME);
    }

    #[test]
    fn non_ip_source_is_dropped() {
        for bad in ["gw.demo", "-", "", "fe80::1%eth0", "01.2.3.4"] {
            assert_eq!(ok_event().source_ip(bad).source_ip, None, "{bad}");
        }
        assert_eq!(
            ok_event().source_ip("2001:DB8::45").source_ip.as_deref(),
            Some("2001:db8::45")
        );
    }

    #[test]
    fn timestamps() {
        for good in [
            "2026-01-15T02:01:12Z",
            "2026-01-15t02:01:12.1234567+05:30",
            "2024-02-29T00:00:00-00:00",
        ] {
            validate_timestamp(good).unwrap();
        }
        for bad in [
            "2026-01-15T02:01:12",
            "2026-01-15 02:01:12Z",
            "2026-01-15",
            "1700000000",
            "2026-01-15T23:59:60Z",
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z",
        ] {
            assert!(validate_timestamp(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn device_identity_is_rejected_on_parse() {
        let with_device =
            r#"{"schema_version":"1","timestamp":"2026-01-15T02:01:12Z","event_type":"x","device_id":"d"}"#;
        assert!(serde_json::from_str::<Event>(with_device).is_err());
    }

    #[test]
    fn attribute_limits() {
        let mut e = ok_event();
        for i in 0..40 {
            e = e.attr(&format!("k{i}"), "v");
        }
        assert_eq!(e.attributes.len(), MAX_ATTRIBUTES);
        e.validate().unwrap();

        let mut big = ok_event();
        for i in 0..9 {
            big.attributes
                .insert(format!("k{i}"), Value::String("x".repeat(1000)));
        }
        assert_eq!(big.validate().unwrap_err().field, "attributes");

        let mut nested = ok_event();
        nested
            .attributes
            .insert("n".into(), serde_json::json!(["x".repeat(1100)]));
        assert!(nested.validate().is_err());
    }
}
