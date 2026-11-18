//! The Rust side of the event contract (ADR 0006): the collectors' bounds and
//! timestamp rule must equal `docs/contracts/event-schema.v1.json`, every event
//! the sources emit must validate against that file with format assertion on,
//! and the in-agent check must reject what the schema rejects.

use std::path::PathBuf;

use lsadra_collector_core::event::{self, Event};
use serde_json::{json, Value};

fn schema() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/event-schema.v1.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("schema file")).expect("schema JSON")
}

fn validator() -> jsonschema::Validator {
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema())
        .expect("schema compiles")
}

#[test]
fn bounds_match_the_schema_file() {
    let s = schema();
    let p = &s["properties"];
    assert_eq!(p["timestamp"]["pattern"], event::TIMESTAMP_PATTERN);
    assert_eq!(p["schema_version"]["const"], event::SCHEMA_VERSION);
    assert_eq!(p["host"]["maxLength"], event::MAX_HOST);
    assert_eq!(p["effective_username"]["maxLength"], event::MAX_USERNAME);
    assert_eq!(p["event_type"]["maxLength"], event::MAX_EVENT_TYPE);
    assert_eq!(p["raw_message"]["maxLength"], event::MAX_RAW_MESSAGE);
    assert_eq!(p["source_ip"]["anyOf"][0]["maxLength"], event::MAX_SOURCE_IP);
    assert_eq!(p["attributes"]["maxProperties"], event::MAX_ATTRIBUTES);
    assert_eq!(
        p["attributes"]["x-lsadra-maxValueLength"],
        event::MAX_ATTRIBUTE_VALUE
    );
    assert_eq!(
        p["attributes"]["x-lsadra-maxSerializedBytes"],
        event::MAX_ATTRIBUTES_BYTES
    );
    let required: Vec<&str> = s["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(required, ["schema_version", "timestamp", "event_type"]);
}

fn source_events() -> Vec<Event> {
    let rec = |ident: &str, msg: &str| {
        json!({"__REALTIME_TIMESTAMP": "1768442472123456", "_HOSTNAME": "demo-host-01", "_PID": "7",
               "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg})
    };
    let mut out: Vec<Event> = [
        rec(
            "sshd",
            "Failed password for alice.demo from 192.0.2.45 port 51422 ssh2",
        ),
        rec(
            "sshd",
            "Accepted publickey for alice.demo from 2001:db8::45 port 22 ssh2",
        ),
        rec(
            "sshd",
            "Failed password for invalid user x from gw.demo port 22 ssh2",
        ),
        rec(
            "sudo",
            &format!(
                "alice.demo : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/{}",
                "x".repeat(5000)
            ),
        ),
        rec("su", "FAILED SU (to root) bob.demo on pts/1"),
    ]
    .iter()
    .map(|r| lsadra_source_journald::map_record(r).expect("mapped"))
    .collect();

    let win = |id: u32, channel: &str, data: &str| {
        format!(
            "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System>\
             <EventID>{id}</EventID><TimeCreated SystemTime=\"2026-01-15T02:01:12.1234567Z\"/>\
             <EventRecordID>1</EventRecordID><Channel>{channel}</Channel><Computer>demo-host-07</Computer>\
             </System><EventData>{data}</EventData></Event>"
        )
    };
    for xml in [
        win(4625, "Security", "<Data Name=\"TargetUserName\">alice.demo</Data><Data Name=\"IpAddress\">198.51.100.7</Data><Data Name=\"LogonType\">3</Data>"),
        win(4688, "Security", &format!("<Data Name=\"SubjectUserName\">bob.demo</Data><Data Name=\"CommandLine\">{}</Data>", "A".repeat(9000))),
        win(7045, "System", "<Data Name=\"ServiceName\">svc-demo</Data><Data Name=\"ImagePath\">C:\\x.exe</Data>"),
    ] {
        out.push(lsadra_source_wineventlog::map_event_xml(&xml).expect("mapped"));
    }
    out
}

#[test]
fn every_source_event_satisfies_the_schema() {
    let v = validator();
    let events = source_events();
    assert!(events.len() >= 8);
    for e in events {
        let value: Value = serde_json::from_str(&e.to_json()).unwrap();
        let errors: Vec<String> = v.iter_errors(&value).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{}: {errors:?}", e.event_type);
        e.validate().unwrap();
    }
}

#[test]
fn agent_check_rejects_what_the_schema_rejects() {
    let v = validator();
    let good = json!({"schema_version": "1", "timestamp": "2026-01-15T02:01:12Z", "event_type": "x",
                      "source_ip": "192.0.2.1", "attributes": {"k": "v"}});
    assert!(v.is_valid(&good));
    event::parse_event(&good.to_string()).unwrap();

    let mutations: Vec<(&str, Value)> = vec![
        ("schema_version", json!("2")),
        ("timestamp", json!("2026-01-15T02:01:12")),
        ("timestamp", json!("2026-01-15 02:01:12Z")),
        ("timestamp", json!("2026-02-30T02:01:12Z")),
        ("timestamp", json!(1768442472)),
        ("source_ip", json!("gw.demo")),
        ("source_ip", json!("fe80::1%eth0")),
        ("source_ip", json!("")),
        ("host", json!("h".repeat(256))),
        ("effective_username", json!("u".repeat(129))),
        ("event_type", json!("e".repeat(65))),
        ("raw_message", json!("r".repeat(4097))),
        ("device_id", json!("dev")),
        ("user_id", json!("u")),
        ("extra_key", json!(1)),
        ("attributes", json!({"k": "v".repeat(1025)})),
        (
            "attributes",
            Value::Object((0..33).map(|i| (format!("k{i}"), json!("v"))).collect()),
        ),
    ];
    for (field, value) in mutations {
        let mut ev = good.clone();
        ev[field] = value.clone();
        let schema_ok = v.is_valid(&ev);
        let agent_ok = event::parse_event(&ev.to_string()).is_ok();
        // device_id/user_id are readOnly: the schema allows them, the core
        // rejects them, and so must the agent.
        if field == "device_id" || field == "user_id" {
            assert!(!agent_ok, "{field}");
        } else {
            assert!(!schema_ok, "schema accepted {field}={value}");
            assert_eq!(agent_ok, schema_ok, "{field}={value}");
        }
    }

    // The two x-lsadra rules JSON Schema cannot express: the agent enforces them.
    let mut nested = good.clone();
    nested["attributes"] = json!({"n": ["x".repeat(1100)]});
    assert!(event::parse_event(&nested.to_string()).is_err());
    let mut heavy = good.clone();
    heavy["attributes"] = Value::Object(
        (0..9)
            .map(|i| (format!("k{i}"), json!("x".repeat(1000))))
            .collect(),
    );
    assert!(v.is_valid(&heavy), "fits the schema keywords");
    assert!(
        event::parse_event(&heavy.to_string()).is_err(),
        "but not the 8 KB rule"
    );
}
