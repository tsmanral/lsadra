# LSADRA collectors

Rust endpoint agents for LSADRA ([ADR 0001](../docs/architecture/adr/0001-rust-collector-split.md)).
Each one reads the host's security log, turns the records the detection core uses into
[event-schema v1](../docs/contracts/event-schema.v1.json) events
([ADR 0006](../docs/architecture/adr/0006-event-schema-v1-freeze.md)), spools them to disk and
ships them to `POST /api/events/batch`.

Status: first cut (M2 work). Linux (journald) and Windows (Event Log) sources work; macOS builds
and passes tests but has no log source yet. Releases do not ship the agent yet, and binaries are
not signed yet.

## Layout

| Crate | What it does |
|---|---|
| `core` (`lsadra-collector-core`) | The v1 `Event` and its contract check, the disk spool, the HTTPS shipper, device-key storage, config |
| `source-journald` | Follows `journalctl --follow --output=json` for sshd, sudo and su; maps logins, invalid users, sudo commands and su to events; resumes from a saved journal cursor |
| `source-wineventlog` | `EvtSubscribe` on Security and System, filtered to 13 event IDs (logons, process creation, services, scheduled tasks, account and group changes, log clearing); resumes from a saved bookmark |
| `agent` (`lsadra-agent`) | The binary: picks the source for the OS, validates, spools and ships |

Source crates build without the HTTP stack, so they can be tested and reused on their own.

## How it stays light and loses nothing

- **Small.** No async runtime, no date-time or CLI crates, rustls for TLS, `journalctl` instead
  of linking libsystemd. Release build on Linux: about 2 MB, under 4 MB RSS while shipping.
- **Checked before it is stored.** Every event passes the same rules the core enforces (bounds,
  RFC 3339 timestamp with an offset, IP literal or nothing, attribute limits, no `device_id` or
  `user_id`). A record that fails is dropped alone, so it can never make the core reject a batch.
- **On disk before the source moves on.** Events go to `state_dir/spool/` (1 MB segments, 64 MB
  cap by default, oldest dropped and counted past the cap). The journal cursor or event-log
  bookmark is saved only after the events are spooled, and the spool is only acked after the
  core answers. Killing the agent at any point loses nothing; at worst the batch in flight is
  sent again. `agent/tests/kill_and_spool.rs` proves this with `kill -9`.
- **Polite to the core.** At most 100 events per request; `Retry-After` honoured on 429 and 503;
  exponential backoff to 5 minutes when the core is down; on 401/403 it keeps the events and
  retries slowly. If the core still rejects a batch (422), the agent halves it until the bad
  event is alone and drops only that one.

## Device key

The key never goes in the config file (a config that contains `api_key` is refused).

- **Windows / macOS:** Credential Manager / Keychain, through the `keyring` crate.
- **Linux:** the agent is a headless root service with no user keyring, so the key is kept in
  `state_dir/device.key`, mode 0600. The agent refuses to read it if group or others can, or if
  it is owned by another user.
- `key_file = "/path"` in the config forces the file store on any OS (containers, tests).

```sh
echo "$DEVICE_KEY" | lsadra-agent set-key --config /etc/lsadra-agent/agent.toml
lsadra-agent check --config /etc/lsadra-agent/agent.toml
lsadra-agent run   --config /etc/lsadra-agent/agent.toml
```

## Config

```toml
server_url = "https://lsadra.example:8443"   # http:// only to loopback, or with allow_insecure_http
device_id  = "web-01"                        # from device registration
# state_dir = "/var/lib/lsadra-agent"        # C:\ProgramData\LSADRA\agent on Windows
# spool_max_bytes = 67108864
# batch_size = 100                           # clamped to 1..100
# flush_interval_secs = 3
# ca_file = "/etc/lsadra-agent/ca.pem"       # private CA for a self-hosted core
# key_file = "/etc/lsadra-agent/device.key"

[journald]
# identifiers = ["sshd", "sshd-session", "sudo", "su"]

[wineventlog]
# query = "<QueryList>...</QueryList>"        # replaces the built-in event-ID filter
```

On Windows the agent must run as LocalSystem or an administrator to read the Security log.

## Develop

```sh
cd collectors
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # unit, schema contract, kill-and-spool
cargo build --release -p lsadra-agent
```

`agent/tests/contract.rs` checks the bounds and timestamp pattern against the schema file and
validates every event the sources emit against it with format assertion on, so a schema change
that the collectors do not follow fails CI. CI runs all of this on Ubuntu, Windows and macOS
(`.github/workflows/collectors.yml`).

## Not done yet

Service install units (systemd, Windows service), authenticated heartbeat, macOS `log stream`
source, signed release binaries and an update channel, and the installer hand-off from the
Connect Device page. These follow in later PRs.
