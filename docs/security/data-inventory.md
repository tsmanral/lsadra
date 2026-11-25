# Data inventory

What a LSADRA server stores, where, and for how long (gap G-27; GDPR Art. 5
and 25, CIS Controls 3.1 to 3.6). Everything below lives in the server's
`data/` directory unless noted.

## Where data lives

| Path | Contents | Protection |
|---|---|---|
| `data/sentinel_v3.db` (+ `-wal`, `-shm`) | SQLite database: every table below | 0600, directory 0700 (set at start-up on Linux and macOS); deleted rows are overwritten (`PRAGMA secure_delete`) |
| `data/models/` | Trained detection models | 0700 / 0600 |
| `data/tls/server.key`, `server.crt` | Self-signed TLS key and certificate (generated only for a non-loopback listener without a configured certificate) | key 0600 |
| `data/backups/` | `python -m lsadra.backup create` output, each with a SHA-256 manifest | 0700 / 0600 |

**Baseline: turn on full-disk encryption** (BitLocker, FileVault or LUKS) on the
machine that runs the server. File permissions stop other local accounts; they do
not protect a stolen disk or a copied backup. Treat backups as sensitive as the
database: they contain the same data.

On Windows, `data/` inherits the ACL of the folder it is in. Keep it inside the
service account's profile, not in a shared folder.

## Tables and retention

Two tiers: raw data uses `LSADRA_RETENTION_DAYS` (default 30, "retention days" below);
alert records use `LSADRA_ALERT_RETENTION_DAYS` (default 365, never shorter than
the raw tier, "alert days" below).
Retention runs every `LSADRA_RETENTION_INTERVAL_MINUTES` in small batches.

| Table | Personal data | Kept |
|---|---|---|
| `normalized_events` | Raw log lines, usernames, source IPs, hostnames | Retention days (longer only while a retained anomaly points at the event) |
| `anomalies` | Source IPs, usernames in narratives | Alert days |
| `incidents` | Source IPs, analyst notes, assignee | Closed (resolved or false positive): alert days after last activity, once no anomaly points at them. Open: until closed |
| `alerts_feedback` | Analyst notes | Alert days |
| `threat_intel_cache` | Observed public IPs and their reputation | Retention days |
| `ip_geolocation` | Observed public IPs and their city or country (only with `LSADRA_GEO_RESOLUTION_ENABLED`) | Retention days |
| `registration_tokens` | Which user minted a device token | Retention days after expiry |
| `device_heartbeats` | Device telemetry | Retention days |
| `metrics_5min`, `feature_drift` | Rollups and model drift records | Alert days |
| `users` | Username, bcrypt password hash, role, optional TOTP secret | Until the account is deleted |
| `devices` | Hostname, owner, bcrypt key hash | Until the device is deleted (revoking keeps the row and its history) |
| `audit_events` | Actor, target, source IP of security actions | `LSADRA_AUDIT_RETENTION_DAYS`, at least 365; rows cannot be changed, and cannot be deleted earlier |
| `ingestion_stats`, `model_registry` | None | Kept |

## What leaves the machine

Nothing, unless you opt in: `LSADRA_ABUSEIPDB_API_KEY` sends looked-up public IPs
to AbuseIPDB, and the hourly job re-checks cached ones as they expire. `LSADRA_INTEL_FEEDS` downloads
public IP lists, and `python -m lsadra.intel geo-update` downloads a geolocation
database; neither sends your IPs anywhere. Geolocation reads the local `.mmdb`
file only.

## Backups and restore

```bash
python -m lsadra.backup create                     # online copy, integrity check, manifest
python -m lsadra.backup verify <file>              # SHA-256 and integrity check
python -m lsadra.backup restore <file> --yes       # stop the server first
```

`restore` refuses a file that does not match its manifest, keeps the current
database as `pre-restore-<time>.db`, and runs any newer migrations. Copy backups
off the machine (CIS 11.4) to somewhere at least as protected as the server, and
test a restore from time to time.
