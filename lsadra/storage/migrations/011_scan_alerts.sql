-- Scheduled scans raise alerts (roadmap W5).
-- incidents.cross_source_at: when the cross-source correlation job raised the
-- incident's severity one step because its source address was active in two
-- or more log-source families. Set once, so the job never raises it twice.
ALTER TABLE incidents ADD COLUMN cross_source_at TEXT;
-- The scheduler's dedup lookup: has this rule already alerted on this address
-- in the current window?
CREATE INDEX IF NOT EXISTS idx_anomalies_rule_ip ON anomalies(rule_id, source_ip, created_at);
