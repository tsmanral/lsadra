-- Indexes for scheduled retention and the time-window jobs (lsadra/jobs/scheduler.py).
-- Without them every retention batch and every correlation / lateral-movement scan
-- is a full table scan of normalized_events, which grows with the retention window.
CREATE INDEX IF NOT EXISTS idx_events_timestamp     ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_anomalies_event      ON anomalies(event_id);
CREATE INDEX IF NOT EXISTS idx_heartbeats_timestamp ON device_heartbeats(timestamp);
