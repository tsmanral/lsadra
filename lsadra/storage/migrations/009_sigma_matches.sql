-- Sigma rule matches (audit G-28). One row per Sigma rule that matched a
-- scored event, recorded in shadow and alert mode alike, so the layer can be
-- compared with the built-in rules before it is allowed to raise alerts.
CREATE TABLE IF NOT EXISTS sigma_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL,
    device_id   TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    level       TEXT NOT NULL,
    techniques  TEXT NOT NULL DEFAULT '[]',
    tactics     TEXT NOT NULL DEFAULT '[]',
    source      TEXT NOT NULL,
    correlation INTEGER NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL,
    event_time  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sigma_matches_device ON sigma_matches(device_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sigma_matches_rule ON sigma_matches(rule_id);
