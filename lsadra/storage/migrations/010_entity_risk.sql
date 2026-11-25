-- Risk-based alerting (audit G-29, ADR 0007 layer 5).
-- risk_events: one row per detection signal attributed to an entity (a host
-- or a user). Signals are kept whether or not they raised an alert: the point
-- is that several low signals on one entity add up.
CREATE TABLE IF NOT EXISTS risk_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type  TEXT NOT NULL CHECK (entity_type IN ('host', 'user')),
    entity       TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    user_id      TEXT,
    event_id     INTEGER,
    source       TEXT NOT NULL,          -- rule | sigma | anomaly
    rule_id      TEXT,
    title        TEXT NOT NULL,
    level        TEXT NOT NULL,
    technique_id TEXT,
    tactics      TEXT NOT NULL DEFAULT '[]',
    base_score   REAL NOT NULL,
    event_time   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_events_entity ON risk_events(entity_type, entity, event_time);
CREATE INDEX IF NOT EXISTS idx_risk_events_created ON risk_events(created_at);

-- User-set weight per asset (a domain controller matters more than a kiosk).
CREATE TABLE IF NOT EXISTS asset_weights (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('host', 'user')),
    entity      TEXT NOT NULL,
    weight      REAL NOT NULL CHECK (weight > 0 AND weight <= 5),
    note        TEXT NOT NULL DEFAULT '',
    updated_by  TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity)
);

-- A risk case: opened when an entity's score crosses the threshold, kept up to
-- date while it stays open. tactics is the ordered (first seen) tactic chain.
CREATE TABLE IF NOT EXISTS risk_notables (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity      TEXT NOT NULL,
    device_id   TEXT,
    user_id     TEXT,
    score       REAL NOT NULL,
    tactics     TEXT NOT NULL DEFAULT '[]',
    signal_count INTEGER NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'OPEN',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_notables_entity ON risk_notables(entity_type, entity, status);
