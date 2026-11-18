-- Audit trail for model training, promotion and rollback (G-18).
-- One row per attempt, whether it was promoted, rejected by the canary,
-- refused (busy / cooldown) or rolled back, with who asked and why.
CREATE TABLE IF NOT EXISTS model_training_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      DATETIME NOT NULL,
    finished_at     DATETIME,
    trigger         TEXT NOT NULL,          -- auto | api | admin | rollback | other
    requested_by    TEXT,                   -- user id, or NULL for automatic runs
    status          TEXT NOT NULL,          -- running | promoted | rejected | failed | skipped | rolled_back
    event_count     INTEGER NOT NULL DEFAULT 0,
    device_count    INTEGER NOT NULL DEFAULT 0,
    excluded_count  INTEGER NOT NULL DEFAULT 0,
    canary          TEXT,                   -- JSON: per-scenario recall and verdict
    detail          TEXT
);

CREATE INDEX IF NOT EXISTS idx_training_runs_started ON model_training_runs(started_at);
