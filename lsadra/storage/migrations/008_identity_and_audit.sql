-- ============================================================================
-- LSADRA — Identity hardening and audit trail
-- Migration: 008_identity_and_audit
-- Created:   2026-11-18
--
-- users:   token_version (bumped on logout, role, password or disable, so every
--          token issued before it stops working), disabled flag, optional TOTP.
-- devices: previous key kept for a short overlap after a key rotation.
-- audit_events: append-only, hash-chained record of security-relevant actions.
-- ============================================================================

ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;

ALTER TABLE devices ADD COLUMN previous_api_key_hash TEXT;
ALTER TABLE devices ADD COLUMN previous_key_expires_at DATETIME;

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,        -- UTC ISO-8601
    actor_id    TEXT,                 -- users.id, or NULL for anonymous/system
    actor_name  TEXT,
    action      TEXT NOT NULL,        -- e.g. auth.login.failure, user.role.change
    target      TEXT,
    outcome     TEXT NOT NULL,        -- success | failure | denied
    source_ip   TEXT,
    details     TEXT,                 -- JSON object
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL UNIQUE  -- sha256(prev_hash || canonical row)
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);

-- Append-only: rows can never be changed, and can only be removed once they
-- are past the fixed 365-day audit retention floor.
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_early_delete
BEFORE DELETE ON audit_events
WHEN old.ts > strftime('%Y-%m-%dT%H:%M:%S', 'now', '-365 days')
BEGIN
    SELECT RAISE(ABORT, 'audit_events rows are kept for at least 365 days');
END;
