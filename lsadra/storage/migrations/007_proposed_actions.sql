-- Recommendations from the optional LLM tier (G-30). The broker can only
-- insert PROPOSED rows; a human moves them to APPROVED or REJECTED. Nothing
-- reads this table to execute an action.
CREATE TABLE IF NOT EXISTS proposed_actions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id         INTEGER REFERENCES incidents(id),
    action              TEXT NOT NULL,
    target              TEXT NOT NULL,
    rationale           TEXT,
    source              TEXT NOT NULL DEFAULT 'llm',
    evidence_event_ids  TEXT,               -- JSON array of cited event ids
    status              TEXT NOT NULL DEFAULT 'PROPOSED',  -- PROPOSED | APPROVED | REJECTED
    created_at          DATETIME NOT NULL,
    decided_by          TEXT,
    decided_at          DATETIME
);

CREATE INDEX IF NOT EXISTS idx_proposed_actions_incident ON proposed_actions(incident_id);
