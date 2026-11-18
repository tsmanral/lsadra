-- Rule attribution on detections (audit G-12 / G-14).
-- Which registered rule (lsadra/detection/rule_engine.py) named the technique,
-- its version, and the technique's ATT&CK tactics (JSON list), so alerts,
-- the scorecard and later risk scoring can be traced to one rule version.
ALTER TABLE anomalies ADD COLUMN rule_id TEXT;
ALTER TABLE anomalies ADD COLUMN rule_version INTEGER;
ALTER TABLE anomalies ADD COLUMN mitre_tactics TEXT;
CREATE INDEX IF NOT EXISTS idx_anomalies_rule ON anomalies(rule_id);
