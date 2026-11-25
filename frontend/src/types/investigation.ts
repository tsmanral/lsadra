// Shapes returned by lsadra/api/investigation.py.

export interface Incident {
  id: number;
  device_id: string | null;
  source_ip: string | null;
  attack_type: string;
  status: string;
  assigned_to: string | null;
  severity_label: string | null;
  anomaly_count: number;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  notes: string | null;
  playbook: string | null;
  device_hostname?: string | null;
  device_os?: string | null;
  assigned_username?: string | null;
}

export interface Alert {
  id: number;
  created_at: string;
  device_id: string | null;
  source_ip: string | null;
  severity_score: number | null;
  severity_label: string | null;
  threat_type: string | null;
  attack_type: string | null;
  mitre_technique: string | null;
  narrative: string | null;
  incident_id: number | null;
  event_time: string | null;
  host: string | null;
  effective_username: string | null;
  event_type: string | null;
  raw_message: string | null;
  risk_score: number | null;
}

export interface PlaybookStep {
  id: number;
  label: string;
  description: string;
  command: string | null;
}

export interface Playbook {
  name: string;
  title: string;
  description: string;
  steps: PlaybookStep[];
}

export interface IncidentDetail {
  incident: Incident;
  risk_score: number | null;
  alerts: Alert[];
  alert_total: number;
  alerts_truncated: boolean;
  entities: { source_ips: string[]; users: string[]; hosts: string[]; mitre_techniques: string[] };
  playbook: Playbook;
}

export interface RawEvent {
  id: number;
  timestamp: string;
  device_id: string | null;
  host: string | null;
  effective_username: string | null;
  source_ip: string | null;
  event_type: string;
  raw_message: string;
}

export interface EntityProfile {
  entity: string;
  type: 'IP' | 'User' | 'Host' | 'Incident';
  incident_id?: number;
  risk_score: number;
  alert_count: number;
  alerts_truncated: boolean;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  affected_hosts: string[];
  affected_users: string[];
  source_ips: string[];
  relationships: { type: string; target: string }[];
  related_incidents: Pick<Incident, 'id' | 'attack_type' | 'severity_label' | 'status' | 'first_seen' | 'last_seen'>[];
  alerts: Alert[];
  recent_events: RawEvent[];
}

export interface FeedbackItem {
  id: number;
  alert_id: number;
  label: 'true_positive' | 'false_positive';
  analyst_note: string | null;
  fp_pattern: string | null;
  source_type: string | null;
  created_at: string;
  threat_type: string | null;
  severity_label: string | null;
  source_ip: string | null;
  incident_id: number | null;
}

export interface FeedbackSummary {
  items: FeedbackItem[];
  total: number;
  true_positives: number;
  false_positives: number;
  precision: number | null;
}

export interface AlertOption {
  id: number | string;
  threat_type?: string | null;
  severity_label?: string | null;
}
