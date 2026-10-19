import axios from 'axios';

export const API_BASE_URL = 'http://localhost:8000'; // Update this based on where your FastAPI runs

// Earlier builds kept plaintext passwords here for an offline login. That
// login is gone; clear what it left behind.
localStorage.removeItem('sentinel_mock_creds');

// Create an Axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to add JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sentinel_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// ── Live simulation counters ──────────────────────────────────────────────────
let _liveEventCount = 1543290;
let _liveAnomCount = 342;
let _lastTick = Date.now();

const tickLive = () => {
  const elapsedSec = (Date.now() - _lastTick) / 1000;
  _lastTick = Date.now();
  _liveEventCount += Math.round(elapsedSec * (4200 + Math.random() * 100));
  if (Math.random() < 0.3) _liveAnomCount += Math.round(Math.random() * 3);
};

export const getLiveStats = () => ({ events: _liveEventCount, anomalies: _liveAnomCount });

const EVENT_TYPES = ['Failed Login', 'Port Scan', 'Lateral Movement', 'Data Exfil', 'Privilege Escalation', 'Malware C2', 'Brute Force', 'Policy Violation', 'DNS Tunneling', 'Ransomware Beacon', 'Outbound 443', 'SMB Traversal', 'SQL Injection', 'ARP Spoof', 'Token Hijack'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'LOW', 'LOW'];

export const generateEventStream = (count = 200, deviceFilter?: string[]): any[] => {
  if (!isTestUser()) return [];
  const rows: any[] = [];
  for (let i = 0; i < count; i++) {
    const sev = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
    const type = EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];
    if (deviceFilter && deviceFilter.length === 0) return []; // STRICT: No devices = no events
    const host = deviceFilter ? deviceFilter[Math.floor(Math.random() * deviceFilter.length)] : `SRV-${100 + Math.floor(Math.random() * 899)}`;

    rows.push({
      id: 1000000 + i,
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      event_type: type,
      severity: sev,
      host: host,
      source_ip: `192.168.1.${10 + Math.floor(Math.random() * 200)}`,
      raw_message: `LSADRA Alert: Detected potential ${type.toLowerCase()} activity on ${host}.`,
      status: 'OPEN'
    });
  }
  return rows.sort((a, b) => b.id - a.id);
};

export const getActiveDeviceFilter = (): string[] | undefined => {
  const user = localStorage.getItem('sentinel_username') || 'anon';
  const raw = localStorage.getItem(`sentinel_device_filter_${user}`);
  if (raw === null) return undefined;
  try {
    return JSON.parse(raw);
  } catch { return undefined; }
};

export const saveActiveDeviceFilter = (deviceIds: string[]) => {
  const user = localStorage.getItem('sentinel_username') || 'anon';
  localStorage.setItem(`sentinel_device_filter_${user}`, JSON.stringify(deviceIds));
  window.dispatchEvent(new Event('sentinel_state_change'));
};

// Rich mock entity data keyed by entity for testuser investigations
export const MOCK_ENTITIES: Record<string, any> = {
  'inc_101': {
    entity: 'inc_101', type: 'Incident', risk_score: 97,
    source_ip: '10.0.5.22', attack_type: 'Ransomware Activity', severity_label: 'CRITICAL',
    affected_hosts: ['WKS-112-X', 'FILE-SRV-01'],
    affected_users: ['CORP\\jsmith', 'CORP\\svc_admin_temp'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 5400000).toISOString(), type: 'Mass File Encryption Detected', source: 'EDR', severity: 'CRITICAL', detail: '4,231 files encrypted in 90s on WKS-112-X' },
      { id: 2, timestamp: new Date(Date.now() - 4800000).toISOString(), type: 'C2 Outbound Connection', source: 'Firewall', severity: 'CRITICAL', detail: 'Outbound to 185.15.202.13:443 - known C2 node' },
      { id: 3, timestamp: new Date(Date.now() - 3600000).toISOString(), type: 'Privilege Escalation via Token Impersonation', source: 'Windows Security', severity: 'HIGH', detail: 'CORP\\svc_admin_temp elevated to SYSTEM via SeImpersonatePrivilege' },
      { id: 4, timestamp: new Date(Date.now() - 1800000).toISOString(), type: 'Lateral Movement (SMB)', source: 'Network Flow', severity: 'HIGH', detail: 'SMB share enumeration from 10.0.5.22 to FILE-SRV-01' },
    ],
    relationships: [
      { type: 'Source IP', target: '10.0.5.22 (WKS-112-X)', iconType: 'network' },
      { type: 'Compromised User', target: 'CORP\\svc_admin_temp', iconType: 'user' },
      { type: 'C2 Server', target: '185.15.202.13 (Rostelecom, RU)', iconType: 'globe' },
      { type: 'Encrypted Path', target: '\\\\FILE-SRV-01\\shares\\finance\\*', iconType: 'file' },
    ],
    playbook: 'RANSOMWARE_RESPONSE',
  },
  'inc_102': {
    entity: 'inc_102', type: 'Incident', risk_score: 78,
    source_ip: '45.33.2.1', attack_type: 'Lateral Movement', severity_label: 'HIGH',
    affected_hosts: ['APP-SRV-02', 'DB-SRV-01'],
    affected_users: ['CORP\\jdoe'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 7200000).toISOString(), type: 'Pass-the-Hash Attack', source: 'Windows Security', severity: 'HIGH', detail: 'NTLM hash reuse from 45.33.2.1 to APP-SRV-02' },
      { id: 2, timestamp: new Date(Date.now() - 5400000).toISOString(), type: 'RDP Session from Unusual Host', source: 'Network Flow', severity: 'MEDIUM', detail: 'RDP to DB-SRV-01 from 45.33.2.1 outside business hours' },
      { id: 3, timestamp: new Date(Date.now() - 3600000).toISOString(), type: 'Database Dump via SQL Tools', source: 'DLP', severity: 'HIGH', detail: 'sqlcmd.exe exfiltrating 2.1GB from customer_db' },
    ],
    relationships: [
      { type: 'Source IP', target: '45.33.2.1 (APP-SRV-02)', iconType: 'network' },
      { type: 'Compromised User', target: 'CORP\\jdoe', iconType: 'user' },
      { type: 'Target DB', target: 'DB-SRV-01 (customer_db)', iconType: 'server' },
    ],
    playbook: 'AD_ELEVATION_RESPONSE',
  },
  'inc_103': {
    entity: 'inc_103', type: 'Incident', risk_score: 55,
    source_ip: '192.168.1.1', attack_type: 'Brute Force', severity_label: 'MEDIUM',
    affected_hosts: ['DC-01'],
    affected_users: ['admin', 'administrator', 'root'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 14400000).toISOString(), type: '847 Failed Login Attempts', source: 'Active Directory', severity: 'MEDIUM', detail: 'Credential stuffing from 192.168.1.1 on DC-01' },
      { id: 2, timestamp: new Date(Date.now() - 10800000).toISOString(), type: 'Account Lockout: admin', source: 'Active Directory', severity: 'HIGH', detail: 'Account admin locked after 5 failed attempts' },
    ],
    relationships: [{ type: 'Network', target: 'Internal Segment', iconType: 'network' }],
    playbook: null,
  },
  'inc_104': {
    entity: 'inc_104', type: 'Incident', risk_score: 94,
    source_ip: '10.0.5.22', attack_type: 'Privilege Escalation', severity_label: 'CRITICAL',
    affected_hosts: ['WKS-112-X'], affected_users: ['CORP\\jsmith'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 1800000).toISOString(), type: 'LSA Secrets Dump', source: 'EDR', severity: 'CRITICAL', detail: 'lsass.exe memory dumped to C:\\Windows\\Temp\\debug.bin' },
      { id: 2, timestamp: new Date(Date.now() - 900000).toISOString(), type: 'Scheduled Task Creation', source: 'Windows Security', severity: 'HIGH', detail: 'New task "Update" created to run as SYSTEM' },
    ],
    relationships: [{ type: 'Host', target: 'WKS-112-X', iconType: 'server' }],
    playbook: 'AD_ELEVATION_RESPONSE',
  },
  'inc_105': {
    entity: 'inc_105', type: 'Incident', risk_score: 88,
    source_ip: '45.33.2.1', attack_type: 'Data Exfiltration', severity_label: 'HIGH',
    affected_hosts: ['LNX-SRV-01'], affected_users: ['ubuntu'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 900000).toISOString(), type: 'Mass SCP Upload', source: 'Syslog', severity: 'HIGH', detail: '4.2GB uploaded to remote IP 8.8.8.8 via scp' },
    ],
    relationships: [{ type: 'Source', target: 'LNX-SRV-01', iconType: 'server' }],
    playbook: null,
  },
  '10.0.5.22': {
    entity: '10.0.5.22', type: 'IP', risk_score: 97,
    related_incidents: ['inc_101'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 5400000).toISOString(), type: 'Ransomware Activity', source: 'EDR', severity: 'CRITICAL', detail: 'WKS-112-X beacon — encryption payload deployed' },
      { id: 2, timestamp: new Date(Date.now() - 4800000).toISOString(), type: 'C2 Communication', source: 'Firewall', severity: 'CRITICAL', detail: 'Outbound to 185.15.202.13:443' },
    ],
    relationships: [
      { type: 'Hostname', target: 'WKS-112-X', iconType: 'server' },
      { type: 'Logged User', target: 'CORP\\jsmith', iconType: 'user' },
      { type: 'C2 Contact', target: '185.15.202.13 (RU)', iconType: 'globe' },
    ],
    playbook: 'RANSOMWARE_RESPONSE',
  },
  '45.33.2.1': {
    entity: '45.33.2.1', type: 'IP', risk_score: 78,
    related_incidents: ['inc_102'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 7200000).toISOString(), type: 'Pass-the-Hash', source: 'Windows Security', severity: 'HIGH', detail: 'NTLM credential reuse from APP-SRV-02' },
      { id: 2, timestamp: new Date(Date.now() - 5400000).toISOString(), type: 'Lateral RDP', source: 'Network Flow', severity: 'MEDIUM', detail: 'RDP to DB-SRV-01 outside business hours' },
    ],
    relationships: [
      { type: 'Hostname', target: 'APP-SRV-02', iconType: 'server' },
      { type: 'Logged User', target: 'CORP\\jdoe', iconType: 'user' },
      { type: 'Target', target: 'DB-SRV-01', iconType: 'server' },
    ],
    playbook: 'AD_ELEVATION_RESPONSE',
  },
  '192.168.1.1': {
    entity: '192.168.1.1', type: 'IP', risk_score: 55,
    source_ip: '192.168.1.1',
    attack_type: 'Brute Force',
    related_incidents: ['inc_103'],
    affected_hosts: ['DC-01'],
    affected_users: ['admin', 'administrator'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 14400000).toISOString(), type: '847 Failed Login Attempts', source: 'Active Directory', severity: 'MEDIUM', detail: 'Credential stuffing on DC-01 from 192.168.1.1 — Hydra pattern detected' },
      { id: 2, timestamp: new Date(Date.now() - 10800000).toISOString(), type: 'Account Lockout', source: 'Active Directory', severity: 'HIGH', detail: 'Account admin locked after threshold exceeded' },
    ],
    relationships: [
      { type: 'Target DC', target: 'DC-01 (Domain Controller)', iconType: 'server' },
      { type: 'Tool Pattern', target: 'Hydra / CrackMapExec', iconType: 'file' },
      { type: 'Related Incident', target: 'inc_103', iconType: 'network' },
    ],
    playbook: 'BRUTE_FORCE_RESPONSE',
  },
  'CORP\\jsmith': {
    entity: 'CORP\\jsmith', type: 'User', risk_score: 91,
    source_ip: '10.0.5.22',
    attack_type: 'Account Compromise',
    related_incidents: ['inc_101'],
    affected_hosts: ['WKS-112-X', 'FILE-SRV-01'],
    affected_users: ['CORP\\jsmith', 'CORP\\svc_admin_temp'],
    related_events: [
      { id: 1, timestamp: new Date(Date.now() - 6000000).toISOString(), type: 'Credentials Used in Ransomware', source: 'EDR', severity: 'CRITICAL', detail: 'jsmith credentials leveraged to deploy encryption payload on WKS-112-X' },
      { id: 2, timestamp: new Date(Date.now() - 5000000).toISOString(), type: 'Token Impersonation', source: 'Windows Security', severity: 'HIGH', detail: 'SeImpersonatePrivilege abused on CORP\\svc_admin_temp via jsmith session' },
    ],
    relationships: [
      { type: 'Primary Host', target: 'WKS-112-X', iconType: 'server' },
      { type: 'Source IP', target: '10.0.5.22', iconType: 'network' },
      { type: 'Impersonated', target: 'CORP\\svc_admin_temp', iconType: 'user' },
      { type: 'Related Incident', target: 'inc_101', iconType: 'network' },
    ],
    playbook: 'RANSOMWARE_RESPONSE',
  },
};

// Extended entity lookup — all pivot nodes clickable in the graph
const EXTRA_ENTITIES: Record<string, any> = {
  'WKS-112-X': { entity: 'WKS-112-X', type: 'Host', risk_score: 95, source_ip: '10.0.5.22', attack_type: 'Ransomware Victim', related_incidents: ['inc_101'], affected_users: ['CORP\\jsmith'], related_events: [{ id: 1, timestamp: new Date().toISOString(), type: 'Mass File Encryption', source: 'EDR', severity: 'CRITICAL', detail: '4,231 files encrypted in 90s on WKS-112-X' }], relationships: [{ type: 'User Session', target: 'CORP\\jsmith', iconType: 'user' }, { type: 'C2 Contact', target: '185.15.202.13', iconType: 'globe' }], playbook: 'RANSOMWARE_RESPONSE' },
  'DC-01': { entity: 'DC-01', type: 'Domain Controller', risk_score: 88, source_ip: '172.16.0.1', attack_type: 'Brute Force Target', related_incidents: ['inc_102'], affected_users: ['administrator'], related_events: [{ id: 1, timestamp: new Date().toISOString(), type: '847 Failed Logins', source: 'Active Directory', severity: 'HIGH', detail: 'Credential stuffing from 192.168.1.1' }], relationships: [{ type: 'Attacker IP', target: '192.168.1.1', iconType: 'network' }, { type: 'Domain', target: 'CORP.LOCAL', iconType: 'server' }], playbook: 'BRUTE_FORCE_RESPONSE' },
  'APP-SRV-02': { entity: 'APP-SRV-02', type: 'Server', risk_score: 75, source_ip: '45.33.2.1', attack_type: 'Lateral Movement Target', related_incidents: ['inc_102'], affected_users: ['CORP\\jdoe'], related_events: [{ id: 1, timestamp: new Date().toISOString(), type: 'Pass-the-Hash Auth', source: 'Windows Security', severity: 'HIGH', detail: 'NTLM hash from 45.33.2.1 used for CORP\\jdoe' }], relationships: [{ type: 'Attacker IP', target: '45.33.2.1', iconType: 'network' }, { type: 'Target DB', target: 'DB-SRV-01', iconType: 'server' }], playbook: 'AD_ELEVATION_RESPONSE' },
  'inc_101': { entity: 'inc_101', type: 'Incident', risk_score: 92, attack_type: 'Ransomware Outbreak', related_events: [{ id: 1, timestamp: new Date().toISOString(), type: 'Ransomware Note', source: 'CrowdStrike', severity: 'CRITICAL', detail: 'README_HOW_TO_DECRYPT.txt created on WKS-112-X' }], relationships: [{ type: 'Infected Host', target: 'WKS-112-X', iconType: 'server' }], playbook: 'RANSOMWARE_RESPONSE' },
  'inc_102': { entity: 'inc_102', type: 'Incident', risk_score: 85, attack_type: 'Domain Escalation', related_events: [{ id: 1, timestamp: new Date().toISOString(), type: 'Privilege Abuse', source: 'AD Security', severity: 'CRITICAL', detail: 'Domain Admin token theft on DC-01' }], relationships: [{ type: 'Compromised DC', target: 'DC-01', iconType: 'server' }], playbook: 'AD_ELEVATION_RESPONSE' },
  '1': { entity: '1', type: 'Incident', risk_score: 85, attack_type: 'Linux Brute Force', related_events: [{ id: 1, timestamp: new Date().toISOString(), type: 'SSH Brute Force', source: 'Syslog', severity: 'HIGH', detail: '150+ failed logins from 185.x.x.x' }], relationships: [{ type: 'Target Host', target: 'Mock-Linux-01', iconType: 'server' }], playbook: 'BRUTE_FORCE_RESPONSE' },
};

// Merge so all lookups go through one object
Object.assign(MOCK_ENTITIES, EXTRA_ENTITIES);


// Incident status persistence (overrides mock/real data)
const INCIDENT_STATUS_KEY = 'sentinel_incident_status';


const getIncidentStatus = (id: string, fallback: string) => {
  const store = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
  return store[id] || fallback;
};

// Mock data generator for testuser
// --- GLOBAL TICK ENGINE FOR DEMO DYNAMICS ---
let _liveTotalEvents = 5340234;
let _liveAnomalies = 854;
let _liveIncidents = 42;

// Live buffer of anomalies that grows over time
let _anomalyBuffer: any[] = [
  { id: 101, device_id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', threat_type: 'SSH_BRUTE_FORCE', severity_label: 'HIGH', created_at: new Date(Date.now() - 3600000).toISOString(), narrative: '150+ failed logins from unique IP 185.x.x.x', playbook: 'BRUTE_FORCE_RESPONSE' },
  { id: 102, device_id: 'b997415c-9653-4f45-87bf-f4a84d936f76', threat_type: 'RANSOMWARE_INDICATOR', severity_label: 'CRITICAL', created_at: new Date(Date.now() - 1800000).toISOString(), narrative: 'Mass file modification in system32 detected', playbook: 'RANSOMWARE_RESPONSE' },
  { id: 103, device_id: 'net-edge-001', threat_type: 'LATERAL_MOVEMENT', severity_label: 'HIGH', created_at: new Date(Date.now() - 900000).toISOString(), narrative: 'Internal port scanning detected from host', playbook: 'LATERAL_MOVEMENT_RESPONSE' },
];

// Update global counts every 2 seconds
setInterval(() => {
  _liveTotalEvents += Math.floor(Math.random() * 50) + 20;
}, 2000);

// Inject a new anomaly every 5 seconds to keep the feed moving
setInterval(() => {
  const types = [
    { t: 'C2_BEACON', s: 'CRITICAL', n: 'Outbound beacon to suspected Cobalt Strike' },
    { t: 'SUSPICIOUS_SUDO', s: 'MEDIUM', n: 'Unexpected privilege escalation on root' },
    { t: 'UNUSUAL_LOGON', s: 'HIGH', n: 'Logon from untrusted geolocation detected' },
    { t: 'DATA_EXFIL', s: 'CRITICAL', n: 'Mass data transfer to unauthorized cloud storage' },
    { t: 'SQL_INJECTION', s: 'HIGH', n: 'SQL injection pattern detected on APP-SRV-02' }
  ];
  const pick = types[Math.floor(Math.random() * types.length)];
  const newAnom = {
    id: Date.now(),
    device_id: ['8a4be99a-200e-4511-a35c-264e0ce69aa8', 'b997415c-9653-4f45-87bf-f4a84d936f76', 'net-edge-001', 'wks-112-pro', 'WKS-112-X', 'DC-01'][Math.floor(Math.random() * 6)],
    threat_type: pick.t,
    severity_label: pick.s,
    created_at: new Date().toISOString(),
    narrative: pick.n,
    playbook: 'BRUTE_FORCE_RESPONSE'
  };
  _anomalyBuffer = [newAnom, ..._anomalyBuffer].slice(0, 50);
  _liveAnomalies += 1;
}, 5000);

const getMockData = (endpoint: string) => {
  const filterIds = getActiveDeviceFilter() || [];

  const statusStore = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
  const filterByDevice = (items: any[]) => {
    if (filterIds.length === 0) return []; // STRICT: Return nothing if no devices selected
    return items.filter(i => filterIds.includes(i.device_id));
  };

  const mockIncidents = [
    { id: '1', device_id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', title: 'Linux Brute Force Attack', severity_label: 'HIGH', status: statusStore['1'] || 'OPEN', created_at: new Date().toISOString(), playbook: 'BRUTE_FORCE_RESPONSE', type: 'Incident' },
    { id: '2', device_id: 'b997415c-9653-4f45-87bf-f4a84d936f76', title: 'Windows Ransomware Indicator', severity_label: 'CRITICAL', status: statusStore['2'] || 'OPEN', created_at: new Date().toISOString(), playbook: 'RANSOMWARE_RESPONSE', type: 'Incident' },
    { id: 'inc_101', device_id: 'WKS-112-X', title: 'Critical Ransomware Outbreak', severity_label: 'CRITICAL', status: statusStore['inc_101'] || 'OPEN', created_at: new Date().toISOString(), playbook: 'RANSOMWARE_RESPONSE', type: 'Incident' },
    { id: 'inc_102', device_id: 'DC-01', title: 'Domain Controller Compromise', severity_label: 'CRITICAL', status: statusStore['inc_102'] || 'OPEN', created_at: new Date().toISOString(), playbook: 'AD_ELEVATION_RESPONSE', type: 'Incident' }
  ];

  if (endpoint.includes('/api/dashboard/kpis')) {
    const filteredAnoms = filterByDevice(_anomalyBuffer);
    const filteredIncs = filterByDevice(mockIncidents);
    const openCount = filteredIncs.filter(i => i.status !== 'RESOLVED').length;
    const resolvedInFiltered = filteredIncs.filter(i => i.status === 'RESOLVED').length;
    
    // Strict scaling: 0 devices = 0 events. 15% per device otherwise.
    const eventFactor = filterIds.length > 0 ? Math.min(1.0, filterIds.length * 0.15) : 0;
    const currentTotal = Math.floor(_liveTotalEvents * eventFactor);

    return {
      data: {
        total_events_24h: currentTotal,
        total_anomalies_24h: filteredAnoms.length,
        open_incidents: openCount,
        closed_incidents: resolvedInFiltered,
        active_devices: filterIds.length 
      }
    };
  }

  if (endpoint.includes('/api/dashboard/anomalies')) {
    return { data: filterByDevice(_anomalyBuffer) };
  }

  if (endpoint.includes('/api/incidents')) {
    const filtered = filterByDevice(mockIncidents);
    return { data: { incidents: filtered, count: filtered.length } };
  }

  if (endpoint.includes('/api/events/stats')) {
    const pulse = Math.sin(Date.now() / 2000) * 2;
    const eventFactor = filterIds.length > 0 ? Math.min(1.0, filterIds.length * 0.15) : 0;
    return {
      data: {
        events_per_second: (12.5 + pulse) * eventFactor,
        avg_latency_ms: eventFactor > 0 ? 4.2 + (pulse * 0.1) : 0,
        drop_rate_pct: 0.0,
        total_events: Math.floor(_liveTotalEvents * eventFactor)
      }
    };
  }

  if (endpoint.includes('/api/dashboard/metrics')) {
    const metrics = [];
    const now = Date.now();
    const eventFactor = filterIds.length > 0 ? Math.min(1.0, filterIds.length * 0.15) : 0;
    for (let i = 0; i < 24; i++) {
      const ts = new Date(now - i * 3600000).toISOString();
      metrics.push({
        timestamp: ts,
        event_count: Math.floor((100 + Math.random() * 50) * eventFactor),
        anomaly_count: Math.floor((Math.random() * 5) * eventFactor),
        avg_score: eventFactor > 0 ? 0.1 + Math.random() * 0.2 : 0
      });
    }
    return { data: metrics.reverse() };
  }

  if (endpoint.includes('/api/dashboard/devices')) {
    return {
      data: [
        { id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', hostname: 'Mock-Linux-01', ip_address: '192.168.1.45', os_type: 'Ubuntu 22.04 (Linux)', is_active: true, status: 'ONLINE', type: 'Server' },
        { id: 'b997415c-9653-4f45-87bf-f4a84d936f76', hostname: 'Mock-Win-Server', ip_address: '10.0.0.12', os_type: 'Windows Server 2022', is_active: true, status: 'ONLINE', type: 'Server' },
        { id: 'net-edge-001', hostname: 'Mock-Net-Edge', ip_address: '172.16.0.1', os_type: 'Zeek Network OS', is_active: true, status: 'ONLINE', type: 'Network' },
        { id: 'wks-112-pro', hostname: 'Mock-WKS-112', ip_address: '10.0.5.101', os_type: 'Windows 11 Pro', is_active: true, status: 'ONLINE', type: 'Workstation' },
        { id: 'WKS-112-X', hostname: 'WKS-112-X', ip_address: '10.0.5.22', os_type: 'Windows 10 Enterprise', is_active: true, status: 'ONLINE', type: 'Workstation' },
        { id: 'DC-01', hostname: 'DC-01', ip_address: '172.16.0.1', os_type: 'Windows Server (Active Directory)', is_active: true, status: 'ONLINE', type: 'Infrastructure' },
        { id: 'APP-SRV-02', hostname: 'APP-SRV-02', ip_address: '45.33.2.1', os_type: 'Ubuntu Linux 20.04', is_active: true, status: 'ONLINE', type: 'Server' }
      ]
    };
  }

  if (endpoint.includes('/api/dashboard/stats') || endpoint.includes('/api/dashboard/db-stats')) {
    const eventFactor = filterIds.length > 0 ? Math.min(1.0, filterIds.length * 0.15) : 0;
    const filteredIncs = filterByDevice(mockIncidents);
    const filteredAnoms = filterByDevice(_anomalyBuffer);
    return {
      data: {
        normalized_events: Math.floor(_liveTotalEvents * eventFactor),
        anomalies: filteredAnoms.length,
        incidents: filteredIncs.length,
        devices: filterIds.length,
        model_registry: filterIds.length > 0 ? 2 : 0,
        feedback_labels: filterIds.length > 0 ? 5 : 0
      }
    };
  }
  if (endpoint.includes('/api/dashboard/health')) {
    return { data: { status: 'HEALTHY', events_per_second: 12.5, avg_latency_ms: 4.2, drop_rate_pct: 0.0 } };
  }
  if (endpoint.includes('/api/dashboard/generate-token')) {
    return { data: { token: 'SENT-' + Math.random().toString(36).slice(2, 10).toUpperCase() + '-' + Date.now() } };
  }
  if (endpoint.includes('/api/dashboard/retrain')) {
    return { data: { status: 'ok', events: _liveTotalEvents, models_retrained: 2, duration_ms: 8234, message: `Ensemble + Autoencoder retrained on ${_liveTotalEvents.toLocaleString()} events.` } };
  }
  if (endpoint.includes('/api/dashboard/run-drift')) {
    return { data: { status: 'ok', features_checked: 8, drifted: 3, message: 'PSI drift detection complete. 3 features drifted (login_hour, failed_logins, latent_var).' } };
  }
  if (endpoint.includes('/api/dashboard/models')) {
    return {
      data: [
        { model_name: 'ensemble', model_type: 'Isolation Forest + LOF + OCSVM', event_count: 1543290, trained_at: new Date(Date.now() - 86400000 * 2).toISOString(), version: 'v2.4.1', is_stale: false },
        { model_name: 'autoencoder', model_type: 'PyTorch Neural Autoencoder', event_count: 1543290, trained_at: new Date(Date.now() - 86400000 * 2).toISOString(), version: 'v1.8.0', is_stale: false },
      ]
    };
  }
  if (endpoint.includes('/api/devices')) {
    return {
      data: [
        { id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', hostname: 'Mock-Linux-01', ip_address: '192.168.1.45', os_type: 'Ubuntu 22.04 (Linux)', is_active: true, status: 'ONLINE', type: 'Server' },
        { id: 'b997415c-9653-4f45-87bf-f4a84d936f76', hostname: 'Mock-Win-Server', ip_address: '10.0.0.12', os_type: 'Windows Server 2022', is_active: true, status: 'ONLINE', type: 'Server' },
        { id: 'net-edge-001', hostname: 'Mock-Net-Edge', ip_address: '172.16.0.1', os_type: 'Zeek Network OS', is_active: true, status: 'ONLINE', type: 'Network' },
        { id: 'wks-112-pro', hostname: 'Mock-WKS-112', ip_address: '10.0.5.101', os_type: 'Windows 11 Pro', is_active: true, status: 'ONLINE', type: 'Workstation' },
        { id: 'WKS-112-X', hostname: 'WKS-112-X', ip_address: '10.0.5.22', os_type: 'Windows 10 Enterprise', is_active: true, status: 'ONLINE', type: 'Workstation' },
        { id: 'DC-01', hostname: 'DC-01', ip_address: '172.16.0.1', os_type: 'Windows Server (Active Directory)', is_active: true, status: 'ONLINE', type: 'Infrastructure' },
        { id: 'APP-SRV-02', hostname: 'APP-SRV-02', ip_address: '45.33.2.1', os_type: 'Ubuntu Linux 20.04', is_active: true, status: 'ONLINE', type: 'Server' }
      ]
    };
  }
  if (endpoint.includes('/api/dashboard/users')) {
    return {
      data: [
        { id: 'usr_001', username: 'admin', role: 'ADMIN', created_at: new Date(Date.now() - 86400000 * 30).toISOString() },
        { id: 'usr_002', username: 'testuser', role: 'ANALYST', created_at: new Date(Date.now() - 86400000 * 14).toISOString() },
        { id: 'usr_003', username: 'jsmith', role: 'ANALYST', created_at: new Date(Date.now() - 86400000 * 7).toISOString() },
        { id: 'usr_004', username: 'jdoe', role: 'VIEWER', created_at: new Date(Date.now() - 86400000 * 3).toISOString() },
      ]
    };
  }
  if (endpoint.includes('/api/entity/')) {
    const id = endpoint.split('/').pop() || '';
    const decoded = decodeURIComponent(id);
    let entity = MOCK_ENTITIES[id] || MOCK_ENTITIES[decoded];
    if (entity) {
      const status = getIncidentStatus(entity.entity, entity.status || 'OPEN');
      return { data: { ...entity, status } };
    }
    return null;
  }
  if (endpoint.includes('/api/dashboard/export')) {
    const statusStore = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
    const closed = Object.keys(statusStore).filter(k => statusStore[k] === 'RESOLVED');
    const custom = JSON.parse(localStorage.getItem('sentinel_custom_resolutions') || '{}');

    const content = `
================================================================================
AI-SENTINEL SOC EXECUTIVE SUMMARY REPORT
================================================================================
Generated At: ${new Date().toLocaleString()}
Classification: CONFIDENTIAL / INTERNAL USE ONLY

1. INCIDENT OVERVIEW
--------------------------------------------------------------------------------
Total Incidents Tracked: 15
Currently Open:          ${Math.max(0, 15 - closed.length)}
Successfully Resolved:   ${closed.length}
Resolution Rate:         ${((closed.length / 15) * 100).toFixed(1)}%

2. RESOLUTION DETAILS
--------------------------------------------------------------------------------
The following incidents were remediated via LSADRA Playbooks:
${closed.map(id => ` - [${id}] Status: RESOLVED (${custom[id]?.playbook || 'Standard Playbook'}) @ ${custom[id]?.timestamp || 'N/A'}`).join('\n')}

3. SYSTEM HEALTH & TELEMETRY
--------------------------------------------------------------------------------
- Active Devices: 7
- Ingestion Status: STABLE
- Model Integrity: 99.4% (Ensemble v2.4.1)

4. OPERATOR RECOMMENDATIONS
--------------------------------------------------------------------------------
- Review custom resolutions for [${Object.keys(custom).join(', ')}]
- Trigger manual model retraining to incorporate new remediation patterns.
- Export detailed log forensic artifacts for high-severity cases.

--------------------------------------------------------------------------------
END OF REPORT
================================================================================
    `;
    return { data: new Blob([content.trim()], { type: 'text/plain' }) };
  }
  return null;
};

export const isTestUser = () => {
  const user = localStorage.getItem('sentinel_username');
  return user === 'testuser'; // STRICT: Only testuser gets mock data
};
// Existing Endpoints wrapped with mock logic
export const login = async (credentials: { username: string; password: string }) => {
  try {
    const res = await api.post('/api/auth/login', credentials);
    localStorage.setItem('sentinel_username', credentials.username);
    if (res.data?.role) localStorage.setItem('sentinel_role', res.data.role);
    return res;
  } catch (err) {
    // No offline fallback: only the server issues tokens.
    const res = axios.isAxiosError(err) ? err.response : undefined;
    throw new Error(res?.data?.detail || (res ? 'Invalid credentials' : 'Backend unreachable'), { cause: err });
  }
};

export const updateIncidentStatus = async (id: string | number, status: string) => {
  const idStr = String(id);
  const store = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
  store[idStr] = status;
  localStorage.setItem(INCIDENT_STATUS_KEY, JSON.stringify(store));

  // Dispatch event for local reactivity
  window.dispatchEvent(new Event('sentinel_state_change'));

  try {
    return await api.post(`/api/incidents/${id}/status`, { status });
  } catch {
    return { data: { ok: true, note: 'Saved locally' } };
  }
};

export const register = async (credentials: any) => api.post('/api/auth/register', credentials);

export const getHealth = async () => api.get('/api/health');

export const getIncidents = async () => {
  // 1. Try real API first
  try {
    const res = await api.get('/api/incidents');
    if (res.data?.incidents?.length > 0) {
      // Merge local resolutions to ensure instant feedback
      const statusStore = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
      res.data.incidents = res.data.incidents.map((i: any) => ({
        ...i,
        status: statusStore[String(i.id)] || i.status
      }));
      return res;
    }
  } catch (err) {
    console.error("Failed to fetch real incidents:", err);
  }

  // 2. Fallback to mock data for demo
  if (isTestUser()) return getMockData('/api/incidents') || { data: { incidents: [] } };
  return { data: { incidents: [] } };
};

export const assignIncident = async (id: number, assigned_to: string) => api.post(`/incidents/${id}/assign`, { assigned_to });

export const getIngestionStats = async () => {
  try {
    const res = await api.get('/api/dashboard/health');
    if (res.data?.events_per_second > 0) return res;
  } catch { }

  if (isTestUser()) {
    // Provide "pulsing" mock stats for demo
    const pulse = Math.sin(Date.now() / 2000) * 2;
    return {
      data: {
        events_per_second: 12.5 + pulse,
        avg_latency_ms: 4.2 + (pulse * 0.1),
        drop_rate_pct: 0.0
      }
    };
  }
  return { data: { events_per_second: 0, avg_latency_ms: 0, drop_rate_pct: 0 } };
};

export const getAnomalies = async () => {
  const deviceId = getActiveDeviceFilter();
  // 1. Try real API first
  try {
    const res = await api.get(`/api/dashboard/anomalies${deviceId ? `?device_id=${deviceId}` : ''}`);
    if (res.data?.length > 0) return res;
  } catch { }

  // 2. Fallback to mock ONLY for testuser
  if (isTestUser()) {
    return getMockData('/api/dashboard/anomalies');
  }

  return { data: [] };
};

export const getEvents = async (limit = 1000) => {
  try { return await api.get(`/api/dashboard/events?limit=${limit}`); } catch { return { data: [] }; }
};

export const getKpis = async () => {
  const deviceId = getActiveDeviceFilter();
  let kpis: any = { total_events_24h: 0, total_anomalies_24h: 0, open_incidents: 0, closed_incidents: 0, active_devices: 0 };

  // 1. Try real API first
  try {
    const res = await api.get(`/api/dashboard/kpis${deviceId ? `?device_id=${deviceId}` : ''}`);
    if (res.data) kpis = { ...res.data };
  } catch (err) { }

  // 3. FORCE correct closed_incidents count based on local status store
  // This ensures the counter matches the "Resolved" section exactly.
  try {
    const statusStore = JSON.parse(localStorage.getItem(INCIDENT_STATUS_KEY) || '{}');
    const closedCount = Object.values(statusStore).filter(s => s === 'RESOLVED' || s === 'FALSE_POSITIVE').length;
    // We use the MAX of the local count and server count to avoid losing data
    kpis.closed_incidents = Math.max(kpis.closed_incidents || 0, closedCount);
  } catch { }

  // 4. Fallback to mock ONLY for testuser if real counts are zero
  if (isTestUser() && kpis.total_events_24h === 0) {
    const mock = getMockData('/api/dashboard/kpis')?.data || {};
    return { data: { ...kpis, ...mock } };
  }

  return { data: kpis };
};

export const exportReport = async () => {
  if (isTestUser()) return getMockData('/api/dashboard/export');
  try { return await api.get('/api/dashboard/export', { responseType: 'blob' }); }
  catch { return getMockData('/api/dashboard/export'); }
};
export const generateToken = async () => {
  if (isTestUser()) return getMockData('/api/dashboard/generate-token') || api.post('/api/dashboard/generate-token');
  return api.post('/api/dashboard/generate-token');
};
export const getMetrics = async () => {
  const start = new Date(Date.now() - 86400000).toISOString();
  const end = new Date().toISOString();

  // 1. Try real API
  try {
    const res = await api.get(`/api/dashboard/metrics?start=${start}&end=${end}`);
    if (res.data?.length > 0) return res;
  } catch { }

  // 2. Mock fallback for testuser
  if (isTestUser()) {
    return getMockData('/api/dashboard/metrics');
  }

  return { data: [] };
};
export const getDevices = async () => {
  if (isTestUser()) return getMockData('/api/dashboard/devices') || { data: [] };
  try { return await api.get('/api/dashboard/devices'); } catch { return { data: [] }; }
};
export const deleteDevice = async (id: string) => {
  // Only use mock success if specifically logged in as 'testuser'
  if (isTestUser()) return { data: { status: 'ok' } };
  return api.delete(`/api/dashboard/devices/${id}`);
};
export const updateDeviceStatus = async (id: string, active: boolean) => {
  if (isTestUser()) return { data: { status: 'ok' } };
  return api.post(`/api/dashboard/devices/${id}/status?active=${active}`);
};
export const retrainModel = async () => {
  const isAdmin = localStorage.getItem('sentinel_role') === 'ADMIN';
  const isTest = isTestUser();

  try {
    const res = await api.post('/api/dashboard/retrain');
    if (res.data?.status === 'ok' || res.data?.status === 'success') return res;
    throw new Error(res.data?.message || 'Retrain returned non-ok status');
  }
  catch (err) {
    // If TestUser is testing offline/broken backend, allow mock success
    if (isTest) {
      return new Promise(r => setTimeout(() => r({ data: { status: 'success', message: 'Model retraining started (Simulation)' } }), 1000));
    }
    return { data: { status: 'error', message: (err as any).message || 'Offline' } };
  }
};
export const runDrift = async () => {
  const isAdmin = localStorage.getItem('sentinel_role') === 'ADMIN';
  const isTest = isTestUser();

  try {
    const res = await api.post('/api/dashboard/run-drift');
    if (res.data?.status === 'ok' || res.data?.status === 'success') return res;
    throw new Error(res.data?.message || 'Drift detection returned non-ok status');
  }
  catch (err) {
    if (isTest) {
      return new Promise(r => setTimeout(() => r({ data: { status: 'success', message: 'Drift detection completed (Simulation)' } }), 1000));
    }
    return { data: { status: 'error', message: (err as any).message || 'Offline' } };
  }
};
export const getModelRegistry = async () => {
  if (isTestUser()) {
    const res = await api.get('/api/dashboard/models').catch(() => null);
    if (res?.data && res.data.length > 0) return res;
    // Fallback to mock models if backend empty or offline for Test
    return {
      data: [
        { model_name: 'ensemble', model_type: 'Isolation Forest + LOF + OCSVM', event_count: 1543290, trained_at: new Date(Date.now() - 86400000 * 2).toISOString(), version: 'v2.4.1', is_stale: false },
        { model_name: 'autoencoder', model_type: 'PyTorch Neural Autoencoder', event_count: 1543290, trained_at: new Date(Date.now() - 86400000 * 2).toISOString(), version: 'v1.8.0', is_stale: false },
      ]
    };
  }
  try { return await api.get('/api/dashboard/models'); } catch { return { data: [] }; }
};
export const getDrift = async () => {
  try { return await api.get('/api/dashboard/drift'); } catch { return { data: {} }; }
};
export const getEntityTimeline = async (params: any) => api.get('/api/entity-timeline', { params });
export const getUsers = async () => {
  try { return await api.get('/api/dashboard/users'); } catch { return { data: [] }; }
};
export const updateUserRole = async (user_id: string, role: string) => {
  return api.post('/api/dashboard/users/role', { user_id, role });
};
export const updateUserPassword = async (user_id: string, password: string) => {
  return api.post('/api/dashboard/users/password', { user_id, password });
};

export const getStats = async () => {
  const isAdmin = localStorage.getItem('sentinel_role') === 'ADMIN';
  if (isTestUser()) {
    const res = await api.get('/api/dashboard/stats').catch(() => null);
    if (res?.data && Object.keys(res.data).length > 0) return res;
    // Mock stats fallback only for testuser
    return { data: { normalized_events: 5340234, anomalies: 854, incidents: 42, devices: 45, model_registry: 2, feedback_labels: 5, users: 4, agents: 4 } };
  }
  try { return await api.get('/api/dashboard/stats'); } catch { return { data: { normalized_events: 0, anomalies: 0, incidents: 0, devices: 0, model_registry: 0, feedback_labels: 0, users: 0, agents: 0 } }; }
};

export const getEntity = async (id: string) => {
  if (isTestUser()) return getMockData(`/api/entity/${id}`) || api.get(`/api/entity/${id}`);
  return api.get(`/api/entity/${id}`);
};
