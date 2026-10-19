import { API_BASE_URL } from './api';

// Live alerts from the server's authenticated /ws/alerts WebSocket.
// The token goes in the subprotocol list (browsers cannot set headers on a
// WebSocket); the server closes the socket when the token expires or when
// this client falls behind, and we reconnect and backfill over REST.

export type AlertStreamStatus = 'connecting' | 'live' | 'offline';

export interface StreamAlert {
  type: 'alert';
  anomaly_id: number | null;
  incident_id: number | null;
  event_id: number | null;
  device_id: string;
  source_ip: string;
  severity_label: string;
  severity_score: number | null;
  threat_type: string;
  mitre_technique: string;
  created_at: string;
}

interface AlertStreamHandlers {
  onAlert: (alert: StreamAlert) => void;
  onStatus?: (status: AlertStreamStatus) => void;
  // Called each time the socket is (re)established. Alerts sent while we
  // were disconnected are not replayed, so callers refetch over REST here.
  onResync?: () => void;
}

const MAX_RETRY_MS = 30000;

export const alertStreamUrl = () => `${API_BASE_URL.replace(/^http/, 'ws')}/ws/alerts`;

// Opens the stream and keeps it open until the returned function is called.
export const subscribeAlerts = ({ onAlert, onStatus, onResync }: AlertStreamHandlers): (() => void) => {
  let socket: WebSocket | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let attempt = 0;
  let stopped = false;

  const scheduleRetry = () => {
    onStatus?.('offline');
    const delay = Math.min(MAX_RETRY_MS, 1000 * 2 ** attempt);
    attempt += 1;
    retryTimer = setTimeout(connect, delay);
  };

  function connect() {
    if (stopped) return;
    const token = localStorage.getItem('sentinel_token');
    if (!token) { scheduleRetry(); return; }
    onStatus?.('connecting');
    try {
      socket = new WebSocket(alertStreamUrl(), ['bearer', token]);
    } catch {
      // A token that is not a valid subprotocol token throws here.
      scheduleRetry();
      return;
    }
    socket.onmessage = (ev: MessageEvent) => {
      let msg: { type?: string };
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'ready') {
        attempt = 0;
        onStatus?.('live');
        onResync?.();
      } else if (msg.type === 'alert') {
        onAlert(msg as StreamAlert);
      }
    };
    socket.onclose = () => {
      socket = null;
      if (!stopped) scheduleRetry();
    };
  }

  connect();
  return () => {
    stopped = true;
    clearTimeout(retryTimer);
    if (socket) {
      socket.onclose = null;
      socket.close();
      socket = null;
    }
  };
};

// Stream alerts carry the anomaly id as anomaly_id; REST rows call it id.
export const alertAsAnomaly = (alert: StreamAlert) => ({ ...alert, id: alert.anomaly_id });
