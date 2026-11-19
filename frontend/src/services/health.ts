// Turns the GET /api/dashboard/health result into what the dashboard shows.
// Kept free of imports so it can be unit-tested with plain `node --test`.

export interface IngestionHealth {
  status: string;
  events_per_second: number | null;
  avg_latency_ms: number | null;
  drop_rate_pct: number | null;
  active_devices?: number;
}

export const UNREACHABLE: IngestionHealth = {
  status: 'UNREACHABLE',
  events_per_second: null,
  avg_latency_ms: null,
  drop_rate_pct: null,
};

/**
 * `body` is the API response body, or undefined when the request failed.
 * A successful response is always shown as-is, including an idle install
 * that ingested nothing in the last minute (0 ev/s is a real reading, not
 * "still connecting"). `mock` is the dev-only demo fallback, used only when
 * the server has nothing to show.
 */
export const pickHealth = (body: IngestionHealth | undefined, mock?: IngestionHealth): IngestionHealth => {
  if (body && typeof body === 'object' && typeof body.status === 'string') {
    if (mock && !body.events_per_second) return mock;
    return body;
  }
  return mock ?? UNREACHABLE;
};
