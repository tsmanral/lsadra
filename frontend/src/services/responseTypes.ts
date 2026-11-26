import { isAxiosError } from 'axios';

/** One row of GET /api/dashboard/models. */
export interface ModelRecord {
  model_name: string;
  model_type?: string;
  event_count?: number;
  trained_at?: string;
  version?: string;
  is_stale?: boolean;
}

/** One PSI measurement from GET /api/dashboard/drift. */
export interface DriftPoint {
  feature_name: string;
  psi_value: number;
  is_drifted: boolean;
  measured_at: string;
}

/** GET /api/dashboard/drift, keyed by model name. */
export type DriftByModel = Partial<Record<string, DriftPoint[]>>;

/** The counters of GET /api/dashboard/stats that the dashboard pages read. */
export interface PipelineStats {
  normalized_events?: number;
  anomalies?: number;
  incidents?: number;
  devices?: number;
  model_registry?: number;
}

/** Body of a retrain or drift-run response. */
export interface ActionResult {
  status?: string;
  message?: string;
  detail?: string;
  events?: number;
}

/** The `data` of an axios-style response, or undefined. */
export const dataOf = <T,>(res: unknown): T | undefined =>
  (res as { data?: T } | null | undefined)?.data;

/** The API's `detail` field from an error response, if there is one. */
export const apiDetail = (err: unknown): string | undefined =>
  isAxiosError<{ detail?: string }>(err) ? err.response?.data?.detail : undefined;

/** The API's `detail`, else the error's own message, for an alert. */
export const errorDetail = (err: unknown): string => {
  if (isAxiosError<{ detail?: string }>(err)) {
    return err.response?.data?.detail || err.message;
  }
  return err instanceof Error ? err.message : String(err);
};
