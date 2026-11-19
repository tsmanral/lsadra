// Shared display helpers for incident and alert pages.

// All four pass WCAG AA (4.5:1) as text on the dashboard's dark panels.
export const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#FF4444',
  HIGH: '#FF8C00',
  MEDIUM: '#FFD700',
  LOW: '#05FFA1',
};

export const STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

// SQLite timestamps come back as "YYYY-MM-DD HH:MM:SS" in UTC with no zone.
export const fmtTime = (ts?: string | null) => {
  if (!ts) return '—';
  const iso = ts.includes('T') ? ts : ts.replace(' ', 'T');
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
};

interface HttpErrorLike {
  message?: string;
  response?: { status?: number; data?: { detail?: unknown } };
}

/** HTTP status of a failed axios call, if any. */
export const httpStatus = (e: unknown): number | undefined => (e as HttpErrorLike | null)?.response?.status;

export const apiError = (e: unknown, fallback: string): string => {
  const err = e as HttpErrorLike | null;
  if (err?.response?.status === 403) return 'Your role is not allowed to make this change.';
  const detail = err?.response?.data?.detail;
  return typeof detail === 'string' ? detail : err?.message || fallback;
};
