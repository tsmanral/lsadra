import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BarChart3, Clock, MessageSquare, RefreshCw, ThumbsDown, ThumbsUp } from 'lucide-react';
import { getAnomalies, getFeedback, submitFeedback } from '../services/api';
import { apiError, fmtTime, httpStatus } from '../utils/incident';
import type { AlertOption, FeedbackSummary } from '../types/investigation';

const LABELS: Record<string, { text: string; color: string }> = {
  true_positive: { text: 'Real threat', color: '#FF4444' },
  false_positive: { text: 'False positive', color: '#05FFA1' },
};

const FeedbackLoop = () => {
  const [searchParams] = useSearchParams();
  const [data, setData] = useState<FeedbackSummary>({ items: [], total: 0, true_positives: 0, false_positives: 0, precision: null });
  const [reload, setReload] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertOption[]>([]);
  const [alertId, setAlertId] = useState(searchParams.get('alert') || '');
  const [label, setLabel] = useState<'true_positive' | 'false_positive'>('true_positive');
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    getFeedback().then(
      r => { if (live) { setData(r.data as FeedbackSummary); setLoadError(null); } },
      e => { if (live) setLoadError(apiError(e, 'Could not load feedback.')); },
    );
    return () => { live = false; };
  }, [reload]);

  useEffect(() => {
    getAnomalies().then(r => { if (Array.isArray(r?.data)) setAlerts(r.data as AlertOption[]); }).catch(() => {});
  }, []);

  const submit = async () => {
    const id = Number(alertId);
    if (!Number.isInteger(id) || id < 1) { setMsg('Choose an alert first.'); return; }
    setBusy(true);
    setMsg(null);
    try {
      await submitFeedback(id, label, note.trim());
      setMsg(`Saved: alert #${id} labelled ${LABELS[label].text.toLowerCase()}.`);
      setNote('');
      setReload(n => n + 1);
    } catch (e) {
      setMsg(httpStatus(e) === 404 ? `Alert #${id} was not found.` : apiError(e, 'Save failed.'));
    } finally {
      setBusy(false);
    }
  };

  const pct = data.precision == null ? '—' : `${Math.round(data.precision * 100)}%`;
  // Keep a preselected alert choosable even if it is not among the latest 50.
  const options: AlertOption[] = alerts.some(a => String(a.id) === alertId) || !alertId ? alerts : [{ id: alertId, threat_type: '(from link)' }, ...alerts];

  return (
    <div className="flex flex-col h-full space-y-6 overflow-y-auto pb-10 pr-2">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4">
        <MessageSquare className="text-[var(--color-primary)] mr-3" size={28} aria-hidden="true" />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Feedback Loop</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Tell the detector which alerts were real. Labels are stored and used when the models are retrained.</p>
        </div>
      </header>

      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4" aria-label="Feedback totals">
        {[
          { label: 'Labelled alerts', value: data.total, icon: <MessageSquare size={18} aria-hidden="true" />, color: '#00F0FF' },
          { label: 'Real threats', value: data.true_positives, icon: <ThumbsUp size={18} aria-hidden="true" />, color: '#FF4444' },
          { label: 'False positives', value: data.false_positives, icon: <ThumbsDown size={18} aria-hidden="true" />, color: '#05FFA1' },
          { label: 'Confirmed rate', value: pct, icon: <BarChart3 size={18} aria-hidden="true" />, color: '#C78BFF' },
        ].map(k => (
          <div key={k.label} className="hud-panel p-4 border-l-2" style={{ borderLeftColor: k.color }}>
            <div className="flex items-center gap-2 text-xs font-mono text-[var(--color-muted)] uppercase mb-2">{k.icon}{k.label}</div>
            <div className="text-3xl font-display font-bold" style={{ color: k.color }}>{k.value}</div>
          </div>
        ))}
      </section>
      <p className="text-xs font-mono text-[var(--color-muted)] -mt-3">Confirmed rate is the share of labelled alerts that analysts marked as real threats.</p>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-4 hud-panel p-5 space-y-4" aria-labelledby="fb-form-h">
          <h3 id="fb-form-h" className="font-display text-base text-[var(--color-primary)] uppercase flex items-center gap-2">
            <RefreshCw size={16} aria-hidden="true" /> Label an alert
          </h3>
          <div>
            <label htmlFor="fb-alert" className="text-xs font-mono text-[var(--color-muted)] uppercase block mb-1">Alert</label>
            <select id="fb-alert" value={alertId} onChange={e => setAlertId(e.target.value)} className="w-full text-sm font-mono px-3 py-2">
              <option value="">Choose a recent alert…</option>
              {options.map(a => (
                <option key={a.id} value={String(a.id)}>#{a.id} {a.threat_type || ''} {a.severity_label ? `(${a.severity_label})` : ''}</option>
              ))}
            </select>
          </div>
          <fieldset>
            <legend className="text-xs font-mono text-[var(--color-muted)] uppercase mb-1">Verdict</legend>
            {(['true_positive', 'false_positive'] as const).map(l => (
              <label key={l} className="flex items-center gap-2 text-sm font-mono text-white">
                <input type="radio" name="fb-label" value={l} checked={label === l} onChange={() => setLabel(l)} /> {LABELS[l].text}
              </label>
            ))}
          </fieldset>
          <div>
            <label htmlFor="fb-note" className="text-xs font-mono text-[var(--color-muted)] uppercase block mb-1">Note (why)</label>
            <textarea id="fb-note" value={note} onChange={e => setNote(e.target.value)} rows={4} maxLength={2000}
              className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.3)] text-white text-sm font-mono px-3 py-2 resize-none" />
          </div>
          <button onClick={submit} disabled={busy} className="w-full hud-button disabled:opacity-60">{busy ? 'Saving…' : 'Save label'}</button>
          <p role="status" aria-live="polite" className="text-xs font-mono text-[var(--color-text)]">{msg}</p>
        </section>

        <section className="lg:col-span-8 hud-panel p-5" aria-labelledby="fb-hist-h">
          <h3 id="fb-hist-h" className="font-display text-base text-[var(--color-primary)] uppercase mb-4 flex items-center gap-2">
            <Clock size={16} aria-hidden="true" /> History ({data.items.length}{data.total > data.items.length ? ` of ${data.total}` : ''})
          </h3>
          {loadError && <p role="alert" className="text-sm font-mono text-[#FF4444]">{loadError}</p>}
          {!loadError && data.items.length === 0 && (
            <p className="text-sm font-mono text-[var(--color-muted)]">No alerts have been labelled yet.</p>
          )}
          <ul className="space-y-3 max-h-[560px] overflow-y-auto pr-1">
            {data.items.map(f => {
              const l = LABELS[f.label] || { text: f.label, color: '#8BA6C1' };
              return (
                <li key={f.id} className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.08)] p-4">
                  <div className="flex flex-wrap justify-between gap-2 mb-2">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-bold font-mono px-2 py-0.5 border" style={{ color: l.color, borderColor: l.color }}>{l.text}</span>
                      <span className="text-xs font-mono text-white">Alert #{f.alert_id}{f.threat_type ? ` · ${f.threat_type}` : ''}</span>
                      {f.incident_id && <Link to={`/app/incident/${f.incident_id}`} className="text-xs font-mono underline text-[var(--color-primary)]">INC-{f.incident_id}</Link>}
                    </div>
                    <span className="text-xs font-mono text-[var(--color-muted)]">{fmtTime(f.created_at)}</span>
                  </div>
                  {f.analyst_note ? <p className="text-sm font-mono text-[var(--color-text)] whitespace-pre-wrap">{f.analyst_note}</p>
                    : <p className="text-xs font-mono text-[var(--color-muted)]">No note.</p>}
                  {f.fp_pattern && <p className="text-xs font-mono text-[var(--color-muted)] mt-1">Pattern: {f.fp_pattern}</p>}
                </li>
              );
            })}
          </ul>
        </section>
      </div>
    </div>
  );
};

export default FeedbackLoop;
