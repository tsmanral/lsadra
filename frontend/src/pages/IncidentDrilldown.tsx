import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Clock, Crosshair, FileTerminal, ShieldCheck, AlertTriangle, Globe, Search } from 'lucide-react';
import { getIncidentDetail, updateIncidentStatus } from '../services/api';
import Markdown from '../components/Markdown';
import { SEVERITY_COLOR, STATUSES, fmtTime, apiError as errorText, httpStatus } from '../utils/incident';
import type { IncidentDetail } from '../types/investigation';

const Chip = ({ label, color }: { label: string; color: string }) => (
  <span className="text-xs font-bold font-mono px-2 py-0.5 border" style={{ color, borderColor: color }}>{label}</span>
);

interface Loaded { key: string; detail?: IncidentDetail; error?: string }

const IncidentDrilldown = () => {
  const { id } = useParams<{ id: string }>();
  const [reload, setReload] = useState(0);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [status, setStatus] = useState('OPEN');
  const [notes, setNotes] = useState('');
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!id) return;
    let live = true;
    const key = `${id}:${reload}`;
    getIncidentDetail(id).then(
      r => {
        if (!live) return;
        const d = r.data as IncidentDetail;
        setLoaded({ key, detail: d });
        setStatus(d.incident.status || 'OPEN');
        setNotes(d.incident.notes || '');
      },
      e => {
        if (!live) return;
        setLoaded({ key, error: httpStatus(e) === 404 ? `Incident ${id} was not found, or it belongs to another account.` : errorText(e, 'Could not load the incident.') });
      },
    );
    return () => { live = false; };
  }, [id, reload]);

  const save = async () => {
    if (!id) return;
    setSaving(true);
    setSaveMsg(null);
    try {
      await updateIncidentStatus(id, status, notes);
      setSaveMsg('Saved.');
      setReload(n => n + 1);
    } catch (e) {
      setSaveMsg(errorText(e, 'Save failed.'));
    } finally {
      setSaving(false);
    }
  };

  // Keep showing the previous load of the same incident while a reload runs.
  const current = loaded && loaded.key.startsWith(`${id}:`) ? loaded : null;
  const detail = current?.detail;

  if (!current) {
    return <p role="status" className="p-6 font-mono text-sm text-[var(--color-muted)]">Loading incident {id}…</p>;
  }
  if (!detail) {
    return (
      <div className="p-6 space-y-3" role="alert">
        <h2 className="text-2xl font-display font-bold text-white">Incident {id}</h2>
        <p className="font-mono text-sm text-[var(--color-muted)]">{current.error}</p>
        <Link to="/app/dashboard" className="text-[var(--color-primary)] underline font-mono text-sm">Back to the dashboard</Link>
      </div>
    );
  }

  const inc = detail.incident;
  const sev = (inc.severity_label || 'LOW').toUpperCase();
  const sevColor = SEVERITY_COLOR[sev] || SEVERITY_COLOR.LOW;
  const ents = detail.entities;

  return (
    <div className="flex flex-col h-full space-y-6 overflow-y-auto pb-10 pr-2">
      <header className="flex flex-wrap gap-4 justify-between items-start border-b border-[rgba(0,240,255,0.3)] pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-2">
            <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">INC-{inc.id}</h2>
            <Chip label={sev} color={sevColor} />
            <Chip label={inc.status} color={inc.status === 'RESOLVED' || inc.status === 'FALSE_POSITIVE' ? '#05FFA1' : '#00F0FF'} />
          </div>
          <p className="text-white font-mono text-sm">{inc.attack_type}</p>
          <p className="text-[var(--color-muted)] font-mono text-xs mt-1">
            First seen {fmtTime(inc.first_seen)} · last seen {fmtTime(inc.last_seen)} · device {inc.device_hostname || inc.device_id || '—'}
          </p>
        </div>
        <Link to={`/app/response?incident=${inc.id}`} className="hud-button flex items-center">
          <FileTerminal size={16} className="mr-2" aria-hidden="true" /> Open playbook
        </Link>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 space-y-6">
          <section className="grid grid-cols-3 gap-3" aria-label="Incident figures">
            {[
              { label: 'Alerts', value: detail.alert_total },
              { label: 'Risk', value: detail.risk_score ?? '—' },
              { label: 'Techniques', value: ents.mitre_techniques?.length || 0 },
            ].map(s => (
              <div key={s.label} className="hud-panel p-3 text-center">
                <div className="text-xs font-mono text-[var(--color-muted)] uppercase">{s.label}</div>
                <div className="text-2xl font-display font-bold text-white">{s.value}</div>
              </div>
            ))}
          </section>

          <section className="hud-panel p-5" aria-labelledby="ent-h">
            <h3 id="ent-h" className="font-display text-lg text-[var(--color-primary)] mb-4 border-b border-[rgba(0,240,255,0.15)] pb-2 flex items-center">
              <Crosshair className="mr-2" size={18} aria-hidden="true" /> Entities
            </h3>
            <dl className="space-y-4 font-mono text-sm">
              {[
                { label: 'Source IPs', items: ents.source_ips, intel: true },
                { label: 'Users', items: ents.users },
                { label: 'Hosts', items: ents.hosts },
              ].map(group => (
                <div key={group.label}>
                  <dt className="text-[var(--color-muted)] text-xs mb-1 uppercase">{group.label}</dt>
                  <dd className="flex flex-wrap gap-2">
                    {group.items?.length ? group.items.map(v => (
                      <span key={v} className="inline-flex items-center gap-1">
                        <Link to={`/app/investigate?entity=${encodeURIComponent(v)}`} className="text-white underline decoration-dotted hover:text-[var(--color-primary)]">
                          {v}
                        </Link>
                        {group.intel && (
                          <Link to={`/app/intel?ip=${encodeURIComponent(v)}`} aria-label={`Threat intel for ${v}`} className="text-[var(--color-primary)]">
                            <Globe size={12} aria-hidden="true" />
                          </Link>
                        )}
                      </span>
                    )) : <span className="text-[var(--color-muted)]">none recorded</span>}
                  </dd>
                </div>
              ))}
              <div>
                <dt className="text-[var(--color-muted)] text-xs mb-1 uppercase">MITRE ATT&amp;CK</dt>
                <dd className="text-[var(--color-warning)]">{ents.mitre_techniques?.join(', ') || 'none recorded'}</dd>
              </div>
            </dl>
          </section>

          <section className="hud-panel p-5" aria-labelledby="status-h">
            <h3 id="status-h" className="font-display text-lg text-[var(--color-primary)] mb-4 border-b border-[rgba(0,240,255,0.15)] pb-2 flex items-center">
              <ShieldCheck className="mr-2" size={18} aria-hidden="true" /> Status
            </h3>
            <label htmlFor="inc-status" className="block text-xs font-mono text-[var(--color-muted)] uppercase mb-1">Status</label>
            <select id="inc-status" value={status} onChange={e => setStatus(e.target.value)} className="w-full text-sm font-mono px-3 py-2 mb-3">
              {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
            <label htmlFor="inc-notes" className="block text-xs font-mono text-[var(--color-muted)] uppercase mb-1">Notes</label>
            <textarea id="inc-notes" value={notes} onChange={e => setNotes(e.target.value)} rows={3}
              className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.3)] text-white text-sm font-mono px-3 py-2 mb-3" />
            <button onClick={save} disabled={saving} className="hud-button w-full disabled:opacity-60">{saving ? 'Saving…' : 'Save'}</button>
            <p role="status" aria-live="polite" className="text-xs font-mono mt-2 text-[var(--color-muted)]">{saveMsg}</p>
            {inc.assigned_username && <p className="text-xs font-mono text-[var(--color-muted)]">Assigned to {inc.assigned_username}</p>}
          </section>
        </div>

        <section className="lg:col-span-8 hud-panel p-5" aria-labelledby="tl-h">
          <h3 id="tl-h" className="font-display text-lg text-[var(--color-primary)] mb-4 border-b border-[rgba(0,240,255,0.15)] pb-2 flex items-center">
            <Clock className="mr-2" size={18} aria-hidden="true" /> Alert timeline
            <span className="ml-2 text-xs font-mono text-[var(--color-muted)]">
              ({detail.alerts.length}{detail.alerts_truncated ? ` of ${detail.alert_total}` : ''}, oldest first)
            </span>
          </h3>
          {detail.alerts.length === 0 && <p className="font-mono text-sm text-[var(--color-muted)]">No alerts are linked to this incident.</p>}
          <ol className="space-y-3">
            {detail.alerts.map(a => {
              const c = SEVERITY_COLOR[(a.severity_label || '').toUpperCase()] || '#00F0FF';
              return (
                <li key={a.id} className="border-l-4 bg-[rgba(255,255,255,0.02)] p-4" style={{ borderLeftColor: c }}>
                  <div className="flex flex-wrap justify-between gap-2 mb-2">
                    <span className="font-display font-bold uppercase tracking-wider" style={{ color: c }}>
                      {a.severity_label === 'CRITICAL' && <AlertTriangle size={14} className="inline mr-1" aria-hidden="true" />}
                      {a.threat_type || a.attack_type || 'Alert'} <span className="text-xs font-mono">({a.severity_label || 'n/a'}{a.risk_score != null ? `, risk ${a.risk_score}` : ''})</span>
                    </span>
                    <span className="text-xs text-[var(--color-muted)] font-mono">{fmtTime(a.created_at)}</span>
                  </div>
                  <div className="text-xs font-mono text-[var(--color-muted)] mb-2">
                    Alert #{a.id}{a.mitre_technique ? ` · ${a.mitre_technique}` : ''}{a.source_ip ? ` · from ${a.source_ip}` : ''}{a.effective_username ? ` · user ${a.effective_username}` : ''}{a.host ? ` · host ${a.host}` : ''}
                  </div>
                  {a.narrative
                    ? <Markdown text={a.narrative} className="text-sm text-[var(--color-text)]" />
                    : <p className="text-sm text-[var(--color-muted)]">No narrative was generated for this alert.</p>}
                  {a.raw_message && (
                    <details className="mt-2">
                      <summary className="cursor-pointer text-xs font-mono text-[var(--color-primary)]">Raw log line</summary>
                      <pre className="mt-2 bg-black border border-[rgba(255,255,255,0.1)] p-3 text-xs text-[#9EF0C4] whitespace-pre-wrap break-all">{a.raw_message}</pre>
                    </details>
                  )}
                </li>
              );
            })}
          </ol>
          <div className="mt-4 flex gap-3 text-xs font-mono">
            <Link to={`/app/feedback?alert=${detail.alerts[0]?.id ?? ''}`} className="text-[var(--color-primary)] underline inline-flex items-center gap-1">
              <Search size={12} aria-hidden="true" /> Label these alerts in Feedback
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
};

export default IncidentDrilldown;
