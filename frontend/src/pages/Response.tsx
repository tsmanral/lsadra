import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BookOpen, Copy, Info, ListChecks } from 'lucide-react';
import { getIncidentDetail, getIncidents, updateIncidentStatus } from '../services/api';
import { SEVERITY_COLOR, STATUSES, apiError, fmtTime, httpStatus } from '../utils/incident';
import type { Incident, IncidentDetail } from '../types/investigation';

// Response: pick a real incident, follow its playbook, record the outcome.
// Playbook steps are guidance. LSADRA does not run any command on a host;
// the analyst runs them, after filling the placeholders in by hand.

const OPEN_STATES = ['OPEN', 'INVESTIGATING'];

interface Loaded { key: string; detail?: IncidentDetail; error?: string }

const Response = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get('incident');

  const [reload, setReload] = useState(0);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [showClosed, setShowClosed] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [status, setStatus] = useState('INVESTIGATING');
  const [notes, setNotes] = useState('');
  const [saveMsg, setSaveMsg] = useState<{ id: string; text: string } | null>(null);
  const [copied, setCopied] = useState<number | null>(null);

  useEffect(() => {
    let live = true;
    getIncidents().then(
      r => { if (live) { setIncidents(r?.data?.incidents || []); setListError(null); } },
      e => { if (live) setListError(apiError(e, 'Could not load incidents.')); },
    );
    return () => { live = false; };
  }, [reload]);

  useEffect(() => {
    if (!selectedId) return;
    let live = true;
    const key = `${selectedId}:${reload}`;
    getIncidentDetail(selectedId).then(
      r => {
        if (!live) return;
        const d = r.data as IncidentDetail;
        setLoaded({ key, detail: d });
        setStatus(d.incident.status === 'OPEN' ? 'INVESTIGATING' : d.incident.status);
        setNotes(d.incident.notes || '');
      },
      e => {
        if (live) setLoaded({ key, error: httpStatus(e) === 404 ? `Incident ${selectedId} was not found.` : apiError(e, 'Could not load the incident.') });
      },
    );
    return () => { live = false; };
  }, [selectedId, reload]);

  const select = (id: number) => setSearchParams({ incident: String(id) });

  const save = async () => {
    if (!selectedId) return;
    try {
      await updateIncidentStatus(selectedId, status, notes);
      setSaveMsg({ id: selectedId, text: 'Saved.' });
      setReload(n => n + 1);
    } catch (e) {
      setSaveMsg({ id: selectedId, text: apiError(e, 'Save failed.') });
    }
  };

  const copy = async (idx: number, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(idx);
      setTimeout(() => setCopied(null), 1500);
    } catch { /* clipboard blocked: the command stays visible to select by hand */ }
  };

  const current = selectedId && loaded && loaded.key.startsWith(`${selectedId}:`) ? loaded : null;
  const detail = current?.detail;
  const detailError = current?.error;
  const message = saveMsg && saveMsg.id === selectedId ? saveMsg.text : null;
  const visible = incidents.filter(i => showClosed || OPEN_STATES.includes(i.status));
  const inc = detail?.incident;
  const pb = detail?.playbook;
  const ents = detail?.entities;

  return (
    <div className="flex flex-col h-full overflow-y-auto pb-10 pr-2 space-y-6">
      <header className="border-b border-[rgba(0,240,255,0.3)] pb-4">
        <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase flex items-center">
          <BookOpen className="text-[var(--color-primary)] mr-3" size={28} aria-hidden="true" /> Response
        </h2>
        <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Pick an incident, work through its playbook, and record the outcome.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-4 hud-panel p-4" aria-labelledby="queue-h">
          <div className="flex justify-between items-center mb-3">
            <h3 id="queue-h" className="font-display text-lg text-[var(--color-primary)]">Incidents ({visible.length})</h3>
            <label className="text-xs font-mono text-[var(--color-muted)] flex items-center gap-2">
              <input type="checkbox" checked={showClosed} onChange={e => setShowClosed(e.target.checked)} /> Show closed
            </label>
          </div>
          {listError && <p role="alert" className="text-sm font-mono text-[#FF4444]">{listError}</p>}
          {!listError && visible.length === 0 && (
            <p className="text-sm font-mono text-[var(--color-muted)]">No {showClosed ? '' : 'open '}incidents. New ones appear here when detection groups alerts.</p>
          )}
          <ul className="space-y-2">
            {visible.map(i => {
              const c = SEVERITY_COLOR[(i.severity_label || '').toUpperCase()] || '#00F0FF';
              const active = String(i.id) === selectedId;
              return (
                <li key={i.id}>
                  <button onClick={() => select(i.id)} aria-current={active ? 'true' : undefined}
                    className={`w-full text-left p-3 border-l-4 font-mono text-sm transition-colors ${active ? 'bg-[rgba(0,240,255,0.1)]' : 'bg-[rgba(255,255,255,0.02)] hover:bg-[rgba(0,240,255,0.05)]'}`}
                    style={{ borderLeftColor: c }}>
                    <div className="flex justify-between gap-2">
                      <span className="text-white font-bold">INC-{i.id}</span>
                      <span className="text-xs" style={{ color: c }}>{i.severity_label || '—'}</span>
                    </div>
                    <div className="text-[var(--color-text)] truncate">{i.attack_type}</div>
                    <div className="text-xs text-[var(--color-muted)]">{i.status} · {i.source_ip || 'no source IP'} · {fmtTime(i.last_seen)}</div>
                  </button>
                </li>
              );
            })}
          </ul>
        </section>

        <section className="lg:col-span-8 space-y-6" aria-live="polite">
          {!selectedId && (
            <div className="hud-panel p-8 text-center font-mono text-sm text-[var(--color-muted)]">Select an incident to see its playbook.</div>
          )}
          {selectedId && detailError && <div role="alert" className="hud-panel p-6 font-mono text-sm text-[#FF4444]">{detailError}</div>}

          {inc && pb && (
            <>
              <div className="hud-panel p-5">
                <div className="flex flex-wrap justify-between gap-3">
                  <div>
                    <p className="text-xs font-mono text-[var(--color-muted)] uppercase">Playbook {pb.name}</p>
                    <h3 className="text-2xl font-display font-bold text-white">{pb.title}</h3>
                    <p className="text-sm font-mono text-[var(--color-text)] mt-1">{pb.description}</p>
                  </div>
                  <Link to={`/app/incident/${inc.id}`} className="self-start text-sm font-mono text-[var(--color-primary)] underline">
                    INC-{inc.id}: {inc.attack_type}
                  </Link>
                </div>
                <p className="mt-4 flex items-start gap-2 text-xs font-mono text-[var(--color-muted)]">
                  <Info size={14} className="flex-shrink-0 mt-0.5" aria-hidden="true" />
                  LSADRA does not run these commands. Run them yourself after replacing the &lt;PLACEHOLDERS&gt; with the values below; they are never filled in from logs automatically, because log text is attacker-controlled.
                </p>
                <dl className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  {([['<SOURCE_IP>', ents?.source_ips], ['<USERNAME>', ents?.users], ['<HOST>', ents?.hosts]] as [string, string[] | undefined][]).map(([k, v]) => (
                    <div key={k} className="bg-[rgba(255,255,255,0.03)] p-2">
                      <dt className="text-[var(--color-muted)]">{k}</dt>
                      <dd className="text-white break-all">{v?.length ? v.join(', ') : 'not recorded'}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="hud-panel p-5">
                <h3 className="font-display text-lg text-[var(--color-primary)] mb-4 flex items-center">
                  <ListChecks size={18} className="mr-2" aria-hidden="true" /> Steps
                </h3>
                <ol className="space-y-3">
                  {pb.steps.map(s => (
                    <li key={s.id} className="p-4 bg-[rgba(255,255,255,0.02)] border-l-4 border-[var(--color-primary)]">
                      <div className="font-bold text-white text-sm">{s.id}. {s.label}</div>
                      <p className="text-sm font-mono text-[var(--color-text)] mt-1">{s.description}</p>
                      {s.command && (
                        <div className="mt-2 flex items-start gap-2">
                          <code className="flex-1 block bg-black text-[#9EF0C4] text-xs p-2 break-all">{s.command}</code>
                          <button onClick={() => copy(s.id, s.command ?? "")} aria-label={`Copy the command for step ${s.id}`}
                            className="text-xs font-mono px-2 py-1 border border-[var(--color-primary)] text-[var(--color-primary)] flex items-center gap-1">
                            <Copy size={12} aria-hidden="true" /> {copied === s.id ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                      )}
                    </li>
                  ))}
                </ol>
              </div>

              <div className="hud-panel p-5">
                <h3 className="font-display text-lg text-[var(--color-primary)] mb-3">Record the outcome</h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label htmlFor="resp-status" className="block text-xs font-mono text-[var(--color-muted)] uppercase mb-1">Status</label>
                    <select id="resp-status" value={status} onChange={e => setStatus(e.target.value)} className="w-full text-sm font-mono px-3 py-2">
                      {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                    </select>
                  </div>
                  <div className="sm:col-span-2">
                    <label htmlFor="resp-notes" className="block text-xs font-mono text-[var(--color-muted)] uppercase mb-1">Notes</label>
                    <textarea id="resp-notes" rows={2} value={notes} onChange={e => setNotes(e.target.value)}
                      className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.3)] text-white text-sm font-mono px-3 py-2" />
                  </div>
                </div>
                <div className="mt-3 flex items-center gap-4">
                  <button onClick={save} className="hud-button">Save</button>
                  <span role="status" className="text-xs font-mono text-[var(--color-muted)]">
                    {message || `Currently ${inc.status}${inc.resolved_at ? `, closed ${fmtTime(inc.resolved_at)}` : ''}.`}
                  </span>
                </div>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
};

export default Response;
