import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Activity, ArrowLeft, Crosshair, Globe, Network, Search, ShieldAlert } from 'lucide-react';
import { getEntity, getIncidents } from '../services/api';
import Markdown from '../components/Markdown';
import { SEVERITY_COLOR, apiError, fmtTime, httpStatus } from '../utils/incident';
import type { EntityProfile } from '../types/investigation';

const riskColor = (r: number) => (r > 80 ? '#FF4444' : r > 50 ? '#FFD700' : '#05FFA1');

// Radial map of the entity and what it touched. Decorative summary only:
// every node is also listed (and keyboard reachable) in "Related entities".
const EntityGraph: React.FC<{ entity: EntityProfile }> = ({ entity }) => {
  const cx = 300, cy = 160, r = 115;
  const rels = (entity.relationships || []).slice(0, 12);
  const color = riskColor(entity.risk_score || 0);
  return (
    <svg viewBox="0 0 600 320" className="w-full" role="img"
      aria-label={`${entity.entity} is linked to ${rels.length} other entities`}>
      {rels.map((rel, i) => {
        const a = (2 * Math.PI * i) / rels.length - Math.PI / 2;
        const nx = cx + r * Math.cos(a), ny = cy + r * Math.sin(a);
        return (
          <g key={i}>
            <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="rgba(0,240,255,0.35)" strokeWidth="1.5" strokeDasharray="4 3" />
            <circle cx={nx} cy={ny} r={30} fill="#0e131e" stroke="rgba(0,240,255,0.5)" />
            <text x={nx} y={ny - 4} textAnchor="middle" fill="#8BA6C1" fontSize="9" fontFamily="monospace">{rel.type}</text>
            <text x={nx} y={ny + 10} textAnchor="middle" fill="#E0F4FF" fontSize="9" fontFamily="monospace">{String(rel.target).slice(0, 14)}</text>
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r={40} fill="#050A14" stroke={color} strokeWidth="2" />
      <text x={cx} y={cy - 8} textAnchor="middle" fill={color} fontSize="11" fontFamily="monospace" fontWeight="bold">{String(entity.type).toUpperCase()}</text>
      <text x={cx} y={cy + 6} textAnchor="middle" fill="#fff" fontSize="9" fontFamily="monospace">{String(entity.entity).slice(0, 16)}</text>
      <text x={cx} y={cy + 22} textAnchor="middle" fill={color} fontSize="14" fontWeight="bold">{entity.risk_score}</text>
    </svg>
  );
};

const Investigate = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const current = searchParams.get('entity') || searchParams.get('incident') || '';

  const [query, setQuery] = useState(current);
  const [found, setFound] = useState<{ q: string; result?: EntityProfile; message?: string } | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [view, setView] = useState<'timeline' | 'graph'>('timeline');
  const [suggestions, setSuggestions] = useState<string[]>([]);

  // Suggestions are the sources of the newest real incidents.
  useEffect(() => {
    getIncidents().then(r => {
      const ips: string[] = (r?.data?.incidents || []).map((i: { source_ip: string | null }) => i.source_ip).filter(Boolean);
      setSuggestions(Array.from(new Set(ips)).slice(0, 6));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!current) return;
    let live = true;
    getEntity(current).then(
      r => {
        if (!live) return;
        const data = r.data as EntityProfile;
        if (data.type === 'Incident') navigate(`/app/incident/${data.incident_id}`);
        else setFound({ q: current, result: data });
      },
      e => {
        if (!live) return;
        setFound({
          q: current,
          message: httpStatus(e) === 404
            ? `Nothing on record for "${current}". Try an IP address, user name, host name or incident id (for example inc_12).`
            : apiError(e, 'Lookup failed.'),
        });
      },
    );
    return () => { live = false; };
  }, [current, navigate]);

  const shown = found && found.q === current ? found : null;
  const result = shown?.result ?? null;
  const message = shown?.message ?? null;
  const loading = !!current && !shown;

  const go = (q: string) => {
    const t = q.trim();
    if (!t) return;
    if (current && t !== current) setHistory(h => [...h, current]);
    setQuery(t);
    setSearchParams({ entity: t });
  };
  const back = () => {
    const prev = history[history.length - 1];
    if (!prev) return;
    setHistory(h => h.slice(0, -1));
    setQuery(prev);
    setSearchParams({ entity: prev });
  };

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pb-10 pr-2">
      <header className="flex items-center gap-4 border-b border-[rgba(0,240,255,0.3)] pb-4">
        {history.length > 0 && (
          <button onClick={back} className="flex items-center gap-1.5 text-xs font-mono text-[var(--color-muted)] hover:text-[var(--color-primary)] border border-[rgba(255,255,255,0.2)] px-3 py-1.5">
            <ArrowLeft size={13} aria-hidden="true" /> Back to {history[history.length - 1]}
          </button>
        )}
        <Crosshair className="text-[var(--color-primary)]" size={28} aria-hidden="true" />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Entity Investigation</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Look up an IP address, user name, host or incident id.</p>
        </div>
      </header>

      <form role="search" onSubmit={e => { e.preventDefault(); go(query); }}
        className="bg-[rgba(255,255,255,0.02)] border border-[rgba(0,240,255,0.15)] p-4">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <label htmlFor="entity-q" className="sr-only">Entity to investigate</label>
            <Search className="absolute left-3 top-2.5 text-[var(--color-muted)]" size={16} aria-hidden="true" />
            <input id="entity-q" value={query} onChange={e => setQuery(e.target.value)}
              placeholder="203.0.113.7 · svc.demo · web-01 · inc_12"
              className="w-full bg-[rgba(10,15,25,0.9)] border border-[rgba(0,240,255,0.3)] pl-9 pr-4 py-2 text-white font-mono text-sm" />
          </div>
          <button type="submit" disabled={loading} className="hud-button text-sm">{loading ? 'Looking up…' : 'Investigate'}</button>
        </div>
        {suggestions.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 mt-3">
            <span className="text-xs font-mono text-[var(--color-muted)]">Recent incident sources:</span>
            {suggestions.map(s => (
              <button type="button" key={s} onClick={() => go(s)}
                className="text-xs font-mono px-2 py-1 border border-[rgba(0,240,255,0.3)] text-[var(--color-text)] hover:text-[var(--color-primary)]">{s}</button>
            ))}
          </div>
        )}
      </form>

      <div aria-live="polite">
        {message && <p className="hud-panel p-5 font-mono text-sm text-[var(--color-text)]">{message}</p>}
      </div>

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <section className="lg:col-span-4 hud-panel p-5 space-y-4" aria-label="Entity profile">
            <div className="flex justify-between items-start">
              <div>
                <div className="text-xs font-mono text-[var(--color-muted)] uppercase">{result.type}</div>
                <div className="text-lg font-bold text-white font-mono break-all">{result.entity}</div>
              </div>
              <div className="px-3 py-2 border text-center" style={{ color: riskColor(result.risk_score), borderColor: riskColor(result.risk_score) }}>
                <div className="text-xs font-mono uppercase">Risk</div>
                <div className="text-2xl font-bold">{result.risk_score}</div>
              </div>
            </div>
            <dl className="grid grid-cols-2 gap-2 text-xs font-mono">
              <dt className="text-[var(--color-muted)]">Alerts</dt><dd className="text-white">{result.alert_count}{result.alerts_truncated ? '+' : ''}</dd>
              <dt className="text-[var(--color-muted)]">Events</dt><dd className="text-white">{result.event_count}</dd>
              <dt className="text-[var(--color-muted)]">First seen</dt><dd className="text-white">{fmtTime(result.first_seen)}</dd>
              <dt className="text-[var(--color-muted)]">Last seen</dt><dd className="text-white">{fmtTime(result.last_seen)}</dd>
            </dl>
            {result.type === 'IP' && (
              <Link to={`/app/intel?ip=${encodeURIComponent(result.entity)}`} className="inline-flex items-center gap-1 text-xs font-mono text-[var(--color-primary)] underline">
                <Globe size={12} aria-hidden="true" /> Threat intel for this IP
              </Link>
            )}

            <div>
              <h3 className="text-xs font-mono text-[var(--color-muted)] uppercase mb-2">Related incidents</h3>
              {result.related_incidents.length === 0 && <p className="text-xs font-mono text-[var(--color-muted)]">None.</p>}
              <ul className="space-y-1">
                {result.related_incidents.map(i => (
                  <li key={i.id}>
                    <Link to={`/app/incident/${i.id}`} className="text-xs font-mono underline" style={{ color: SEVERITY_COLOR[(i.severity_label || '').toUpperCase()] || '#00F0FF' }}>
                      INC-{i.id} · {i.attack_type} · {i.status}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-xs font-mono text-[var(--color-muted)] uppercase mb-2">Related entities</h3>
              {result.relationships.length === 0 && <p className="text-xs font-mono text-[var(--color-muted)]">None.</p>}
              <ul className="space-y-1">
                {result.relationships.map(rel => (
                  <li key={`${rel.type}-${rel.target}`}>
                    <button onClick={() => go(rel.target)} className="w-full flex items-center text-left text-xs bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.08)] px-3 py-2 hover:bg-[rgba(0,240,255,0.06)]">
                      <Network size={12} className="text-[var(--color-primary)] mr-2 flex-shrink-0" aria-hidden="true" />
                      <span className="text-[var(--color-muted)] mr-2 w-10">{rel.type}</span>
                      <span className="text-white font-mono truncate">{rel.target}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          <section className="lg:col-span-8 space-y-4">
            <div className="flex gap-2" role="tablist" aria-label="View">
              {(['timeline', 'graph'] as const).map(v => (
                <button key={v} role="tab" aria-selected={view === v} onClick={() => setView(v)}
                  className={`text-xs font-mono px-4 py-1.5 border ${view === v ? 'border-[var(--color-primary)] text-[var(--color-primary)]' : 'border-[rgba(255,255,255,0.2)] text-[var(--color-text)]'}`}>
                  {v === 'timeline' ? 'Alert timeline' : 'Relationship map'}
                </button>
              ))}
            </div>

            {view === 'graph' ? (
              <div className="hud-panel p-5"><EntityGraph entity={result} /></div>
            ) : (
              <div className="hud-panel p-5 space-y-4">
                <h3 className="text-sm font-display text-[var(--color-primary)] uppercase flex items-center gap-2">
                  <Activity size={16} aria-hidden="true" /> Alerts ({result.alerts.length}, newest first)
                </h3>
                {result.alerts.length === 0 && <p className="text-sm font-mono text-[var(--color-muted)]">No alerts involve this entity.</p>}
                <ol className="space-y-3">
                  {result.alerts.map(a => {
                    const c = SEVERITY_COLOR[(a.severity_label || '').toUpperCase()] || '#00F0FF';
                    return (
                      <li key={a.id} className="border-l-4 p-3 bg-[rgba(255,255,255,0.02)]" style={{ borderLeftColor: c }}>
                        <div className="flex flex-wrap justify-between gap-2">
                          <span className="font-bold text-sm" style={{ color: c }}>
                            {a.severity_label === 'CRITICAL' && <ShieldAlert size={13} className="inline mr-1" aria-hidden="true" />}
                            {a.threat_type || 'Alert'} ({a.severity_label || 'n/a'})
                          </span>
                          <span className="text-xs font-mono text-[var(--color-muted)]">{fmtTime(a.created_at)}</span>
                        </div>
                        <div className="text-xs font-mono text-[var(--color-muted)] my-1">
                          Alert #{a.id}{a.incident_id ? <> · <Link className="underline text-[var(--color-primary)]" to={`/app/incident/${a.incident_id}`}>INC-{a.incident_id}</Link></> : ''}{a.mitre_technique ? ` · ${a.mitre_technique}` : ''}
                        </div>
                        {a.narrative && <Markdown text={a.narrative} className="text-sm text-[var(--color-text)]" />}
                      </li>
                    );
                  })}
                </ol>

                <h3 className="text-sm font-display text-[var(--color-primary)] uppercase pt-2">Latest raw events ({result.recent_events.length} of {result.event_count})</h3>
                {result.recent_events.length === 0 && <p className="text-sm font-mono text-[var(--color-muted)]">No raw events.</p>}
                <ul className="space-y-1">
                  {result.recent_events.map(e => (
                    <li key={e.id} className="text-xs font-mono bg-black p-2 text-[#9EF0C4] break-all">
                      <span className="text-[var(--color-muted)]">{fmtTime(e.timestamp)} {e.event_type}</span> {e.raw_message}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};

export default Investigate;
