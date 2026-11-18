import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, Network, Globe, Activity, ShieldAlert, Crosshair, BookOpen, ChevronRight, ChevronDown, ArrowLeft, CheckCircle, Zap, Plus } from 'lucide-react';
import { MOCK_ENTITIES, getEntity, updateIncidentStatus, isTestUser } from '../services/api';

// ── SVG Entity Graph ──────────────────────────────────────────────────────────
const EntityGraph: React.FC<{ entity: any; onNodeClick: (q: string) => void }> = ({ entity, onNodeClick }) => {
  const cx = 300, cy = 160, r = 110;
  const rels = entity.relationships || [];
  const nodeColor = entity.risk_score > 80 ? '#FF4444' : entity.risk_score > 50 ? '#FFD700' : '#05FFA1';

  const iconChar = (t: string) =>
    t === 'network' ? '⬡' : t === 'user' ? '◉' : t === 'server' ? '▣' : t === 'globe' ? '⊕' : '◈';

  return (
    <svg width="100%" viewBox="0 0 600 320" className="w-full">
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L6,3 z" fill="rgba(0,240,255,0.4)"/>
        </marker>
      </defs>

      {/* Edges */}
      {rels.map((rel: any, i: number) => {
        const angle = (2 * Math.PI * i) / rels.length - Math.PI / 2;
        const nx = cx + r * Math.cos(angle), ny = cy + r * Math.sin(angle);
        return (
          <g key={i}>
            <line x1={cx} y1={cy} x2={nx} y2={ny}
              stroke="rgba(0,240,255,0.25)" strokeWidth="1.5" strokeDasharray="4 3"
              markerEnd="url(#arrow)"/>
            <text x={(cx + nx) / 2} y={(cy + ny) / 2 - 5}
              fill="rgba(0,240,255,0.5)" fontSize="9" textAnchor="middle" fontFamily="monospace">
              {rel.type}
            </text>
          </g>
        );
      })}

      {/* Center node */}
      <circle cx={cx} cy={cy} r={36} fill="rgba(3,6,10,0.95)"
        stroke={nodeColor} strokeWidth="2" filter="url(#glow)"/>
      <circle cx={cx} cy={cy} r={36} fill="transparent"
        stroke={nodeColor} strokeWidth="1" strokeDasharray="3 3" opacity={0.4}>
        <animateTransform attributeName="transform" type="rotate" from={`0 ${cx} ${cy}`} to={`360 ${cx} ${cy}`} dur="12s" repeatCount="indefinite"/>
      </circle>
      <text x={cx} y={cy - 6} textAnchor="middle" fill={nodeColor} fontSize="11" fontFamily="monospace" fontWeight="bold">
        {entity.type?.toUpperCase()}
      </text>
      <text x={cx} y={cy + 8} textAnchor="middle" fill="white" fontSize="9" fontFamily="monospace">
        {String(entity.entity).slice(0, 16)}
      </text>
      <text x={cx} y={cy + 22} textAnchor="middle" fill={nodeColor} fontSize="14" fontWeight="bold">
        {entity.risk_score}
      </text>

      {/* Relation nodes */}
      {rels.map((rel: any, i: number) => {
        const angle = (2 * Math.PI * i) / rels.length - Math.PI / 2;
        const nx = cx + r * Math.cos(angle), ny = cy + r * Math.sin(angle);
        const label = rel.target.split(' ')[0];
        return (
          <g key={i} className="cursor-pointer" onClick={() => onNodeClick(label)}
            style={{ cursor: 'pointer' }}>
            <circle cx={nx} cy={ny} r={28} fill="rgba(3,6,10,0.9)"
              stroke="rgba(0,240,255,0.4)" strokeWidth="1.5"/>
            <circle cx={nx} cy={ny} r={28} fill="rgba(0,240,255,0.04)"
              className="hover:fill-[rgba(0,240,255,0.1)]"/>
            <text x={nx} y={ny - 4} textAnchor="middle" fill="#00F0FF" fontSize="14">{iconChar(rel.iconType)}</text>
            <text x={nx} y={ny + 12} textAnchor="middle" fill="#aaa" fontSize="8" fontFamily="monospace">
              {label.slice(0, 14)}
            </text>
          </g>
        );
      })}
    </svg>
  );
};

// ── Severity helpers ──────────────────────────────────────────────────────────
const sevColor = (s: string) =>
  s === 'CRITICAL' ? '#FF4444' : s === 'HIGH' ? '#FF8C00' : s === 'MEDIUM' ? '#FFD700' : '#05FFA1';
const sevBg = (s: string) =>
  s === 'CRITICAL' ? 'bg-[#FF4444]' : s === 'HIGH' ? 'bg-[#FF8C00]' : 'bg-[#FFD700]';

// ── Fallback for unknown entities ─────────────────────────────────────────────
const makeFallback = (q: string) => {
  const isIP = /^\d+\.\d+\.\d+/.test(q);
  // If it's an IP, try to find matching incidents
  if (isIP && isTestUser()) {
    const match = Object.values(MOCK_ENTITIES).find((e: any) => e.source_ip === q);
    if (match) return { ...match, entity: q };
  }
  return {
    entity: q, type: isIP ? 'IP' : q.startsWith('inc_') ? 'Incident' : 'Host',
    risk_score: 42, attack_type: 'Unknown',
    affected_hosts: [], affected_users: [],
    related_events: [
      { id: 1, timestamp: new Date(Date.now()-3600000).toISOString(), type: 'Auth Event', source: 'AD', severity: 'MEDIUM', detail: `Activity observed for ${q}` },
    ],
    relationships: [{ type: 'Network', target: 'Internal Segment', iconType: 'network' }],
    playbook: null,
  };
};

// ── Main Component ────────────────────────────────────────────────────────────
const Investigate = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialQ = searchParams.get('entity') || searchParams.get('incident') || '';

  const [query, setQuery] = useState(initialQ);
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [expandedEvt, setExpandedEvt] = useState<number | null>(null);
  const [view, setView] = useState<'timeline' | 'graph'>('graph');
  const [history, setHistory] = useState<string[]>([]);  // navigation stack

  const queryRef = React.useRef(query);
  queryRef.current = query;

  const search = useCallback(async (q: string, pushHistory = true) => {
    if (!q.trim()) return;
    setLoading(true);
    setExpandedEvt(null);
    if (pushHistory) setHistory(prev => queryRef.current ? [...prev, queryRef.current] : prev);
    
    try {
      const r = await getEntity(q);
      if ((r as any)?.data) {
        let data = { ...(r as any).data };
        
        // Inject manual resolution logs only if actually resolved
        const custom = JSON.parse(localStorage.getItem('sentinel_custom_resolutions') || '{}');
        const resInfo = custom[q] || custom[data.entity];
        const statusInStore = localStorage.getItem('sentinel_incident_status') ? JSON.parse(localStorage.getItem('sentinel_incident_status') || '{}')[data.entity || q] : null;
        const effectiveStatus = statusInStore || data.status || 'OPEN';

        if (resInfo && effectiveStatus === 'RESOLVED') {
          const resEvt = {
            id: 'manual_res_' + Date.now(),
            timestamp: resInfo.timestamp,
            type: 'Manual Remediation',
            source: 'Security Operator',
            severity: 'LOW',
            detail: 'Incident resolved via: ' + (resInfo.playbook || 'Manual Update')
          };
          if (!data.related_events) data.related_events = [];
          if (!data.related_events.find((e: any) => e.type === 'Manual Remediation')) {
            data.related_events.unshift(resEvt);
          }
        }
        data.status = effectiveStatus;

        setResults(data);
        setQuery(q);
      } else {
        const fb = makeFallback(q);
        setResults({ ...fb, entity: q });
        setQuery(q);
      }
    } catch {
      const fb = makeFallback(q);
      setResults({ ...fb, entity: q });
      setQuery(q);
    }
    setLoading(false);
  }, []);

  const goBack = () => {
    if (!history.length) return;
    const prev = history[history.length - 1];
    setHistory(h => h.slice(0, -1));
    setQuery(prev);
    search(prev, false);
  };

  useEffect(() => { 
    if (initialQ && queryRef.current !== initialQ) { 
      setQuery(initialQ); 
      search(initialQ, false); 
    } 
  }, [initialQ, search]);

  const QUICK = ['inc_101','inc_102','inc_103','192.168.1.46','10.0.0.5','172.16.0.50'];

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      {/* Header */}
      <header className="flex items-center gap-4 border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        {history.length > 0 && (
          <button onClick={goBack}
            className="flex items-center gap-1.5 text-xs font-mono text-[var(--color-muted)] hover:text-[var(--color-primary)] border border-[rgba(255,255,255,0.1)] hover:border-[rgba(0,240,255,0.3)] px-3 py-1.5 transition-colors flex-shrink-0">
            <ArrowLeft size={13}/> {history[history.length-1]}
          </button>
        )}
        <Crosshair className="text-[var(--color-primary)]" size={28}/>
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Entity Investigation</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Cross-system correlation — IP · Hostname · Username · Incident ID</p>
        </div>
      </header>

      {/* Search */}
      <div className="bg-[rgba(255,255,255,0.02)] border border-[rgba(0,240,255,0.15)] rounded p-4">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-2.5 text-[var(--color-muted)]" size={16}/>
            <input
              value={query} onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && search(query)}
              placeholder="inc_101 · 192.168.1.46 · CORP\jsmith · WKS-112-X · file hash..."
              className="w-full bg-[rgba(10,15,25,0.9)] border border-[rgba(0,240,255,0.3)] rounded pl-9 pr-4 py-2 text-white font-mono text-sm focus:outline-none focus:border-[var(--color-primary)]"
            />
          </div>
          <button onClick={() => search(query)} disabled={loading}
            className="hud-button bg-[var(--color-primary)] text-black font-bold px-5 text-sm">
            {loading ? 'Mapping…' : 'Investigate'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          {QUICK.map(q => (
            <button key={q} onClick={() => { setQuery(q); search(q); }}
              className="text-[10px] font-mono px-2 py-1 border border-[rgba(0,240,255,0.2)] text-[var(--color-muted)] hover:text-[var(--color-primary)] hover:border-[var(--color-primary)] transition-colors rounded-sm">
              {q}
            </button>
          ))}
        </div>
      </div>

      {results && (
        <div className="grid grid-cols-12 gap-5">
          {/* Left — Entity Card */}
          <div className="col-span-4 flex flex-col gap-4">
            <div className="hud-panel p-5">
              {/* Risk header */}
              <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1 flex items-center gap-2">
                    {results.type} Profile
                    {results.type === 'Incident' && (
                      <select 
                        value={results.status || 'OPEN'} 
                        onChange={async (e) => {
                          const ns = e.target.value;
                          await updateIncidentStatus(results.entity, ns);
                          
                          const custom = JSON.parse(localStorage.getItem('sentinel_custom_resolutions') || '{}');
                          if (ns === 'RESOLVED') {
                            custom[results.entity] = { 
                              playbook: 'Manual Resolution',
                              timestamp: new Date().toISOString() 
                            };
                          } else {
                            delete custom[results.entity];
                          }
                          localStorage.setItem('sentinel_custom_resolutions', JSON.stringify(custom));
                          
                          // Optimistic update
                          setResults((prev: any) => prev ? { ...prev, status: ns } : null);
                          window.dispatchEvent(new Event('sentinel_state_change'));
                          
                          // Then deep reload
                          setTimeout(() => search(results.entity, false), 100);
                        }}
                        className={`bg-transparent border-none outline-none font-bold cursor-pointer hover:underline ${results.status==='RESOLVED'?'text-[#05FFA1]':'text-[#FF8C00]'}`}
                      >
                        <option value="OPEN" className="bg-[#03060a]">OPEN</option>
                        <option value="INVESTIGATING" className="bg-[#03060a]">INVESTIGATING</option>
                        <option value="RESOLVED" className="bg-[#03060a]">RESOLVED</option>
                      </select>
                    )}
                    {results.type !== 'Incident' && results.status === 'RESOLVED' && (
                      <span className="text-[#05FFA1] font-bold">[RESOLVED]</span>
                    )}
                  </div>
                  <div className="text-lg font-bold text-white font-mono break-all">{results.entity}</div>
                  {results.attack_type && <div className="text-xs font-mono text-[#FF8C00] mt-1">{results.attack_type}</div>}
                </div>
                <div className={`px-3 py-2 border flex flex-col items-center text-center ${
                  results.risk_score > 80 ? 'bg-[rgba(255,68,68,0.1)] border-[#FF4444] text-[#FF4444]' :
                  results.risk_score > 50 ? 'bg-[rgba(255,215,0,0.1)] border-[#FFD700] text-[#FFD700]' :
                  'bg-[rgba(5,255,161,0.1)] border-[#05FFA1] text-[#05FFA1]'}`}>
                  <div className="text-[9px] font-mono uppercase">Risk</div>
                  <div className="text-2xl font-bold">{results.risk_score}</div>
                </div>
              </div>

              {/* Risk bar */}
              <div className="h-1 w-full bg-[rgba(255,255,255,0.05)] rounded-full mb-4 overflow-hidden">
                <div className="h-full rounded-full transition-all"
                  style={{ width:`${results.risk_score}%`, backgroundColor: results.risk_score>80?'#FF4444':results.risk_score>50?'#FFD700':'#05FFA1' }}/>
              </div>

              {/* Metadata chips */}
              {results.affected_hosts?.length > 0 && (
                <div className="mb-3">
                  <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1.5">Affected Hosts</div>
                  <div className="flex flex-wrap gap-1">
                    {results.affected_hosts.map((h: string) => (
                      <span key={h} className="text-[10px] font-mono px-2 py-0.5 border border-[rgba(0,240,255,0.25)] text-[var(--color-primary)]">{h}</span>
                    ))}
                  </div>
                </div>
              )}
              {results.affected_users?.length > 0 && (
                <div className="mb-4">
                  <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1.5">Affected Users</div>
                  <div className="flex flex-wrap gap-1">
                    {results.affected_users.map((u: string) => (
                      <span key={u} className="text-[10px] font-mono px-2 py-0.5 border border-[rgba(255,215,0,0.3)] text-[#FFD700]">{u}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Related incidents for IP lookups */}
              {results.related_incidents?.length > 0 && (
                <div className="mb-4">
                  <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1.5">Related Incidents</div>
                  <div className="flex flex-wrap gap-1">
                    {results.related_incidents.map((id: string) => (
                      <button key={id} onClick={() => { setQuery(id); search(id); }}
                        className="text-[10px] font-mono px-2 py-0.5 border border-[rgba(255,68,68,0.4)] text-[#FF4444] hover:bg-[rgba(255,68,68,0.1)] transition-colors">
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Relationships */}
              <div className="space-y-1.5 border-t border-[rgba(255,255,255,0.05)] pt-4">
                <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-2">Entity Relationships</div>
                {results.relationships?.map((rel: any, i: number) => (
                  <div key={i} onClick={() => { const t = rel.target.split(' ')[0]; setQuery(t); search(t); }}
                    className="flex items-center text-xs bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.05)] rounded px-3 py-2 hover:bg-[rgba(0,240,255,0.05)] transition-colors cursor-pointer group">
                    <Network size={12} className="text-[var(--color-primary)] mr-2 flex-shrink-0"/>
                    <div className="flex-1 min-w-0">
                      <div className="text-[9px] text-[var(--color-muted)] uppercase">{rel.type}</div>
                      <div className="text-white font-mono truncate text-[11px]">{rel.target}</div>
                    </div>
                    <ChevronRight size={11} className="text-[var(--color-muted)] group-hover:text-[var(--color-primary)] flex-shrink-0"/>
                  </div>
                ))}
              </div>

              {/* Playbook CTA */}
              {results.type === 'Incident' && (
                results.status === 'RESOLVED' ? (
                  <div className="mt-4 w-full flex items-center justify-center gap-2 border border-[#05FFA1] text-[#05FFA1] bg-[rgba(5,255,161,0.1)] px-3 py-2 text-xs font-bold font-mono">
                    <CheckCircle size={13}/> Incident Resolved via Playbook
                  </div>
                ) : results.playbook ? (
                  <button onClick={() => navigate(`/app/response?playbook=${results.playbook}&entity=${results.entity}`)}
                    className="mt-4 w-full flex items-center justify-center gap-2 bg-[#FF4444] text-black px-3 py-2 text-xs font-bold font-mono hover:bg-[#FF6666] transition-colors">
                    <Zap size={13}/> Launch Playbook: {results.playbook}
                  </button>
                ) : (
                  <button onClick={() => navigate(`/app/response?incident=${results.entity}`)}
                    className="mt-4 w-full flex items-center justify-center gap-2 border border-[var(--color-primary)] text-[var(--color-primary)] px-3 py-2 text-xs font-bold font-mono hover:bg-[var(--color-primary)] hover:text-black transition-colors">
                    <Plus size={13}/> Create Manual Playbook
                  </button>
                )
              )}
            </div>
          </div>

          {/* Right — Graph + Timeline */}
          <div className="col-span-8 flex flex-col gap-4">
            {/* View Toggle */}
            <div className="flex gap-2 shrink-0">
              {(['graph','timeline'] as const).map(v => (
                <button key={v} onClick={() => setView(v)}
                  className={`text-xs font-mono px-4 py-1.5 border transition-colors ${view===v ? 'border-[var(--color-primary)] text-[var(--color-primary)] bg-[rgba(0,240,255,0.06)]' : 'border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] hover:border-[rgba(0,240,255,0.3)]'}`}>
                  {v === 'graph' ? '⬡ Relationship Graph' : '⊞ Behavior Timeline'}
                </button>
              ))}
            </div>

            {view === 'graph' ? (
              <div className="hud-panel p-5 flex-1">
                <h4 className="text-sm font-display text-[var(--color-primary)] uppercase mb-3">Entity Relationship Map — click nodes to pivot</h4>
                <EntityGraph entity={results} onNodeClick={(q) => { setQuery(q); search(q); }}/>
                <div className="mt-3 text-[10px] font-mono text-[var(--color-muted)] text-center">
                  Center = {results.entity} · Outer nodes = related entities · Click to investigate
                </div>
              </div>
            ) : (
              <div className="hud-panel p-5 flex-1">
                <h4 className="text-sm font-display text-[var(--color-primary)] uppercase mb-4 flex items-center gap-2">
                  <Activity size={16}/> Behavior Timeline
                  <span className="text-[var(--color-muted)] text-[10px] font-mono">({results.related_events?.length || 0} events)</span>
                </h4>
                <div className="relative pl-6 border-l-2 border-[rgba(0,240,255,0.15)] space-y-3">
                  {results.related_events?.map((evt: any, i: number) => (
                    <div key={i} className="relative">
                      <div className={`absolute -left-[29px] top-3 w-3.5 h-3.5 rounded-full border-2 border-[#03060a] ${sevBg(evt.severity)}`}/>
                      <div onClick={() => setExpandedEvt(expandedEvt === i ? null : i)}
                        className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.05)] rounded p-3 hover:bg-[rgba(0,240,255,0.04)] transition-colors cursor-pointer">
                        <div className="flex justify-between items-start">
                          <div className="flex items-center gap-2">
                            {evt.severity === 'CRITICAL' && <ShieldAlert size={13} className="text-[#FF4444] flex-shrink-0"/>}
                            <span className="font-bold text-sm" style={{color: sevColor(evt.severity)}}>{evt.type}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono text-[var(--color-muted)]">{new Date(evt.timestamp).toLocaleString()}</span>
                            <ChevronDown size={12} className={`text-[var(--color-muted)] transition-transform ${expandedEvt===i?'rotate-180':''}`}/>
                          </div>
                        </div>
                        <div className="text-xs font-mono text-gray-400 mt-1">Source: {evt.source}</div>
                        {expandedEvt === i && (
                          <div className="mt-3 pt-3 border-t border-[rgba(255,255,255,0.05)]">
                            <div className="text-xs font-mono text-white bg-[rgba(0,0,0,0.4)] rounded p-2 mb-3">{evt.detail}</div>
                            <div className="flex gap-2">
                              {results.source_ip && (
                                <button onClick={e => { e.stopPropagation(); navigate(`/app/intel?ip=${results.source_ip}`); }}
                                  className="text-[10px] font-mono px-3 py-1 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.05)] transition-colors flex items-center gap-1">
                                  <Globe size={10}/> Threat Intel
                                </button>
                              )}
                              {results.type === 'Incident' && (
                                results.playbook ? (
                                  <button onClick={e => { e.stopPropagation(); navigate(`/app/response?playbook=${results.playbook}&entity=${results.entity}`); }}
                                    className="text-[10px] font-mono px-3 py-1 border border-[rgba(255,68,68,0.3)] text-[#FF4444] hover:bg-[rgba(255,68,68,0.05)] transition-colors flex items-center gap-1">
                                    <BookOpen size={10}/> Remediate
                                  </button>
                                ) : (
                                  <button onClick={e => { e.stopPropagation(); navigate(`/app/response?incident=${results.entity}`); }}
                                    className="text-[10px] font-mono px-3 py-1 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.05)] transition-colors flex items-center gap-1">
                                    <Plus size={10}/> Create Playbook
                                  </button>
                                )
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {!results.related_events?.length && (
                    <div className="text-[var(--color-muted)] font-mono text-sm py-6 text-center">No events on record for this entity.</div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {!results && !loading && (
        <div className="flex-1 flex flex-col items-center justify-center text-[var(--color-muted)] opacity-40">
          <Crosshair size={56} className="mb-4"/>
          <p className="font-display text-xl uppercase tracking-widest">Awaiting Entity Input</p>
          <p className="font-mono text-xs mt-2">Try: inc_101 · 192.168.1.46 · CORP\jsmith</p>
        </div>
      )}
    </div>
  );
};

export default Investigate;
