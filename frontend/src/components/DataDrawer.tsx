import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { generateEventStream, getActiveDeviceFilter, getEvents, isTestUser } from '../services/api';
import { X, Search, Download, Crosshair, ChevronDown } from 'lucide-react';

export type DrawerType = 'events' | 'threats' | 'incidents' | 'anomalies';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#FF4444', HIGH: '#FF8C00', MEDIUM: '#FFD700', LOW: '#05FFA1',
};

const TITLES: Record<string, string> = {
  events: 'Events Stream', threats: 'Active Threats / Anomalies',
  incidents: 'Open Incidents', anomalies: 'Anomaly Log',
};

const PAGE_SIZE = 100;

interface Props {
  type: DrawerType;
  statusFilter?: string;
  onClose: () => void;
  incidents?: any[];
  anomalies?: any[];
  /** pre-filtered time range label, e.g. "24h" */
  defaultTime?: string;
}

const DataDrawer: React.FC<Props> = ({ type, statusFilter, onClose, incidents = [], anomalies = [], defaultTime = '24h' }) => {
  const navigate = useNavigate();
  const isTest = isTestUser();
  const [search,  setSearch]  = useState('');
  const [sevF,    setSevF]    = useState('All');
  const [timeF,   setTimeF]   = useState(defaultTime);
  const [srcF,    setSrcF]    = useState('');
  const [typeF,   setTypeF]   = useState('All');
  const [page,    setPage]    = useState(1);
  const [events,  setEvents]  = useState<any[]>([]);
  const bodyRef = useRef<HTMLDivElement>(null);
  const df = getActiveDeviceFilter();

  const title = statusFilter === 'RESOLVED' ? 'Closed Incidents' : statusFilter === 'OPEN' ? 'Open Incidents' : TITLES[type];

  // Regenerate event stream whenever time filter changes; count driven by live counter
  useEffect(() => {
    const hrs = timeF === '1h' ? 1 : timeF === '6h' ? 6 : timeF === '7d' ? 168 : timeF === '30d' ? 720 : 24;
    
    if (isTest) {
      // Generate enough rows to fill up to 30d worth at ~4200 eps — use capped max for perf
      const wantCount = Math.min(hrs * 3600 * 4200 / 8000, 50000); // scale but cap at 50k for browser
      const stream = generateEventStream(Math.round(wantCount), df);
      setEvents(stream.filter(e => (Date.now() - new Date(e.timestamp).getTime()) < hrs * 3600000));
    } else {
      // Fetch real events for non-test users
      getEvents(2000).then(res => {
        if (Array.isArray(res?.data)) {
          setEvents(res.data.map((e: any) => ({
            timestamp: e.timestamp,
            severity: e.severity_label || 'INFO',
            type: e.event_type || 'Unknown',
            source_ip: e.source_ip || '—',
            source: e.hostname || '—',
            detail: e.raw_message || '—'
          })));
        }
      });
    }
    setPage(1);
  }, [timeF, isTest]);

  // Filtered rows for events
  const filteredEvents = events.filter(e =>
    (sevF === 'All' || e.severity === sevF) &&
    (!srcF || e.source_ip.includes(srcF)) &&
    (typeF === 'All' || e.type === typeF) &&
    (!search || e.type.toLowerCase().includes(search.toLowerCase()) || e.source_ip.includes(search))
  );

  // Filtered rows for threats/incidents
  const threatRows = (type === 'incidents' ? incidents : (type === 'threats' ? [...anomalies, ...incidents] : anomalies)).filter(r =>
    (sevF === 'All' || (r.severity_label || r.severity) === sevF) &&
    (!srcF || (r.source_ip || '').includes(srcF)) &&
    (!statusFilter || r.status === statusFilter) &&
    (!search ||
      (r.threat_type || r.attack_type || '').toLowerCase().includes(search.toLowerCase()) ||
      (r.source_ip || '').includes(search) ||
      (r.id || '').toLowerCase().includes(search.toLowerCase())
    )
  );

  const isEvents = type === 'events';
  const allRows  = isEvents ? filteredEvents : threatRows;
  const pageRows = allRows.slice(0, page * PAGE_SIZE);
  const hasMore  = pageRows.length < allRows.length;

  const loadMore = useCallback(() => setPage(p => p + 1), []);

  // Infinite scroll
  const onScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 120 && hasMore) loadMore();
  };

  const uniqueTypes = [...new Set(events.map(e => e.type))].sort();

  const csvExport = () => {
    if (!allRows.length) return;
    const hdr = Object.keys(allRows[0]).join(',');
    const body = allRows.map(r => Object.values(r).map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
    const blob = new Blob([hdr + '\n' + body], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `lsadra_${type}_${timeF}.csv`;
    a.click();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-start justify-end" onClick={onClose}>
      <div
        className="h-full w-full max-w-5xl bg-[#03060a] border-l border-[rgba(0,240,255,0.3)] shadow-[0_0_60px_rgba(0,240,255,0.08)] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[rgba(0,240,255,0.15)] shrink-0">
          <div>
            <h3 className="font-display text-xl text-[var(--color-primary)] uppercase tracking-widest">{title}</h3>
            <p className="text-xs font-mono text-[var(--color-muted)] mt-0.5">
              {allRows.length.toLocaleString()} records
              {df ? (df.length > 0 ? ` · Filter: ${df.join(', ')}` : ' · Filter: No Devices Selected (All Hidden)') : ''}
              {' · '}Showing {pageRows.length.toLocaleString()} · infinite scroll
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={csvExport}
              className="flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.06)] transition-colors">
              <Download size={12}/> Export CSV ({allRows.length.toLocaleString()})
            </button>
            <button onClick={onClose} className="text-[var(--color-muted)] hover:text-white p-1">
              <X size={18}/>
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="px-6 py-3 border-b border-[rgba(255,255,255,0.05)] grid grid-cols-5 gap-3 shrink-0 bg-[rgba(0,0,0,0.3)]">
          <div className="relative col-span-2">
            <Search size={13} className="absolute left-3 top-2.5 text-[var(--color-muted)]"/>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search type, IP, ID…"
              className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono pl-8 pr-3 py-2 focus:outline-none focus:border-[var(--color-primary)]"/>
          </div>
          {isEvents && (
            <select value={timeF} onChange={e => setTimeF(e.target.value)}
              className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
              {['1h','6h','24h','7d','30d'].map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          )}
          <select value={sevF} onChange={e => setSevF(e.target.value)}
            className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
            {['All','CRITICAL','HIGH','MEDIUM','LOW'].map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          {isEvents && (
            <select value={typeF} onChange={e => setTypeF(e.target.value)}
              className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
              {['All', ...uniqueTypes.slice(0, 14)].map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          )}
          <input value={srcF} onChange={e => setSrcF(e.target.value)} placeholder="Source IP…"
            className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]"/>
        </div>

        {/* Table body with infinite scroll */}
        <div ref={bodyRef} className="flex-1 overflow-y-auto custom-scrollbar" onScroll={onScroll}>
          {isEvents ? (
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-[rgba(3,6,10,0.99)] border-b border-[rgba(0,240,255,0.15)] text-[10px] text-[var(--color-muted)] uppercase z-10">
                <tr>
                  {['#','Time','Severity','Type','Source IP','Source','Detail'].map(h => (
                    <th key={h} className="p-3 font-normal text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageRows.map((r, i) => (
                  <tr key={i} onClick={() => navigate(`/app/investigate?entity=${r.source_ip}`)}
                    className="border-b border-[rgba(255,255,255,0.03)] hover:bg-[rgba(0,240,255,0.04)] cursor-pointer transition-colors">
                    <td className="p-3 text-[var(--color-muted)] select-none">{(i + 1).toLocaleString()}</td>
                    <td className="p-3 text-[var(--color-muted)]">{r.timestamp.substring(0, 19).replace('T', ' ')}</td>
                    <td className="p-3">
                      <span className="font-bold" style={{ color: SEV_COLORS[r.severity] || '#aaa' }}>{r.severity}</span>
                    </td>
                    <td className="p-3 text-white">{r.type}</td>
                    <td className="p-3 text-[var(--color-primary)]">{r.source_ip}</td>
                    <td className="p-3 text-[var(--color-muted)]">{r.source}</td>
                    <td className="p-3 text-gray-500 truncate max-w-xs">{r.detail}</td>
                  </tr>
                ))}
                {hasMore && (
                  <tr>
                    <td colSpan={7} className="text-center py-4">
                      <button onClick={loadMore}
                        className="text-xs font-mono text-[var(--color-primary)] border border-[rgba(0,240,255,0.3)] px-6 py-2 hover:bg-[rgba(0,240,255,0.06)] transition-colors flex items-center gap-2 mx-auto">
                        <ChevronDown size={13}/> Load more ({(allRows.length - pageRows.length).toLocaleString()} remaining)
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          ) : (
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-[rgba(3,6,10,0.99)] border-b border-[rgba(0,240,255,0.15)] text-[10px] text-[var(--color-muted)] uppercase z-10">
                <tr>
                  {['#','ID','Severity','Type / Attack','Source IP','Score / Status','Time',''].map(h => (
                    <th key={h} className="p-3 font-normal text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageRows.map((r, i) => (
                  <tr key={i} onClick={() => navigate(`/app/investigate?entity=${r.source_ip || r.id}`)}
                    className="border-b border-[rgba(255,255,255,0.03)] hover:bg-[rgba(0,240,255,0.04)] cursor-pointer transition-colors">
                    <td className="p-3 text-[var(--color-muted)] select-none">{(i + 1).toLocaleString()}</td>
                    <td className="p-3 text-[var(--color-muted)]">{r.id}</td>
                    <td className="p-3">
                      <span className="font-bold" style={{ color: SEV_COLORS[r.severity_label || r.severity] || '#aaa' }}>
                        {r.severity_label || r.severity}
                      </span>
                    </td>
                    <td className="p-3 text-white">{r.threat_type || r.attack_type || r.type}</td>
                    <td className="p-3 text-[var(--color-primary)]">{r.source_ip}</td>
                    <td className="p-3 text-[var(--color-muted)]">
                      {r.severity_score?.toFixed(2) || r.status || '—'}
                    </td>
                    <td className="p-3 text-[var(--color-muted)]">
                      {String(r.created_at || '').substring(11, 19)}
                    </td>
                    <td className="p-3">
                      <span className="text-[var(--color-primary)] flex items-center gap-1">
                        <Crosshair size={10}/> Investigate
                      </span>
                    </td>
                  </tr>
                ))}
                {hasMore && (
                  <tr>
                    <td colSpan={8} className="text-center py-4">
                      <button onClick={loadMore}
                        className="text-xs font-mono text-[var(--color-primary)] border border-[rgba(0,240,255,0.3)] px-6 py-2 hover:bg-[rgba(0,240,255,0.06)] transition-colors flex items-center gap-2 mx-auto">
                        <ChevronDown size={13}/> Load more ({(allRows.length - pageRows.length).toLocaleString()} remaining)
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-2 border-t border-[rgba(255,255,255,0.05)] text-[10px] font-mono text-[var(--color-muted)] shrink-0 flex justify-between">
          <span>Showing {pageRows.length.toLocaleString()} / {allRows.length.toLocaleString()} records</span>
          <span>Scroll to load more · Click row → Entity Investigation</span>
        </div>
      </div>
    </div>
  );
};

export default DataDrawer;
