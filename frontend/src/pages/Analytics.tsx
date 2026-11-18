import React, { useEffect, useState, useMemo, useRef } from 'react';
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell, ScatterChart, Scatter,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, ZAxis
} from 'recharts';
import { getKpis, getAnomalies, getIncidents, exportReport, getIngestionStats, saveActiveDeviceFilter, isTestUser } from '../services/api';
import DataDrawer from '../components/DataDrawer'; import type { DrawerType } from '../components/DataDrawer';
import {
  Activity, Database, TrendingUp, BarChart3,
  Download, Filter, Maximize2, X, ChevronDown, CheckCircle
} from 'lucide-react';

// ── colour tokens ─────────────────────────────────────────────────────────────
const C = {
  critical: '#FF4444',
  high:     '#FF8C00',
  medium:   '#FFD700',
  low:      '#05FFA1',
  primary:  '#00F0FF',
  purple:   '#B026FF',
  blue:     '#4A9EFF',
  grid:     'rgba(255,255,255,0.06)',
  tooltip:  { backgroundColor: 'rgba(10,15,25,0.95)', border: '1px solid rgba(0,240,255,0.3)', borderRadius: 4 },
  tooltipLabel: { color: '#fff', fontFamily: 'monospace', fontSize: 12 },
};

const TICK_STYLE = { fill: '#8899aa', fontFamily: 'monospace', fontSize: 11 };

// ── deterministic "random" data seeded by index ───────────────────────────────
const seed = (i: number, base: number, spread: number) => {
  if (!isTestUser()) return 0;
  return base + Math.abs(Math.sin(i * 31.7 + 5.9) * spread);
};

// ── Drilldown Modal ───────────────────────────────────────────────────────────
const DrillModal: React.FC<{ data: any; onClose: () => void }> = ({ data, onClose }) => (
  <div
    className="fixed inset-0 bg-black/70 z-50 flex justify-center items-center backdrop-blur-sm"
    onClick={onClose}
  >
    <div
      className="bg-[#03060a] border border-[var(--color-primary)] shadow-[0_0_40px_rgba(0,240,255,0.15)] rounded p-6 max-w-lg w-full"
      onClick={e => e.stopPropagation()}
    >
      <div className="flex justify-between items-center border-b border-[rgba(0,240,255,0.2)] pb-4 mb-5">
        <h3 className="text-xl font-display text-[var(--color-primary)] flex items-center">
          <Filter size={18} className="mr-2" /> Drill-Down Detail
        </h3>
        <button onClick={onClose} className="text-[var(--color-muted)] hover:text-white text-2xl leading-none">&times;</button>
      </div>
      <div className="grid grid-cols-2 gap-3 mb-5">
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.06)] rounded p-3">
            <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1">{k}</div>
            <div className="text-white font-mono text-sm font-bold">{String(v)}</div>
          </div>
        ))}
      </div>
      <button onClick={onClose} className="w-full hud-button bg-[var(--color-primary)] text-black font-bold">
        Close
      </button>
    </div>
  </div>
);

// ── Expandable chart tile ─────────────────────────────────────────────────────
const Tile: React.FC<{ title: string; icon: React.ReactNode; children: React.ReactNode; h?: number }> = ({
  title, icon, children, h = 280
}) => {
  const [full, setFull] = useState(false);
  return (
    <>
      <div className="hud-panel p-5 flex flex-col h-full">
        <div className="flex items-center justify-between mb-3 shrink-0">
          <h3 className="font-display text-sm text-[var(--color-primary)] flex items-center gap-2 uppercase tracking-wider">
            {icon}{title}
          </h3>
          <button
            onClick={() => setFull(true)}
            className="p-1 text-[var(--color-muted)] hover:text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.08)] rounded transition-colors"
            title="Expand"
          >
            <Maximize2 size={14} />
          </button>
        </div>
        <div style={{ height: h }}>{children}</div>
      </div>

      {full && (
        <div
          className="fixed inset-0 z-50 bg-[rgba(3,6,10,0.97)] backdrop-blur-sm flex flex-col p-8"
          onClick={() => setFull(false)}
        >
          <div className="max-w-6xl w-full mx-auto flex flex-col flex-1" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6 border-b border-[rgba(0,240,255,0.2)] pb-4">
              <h2 className="text-2xl font-display text-[var(--color-primary)] flex items-center gap-3">
                {icon}{title}
              </h2>
              <button onClick={() => setFull(false)} className="text-[var(--color-muted)] hover:text-white">
                <X size={24} />
              </button>
            </div>
            <div className="flex-1">{children}</div>
          </div>
        </div>
      )}
    </>
  );
};

// ── KPI card ──────────────────────────────────────────────────────────────────
const KpiCard: React.FC<{ label: string; value: any; icon: React.ReactNode; detail: string; spark: number[] }> = ({
  label, value, icon, detail, spark
}) => {
  const [open, setOpen] = useState(false);
  const max = Math.max(...spark, 1);
  return (
    <div
      className="hud-panel p-5 relative overflow-hidden group cursor-pointer select-none"
      onClick={() => setOpen(o => !o)}
    >
      <div className="absolute right-0 top-0 p-4 opacity-10 text-[var(--color-primary)] scale-[2.5] origin-top-right group-hover:opacity-20 transition-opacity">
        {icon}
      </div>
      <span className="text-[10px] font-mono text-[var(--color-muted)] uppercase tracking-widest">{label}</span>
      <div className="flex items-baseline gap-2 mt-1">
        <span className="text-4xl font-display font-bold text-white">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
        <ChevronDown size={14} className={`text-[var(--color-primary)] transition-transform ${open ? 'rotate-180' : ''}`} />
      </div>
      {/* sparkline */}
      <div className="mt-3 flex items-end gap-px h-5">
        {spark.map((v, i) => (
          <div
            key={i}
            className="flex-1 bg-[var(--color-primary)] opacity-25 group-hover:opacity-50 transition-opacity rounded-sm"
            style={{ height: `${(v / max) * 100}%` }}
          />
        ))}
      </div>
      {open && (
        <p className="mt-3 pt-3 border-t border-[rgba(255,255,255,0.05)] text-xs font-mono text-gray-400 leading-relaxed">
          {detail}
        </p>
      )}
    </div>
  );
};

// ── Custom Tooltip ────────────────────────────────────────────────────────────
const CT: React.FC<any> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={C.tooltip} className="p-3 text-xs font-mono">
      <p style={C.tooltipLabel} className="mb-2 font-bold">{label}</p>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color }} className="flex justify-between gap-6">
          <span>{p.name}</span>
          <span className="font-bold">{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</span>
        </div>
      ))}
    </div>
  );
};

// ── Main Analytics ────────────────────────────────────────────────────────────
const Analytics = () => {
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [kpis, setKpis]           = useState<any>({});
  const [stats, setStats]         = useState<any>({});
  const [severity, setSeverity]   = useState('ALL');
  const [range, setRange]         = useState('24h');
  const [drill, setDrill]         = useState<any>(null);
  const [drawer, setDrawer]       = useState<{type: DrawerType, status?: string}|null>(null);
  const [tempIds, setTempIds]     = useState<string[]>([]);

  const applyFilter = () => {
    saveActiveDeviceFilter(tempIds);
    setDrawer(null);
  };

  useEffect(() => {
    const load = async () => {
      try {
        const [sRes, aRes, iRes, kRes] = await Promise.all([
          getIngestionStats(), getAnomalies(), getIncidents(), getKpis(),
        ]);
        if (sRes?.data) setStats(sRes.data);
        if (Array.isArray(aRes?.data)) setAnomalies(aRes.data);
        if (iRes?.data?.incidents) setIncidents(iRes.data.incidents);
        if (kRes?.data) setKpis(kRes.data);
      } catch { /* silently fallback to mock already in state */ }
    };
    load();
    const iv = setInterval(load, 5000);
    
    // Listen for manual status changes or filter updates
    const onStateChange = () => load();
    window.addEventListener('sentinel_state_change', onStateChange);

    return () => { 
      clearInterval(iv);
      window.removeEventListener('sentinel_state_change', onStateChange);
    };
  }, [range]);

  const deviceFilter = useMemo(() => {
    const user = localStorage.getItem('sentinel_username') || 'anon';
    const saved = localStorage.getItem(`sentinel_device_filter_${user}`);
    return saved ? new Set(JSON.parse(saved)) : null;
  }, []);

  const filteredAnomalies = useMemo(() => {
    let list = anomalies;
    if (deviceFilter && deviceFilter.size > 0) {
      list = list.filter(a => deviceFilter.has(a.device_id));
    }
    return severity === 'ALL' ? list : list.filter(a => a.severity_label === severity);
  }, [anomalies, severity, deviceFilter]);

  const filteredIncidents = useMemo(() => {
    if (!deviceFilter || deviceFilter.size === 0) return incidents;
    return incidents.filter(i => deviceFilter.has(i.device_id));
  }, [incidents, deviceFilter]);

  // ── Incident timeline (24 hourly buckets) ──────────────────────────────────
  const incTimeline = useMemo(() => {
    const isFiltered = deviceFilter && deviceFilter.size > 0;
    const isGlobalMock = !deviceFilter; // Only show global mock if user hasn't touched filter at all
    
    return Array.from({ length: 24 }, (_, i) => {
      const h = `${String(i).padStart(2, '0')}:00`;
      const base = filteredIncidents.filter(x => new Date(x.created_at).getHours() === i);
      const hasReal = base.length > 0;
      
      return {
        time: h,
        CRITICAL: hasReal ? base.filter(x => x.severity_label === 'CRITICAL').length : (isGlobalMock ? Math.round(seed(i, 1, 3)) : 0),
        HIGH:     hasReal ? base.filter(x => x.severity_label === 'HIGH').length     : (isGlobalMock ? Math.round(seed(i + 8, 3, 5)) : 0),
        MEDIUM:   hasReal ? base.filter(x => x.severity_label === 'MEDIUM').length   : (isGlobalMock ? Math.round(seed(i + 16, 5, 7)) : 0),
      };
    });
  }, [filteredIncidents, deviceFilter]);

  // ── Event + Anomaly timeline ───────────────────────────────────────────────
  const evTimeline = useMemo(() => {
    const isGlobalMock = !deviceFilter;
    const hasData = kpis && kpis.total_events_24h > 0;

    return Array.from({ length: 24 }, (_, i) => ({
      time: `-${24 - i}h`,
      Events:    hasData ? (kpis.total_events_24h / 24) : (isGlobalMock ? Math.round(seed(i, 1800, 3000)) : 0),
      Anomalies: hasData ? (kpis.total_anomalies_24h / 24) : (isGlobalMock ? Math.round(seed(i + 7, 12, 55)) : 0),
    }));
  }, [kpis, deviceFilter]);

  // ── Severity pie ───────────────────────────────────────────────────────────
  const sevPie = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    filteredAnomalies.forEach(a => { if (a.severity_label in c) (c as any)[a.severity_label]++; });
    const isGlobalMock = !deviceFilter;
    
    if (Object.values(c).every(v => v === 0) && isGlobalMock) return [
      { name: 'CRITICAL', value: 2,  color: C.critical },
      { name: 'HIGH',     value: 8,  color: C.high },
      { name: 'MEDIUM',   value: 15, color: C.medium },
      { name: 'LOW',      value: 5,  color: C.low },
    ];
    return Object.entries(c).filter(([,v]) => v > 0).map(([name, value]) => ({
      name, value,
      color: name === 'CRITICAL' ? C.critical : name === 'HIGH' ? C.high : name === 'MEDIUM' ? C.medium : C.low,
    }));
  }, [filteredAnomalies, deviceFilter]);

  // ── Top threat types ───────────────────────────────────────────────────────
  const threats = useMemo(() => {
    const c: Record<string, number> = {};
    filteredAnomalies.forEach(a => { if (a.threat_type) c[a.threat_type] = (c[a.threat_type] || 0) + 1; });
    const isGlobalMock = !deviceFilter;
    if (!Object.keys(c).length && isGlobalMock) return [
      { name: 'Brute Force',          count: 18 },
      { name: 'C2 Outbound',          count: 12 },
      { name: 'Privilege Escalation', count: 9  },
      { name: 'Lateral Movement',     count: 7  },
      { name: 'Ransomware',           count: 4  },
      { name: 'Port Scan',            count: 3  },
      { name: 'Data Exfil',           count: 2  },
    ];
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([name, count]) => ({ name, count }));
  }, [filteredAnomalies, deviceFilter]);

  // ── Anomaly scatter ────────────────────────────────────────────────────────
  const scatter = useMemo(() => {
    const isGlobalMock = !deviceFilter;
    if (filteredAnomalies.length === 0 && !isGlobalMock) return [];
    
    return filteredAnomalies.map((a, i) => ({
      x: i,
      y: a.severity_score ?? parseFloat(seed(i, 0.2, 0.75).toFixed(2)),
      label: a.threat_type || 'Unknown',
      severity: a.severity_label,
    }));
  }, [filteredAnomalies, deviceFilter]);

  const handleExport = async () => {
    try {
      const res = await exportReport();
      if (!res) return;
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url; link.download = 'lsadra_report.pdf';
      document.body.appendChild(link); link.click(); link.remove();
    } catch (err) {
      window.alert(`Report export failed: ${(err as Error)?.message || 'the API did not answer'}`);
    }
  };

  const openDrill = (payload: any, extra: object) => {
    if (payload?.activePayload?.length) {
      const p = payload.activePayload[0];
      setDrill({ ...extra, value: p.value, name: p.name, time: payload.activeLabel });
    }
  };

  // ── Pie label ─────────────────────────────────────────────────────────────
  const PieLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, name, percent }: any) => {
    const RADIAN = Math.PI / 180;
    const r  = innerRadius + (outerRadius - innerRadius) * 1.35;
    const x  = cx + r * Math.cos(-midAngle * RADIAN);
    const y  = cy + r * Math.sin(-midAngle * RADIAN);
    return (
      <text x={x} y={y} fill="#aaa" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central" style={{ fontSize: 10, fontFamily: 'monospace' }}>
        {name} {(percent * 100).toFixed(0)}%
      </text>
    );
  };

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      {drawer && <DataDrawer type={drawer.type} statusFilter={drawer.status} onClose={()=>setDrawer(null)} incidents={incidents} anomalies={anomalies} defaultTime={range}/>}

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className="flex justify-between items-end border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Analytics</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">
            Click any chart point or tile to drill down. Use filters to narrow data.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {[
            { val: severity, set: setSeverity, opts: [['ALL','All Sev.'],['CRITICAL','Critical'],['HIGH','High'],['MEDIUM','Medium'],['LOW','Low']] },
            { val: range,    set: setRange,    opts: [['1h','1 Hour'],['24h','24 Hours'],['7d','7 Days'],['30d','30 Days']] },
          ].map((sel, si) => (
            <div key={si} className="flex items-center bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.3)] rounded px-3 py-1.5 gap-2">
              <Filter size={13} className="text-[var(--color-primary)]" />
              <select value={sel.val} onChange={e => sel.set(e.target.value)} className="bg-transparent text-white font-mono text-xs outline-none cursor-pointer">
                {sel.opts.map(([v, l]) => <option key={v} value={v} className="bg-gray-900 text-white">{l}</option>)}
              </select>
            </div>
          ))}

          <button onClick={handleExport} className="hud-button flex items-center gap-2 bg-[var(--color-primary)] text-black text-xs font-bold">
            <Download size={13} /> SOC Report
          </button>
        </div>
      </header>



      {/* ── KPI tiles ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-4 shrink-0">
        <div onClick={()=>setDrawer({type:'events'})} className="cursor-pointer hover:ring-1 hover:ring-[var(--color-primary)] transition-all rounded">
          <KpiCard label="Events (24h)" value={kpis?.total_events_24h ?? 0} icon={<Database size={20}/>}
            detail={`EPS: ${stats?.events_per_second?.toFixed(1)??0} · Click to view stream →`}
            spark={Array.from({length:14},(_,i)=>seed(i,600,800))} />
        </div>
        <div onClick={()=>setDrawer({type:'anomalies'})} className="cursor-pointer hover:ring-1 hover:ring-[#FF4444] transition-all rounded">
          <KpiCard label="Anomalies (24h)" value={kpis?.total_anomalies_24h ?? 0} icon={<Activity size={20}/>}
            detail={`Critical: ${sevPie.find(s=>s.name==='CRITICAL')?.value??0} · Click to view log →`}
            spark={Array.from({length:14},(_,i)=>seed(i+3,20,60))} />
        </div>
        <div onClick={()=>setDrawer({type:'incidents', status:'OPEN'})} className="cursor-pointer hover:ring-1 hover:ring-[#FF8C00] transition-all rounded">
          <KpiCard label="Open Incidents" value={kpis?.open_incidents ?? 0} icon={<TrendingUp size={20}/>}
            detail="Click to view all incidents with filters →"
            spark={Array.from({length:14},(_,i)=>seed(i+9,2,10))} />
        </div>
        <div onClick={()=>setDrawer({type:'incidents', status:'RESOLVED'})} className="cursor-pointer hover:ring-1 hover:ring-[#05FFA1] transition-all rounded">
          <KpiCard label="Closed Incidents" value={kpis?.closed_incidents ?? 0} icon={<CheckCircle size={20}/>}
            detail="Remediated via playbook response."
            spark={Array.from({length:14},(_,i)=>seed(i+12,1,5))} />
        </div>
        <KpiCard label="Active Devices" value={deviceFilter && deviceFilter.size > 0 ? deviceFilter.size : (kpis?.active_devices ?? 0)} icon={<BarChart3 size={20}/>}
          detail={deviceFilter && deviceFilter.size > 0 ? `Filtering ${deviceFilter.size} selected devices.` : "Sources tab shows per-device breakdown."}
          spark={Array.from({length:14},(_,i)=>seed(i+5,30,10))} />
      </div>

      {/* ── Row: Incident Timeline + Severity Pie ───────────────────────── */}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-8">
          <Tile title="Incident Timeline — 24h" icon={<TrendingUp size={15}/>} h={280}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={incTimeline} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}
                onClick={p => openDrill(p, { chart: 'Incident Timeline' })}>
                <defs>
                  {[['crit',C.critical],['high',C.high],['med',C.medium]].map(([id,col]) => (
                    <linearGradient key={id} id={`g-${id}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={col} stopOpacity={0.4}/>
                      <stop offset="95%" stopColor={col} stopOpacity={0}/>
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={C.grid} vertical={false}/>
                <XAxis dataKey="time" stroke="#555" tick={TICK_STYLE} interval={3} dy={8}/>
                <YAxis stroke="#555" tick={TICK_STYLE} dx={-4}/>
                <Tooltip content={<CT/>}/>
                <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11, fontFamily: 'monospace', paddingTop: 8 }}/>
                <Area type="monotone" dataKey="CRITICAL" stroke={C.critical} fill="url(#g-crit)" strokeWidth={2} dot={false}/>
                <Area type="monotone" dataKey="HIGH"     stroke={C.high}     fill="url(#g-high)" strokeWidth={2} dot={false}/>
                <Area type="monotone" dataKey="MEDIUM"   stroke={C.medium}   fill="url(#g-med)"  strokeWidth={2} dot={false}/>
              </AreaChart>
            </ResponsiveContainer>
          </Tile>
        </div>

        <div className="col-span-4">
          <Tile title="Severity Distribution" icon={<Activity size={15}/>} h={280}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={sevPie}
                  cx="50%" cy="45%"
                  innerRadius="40%" outerRadius="60%"
                  paddingAngle={3}
                  dataKey="value"
                  labelLine={false}
                  label={PieLabel}
                  onClick={d => setDrill({ chart: 'Severity', severity: d.name, count: d.value })}
                >
                  {sevPie.map((e, i) => <Cell key={i} fill={e.color}/>)}
                </Pie>
                <Tooltip content={<CT/>}/>
              </PieChart>
            </ResponsiveContainer>
          </Tile>
        </div>
      </div>

      {/* ── Event & Anomaly Timeline ─────────────────────────────────────── */}
      <Tile title="Event & Anomaly Timeline" icon={<Activity size={15}/>} h={260}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={evTimeline} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}
            onClick={p => openDrill(p, { chart: 'Event/Anomaly Timeline' })}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.grid} vertical={false}/>
            <XAxis dataKey="time" stroke="#555" tick={TICK_STYLE} interval={3} dy={8}/>
            <YAxis yAxisId="ev" stroke="#555" tick={TICK_STYLE} dx={-4}/>
            <YAxis yAxisId="an" orientation="right" stroke="#555" tick={TICK_STYLE} dx={4}/>
            <Tooltip content={<CT/>}/>
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11, fontFamily: 'monospace', paddingTop: 8 }}/>
            <Line yAxisId="ev" type="monotone" dataKey="Events"    stroke={C.blue}   strokeWidth={2} dot={false}/>
            <Line yAxisId="an" type="monotone" dataKey="Anomalies" stroke={C.high}   strokeWidth={2} dot={{ r: 3, fill: C.high }} strokeDasharray="4 2"/>
          </LineChart>
        </ResponsiveContainer>
      </Tile>

      {/* ── Top Threats + Scatter ────────────────────────────────────────── */}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-7">
          <Tile title="Top Threat Types" icon={<BarChart3 size={15}/>} h={280}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threats} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
                onClick={(p: any) => p?.activePayload && setDrill({ chart: 'Threat Type', name: p.activePayload[0]?.payload?.name, count: p.activePayload[0]?.value })}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.grid} horizontal={false}/>
                <XAxis type="number" stroke="#555" tick={TICK_STYLE}/>
                <YAxis type="category" dataKey="name" stroke="#555" tick={TICK_STYLE} width={160}/>
                <Tooltip content={<CT/>}/>
                <Bar dataKey="count" fill={C.purple} radius={[0, 4, 4, 0]} maxBarSize={20}/>
              </BarChart>
            </ResponsiveContainer>
          </Tile>
        </div>

        <div className="col-span-5">
          <Tile title="Anomaly Score vs Index" icon={<Activity size={15}/>} h={280}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.grid}/>
                <XAxis dataKey="x" name="Index" stroke="#555" tick={TICK_STYLE} label={{ value: 'Event #', position: 'insideBottom', offset: -10, fill: '#666', fontSize: 10 }}/>
                <YAxis dataKey="y" name="Score"  stroke="#555" tick={TICK_STYLE} domain={[0, 1]}/>
                <ZAxis range={[40, 80]}/>
                <Tooltip cursor={{ strokeDasharray: '3 3' }} content={({ payload }) => {
                  if (!payload?.length) return null;
                  const d = payload[0]?.payload;
                  return (
                    <div style={C.tooltip} className="p-3 text-xs font-mono">
                      <p className="text-white font-bold mb-1">{d?.label}</p>
                      <p style={{ color: d?.severity === 'CRITICAL' ? C.critical : d?.severity === 'HIGH' ? C.high : C.medium }}>
                        {d?.severity} — Score: {d?.y?.toFixed(2)}
                      </p>
                    </div>
                  );
                }}/>
                {/* one scatter series per severity so we get different colours */}
                {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(sev => (
                  <Scatter
                    key={sev}
                    name={sev}
                    data={scatter.filter(d => d.severity === sev)}
                    fill={sev === 'CRITICAL' ? C.critical : sev === 'HIGH' ? C.high : sev === 'MEDIUM' ? C.medium : C.low}
                    onClick={(d: any) => setDrill({ chart: 'Anomaly Scatter', severity: d.severity, score: d.y, label: d.label })}
                  />
                ))}
                <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11, fontFamily: 'monospace', paddingTop: 8 }}/>
              </ScatterChart>
            </ResponsiveContainer>
          </Tile>
        </div>
      </div>

      {/* ── Drilldown modal ──────────────────────────────────────────────── */}
      {drill && <DrillModal data={drill} onClose={() => setDrill(null)}/>}
    </div>
  );
};

export default Analytics;
