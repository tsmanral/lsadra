import React, { useEffect, useState, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { getIncidents, getIngestionStats, getAnomalies, getKpis, isTestUser } from '../services/api';
import { subscribeAlerts, alertAsAnomaly } from '../services/alertStream';
import type { AlertStreamStatus } from '../services/alertStream';
import { ShieldAlert, Activity, Cpu, Crosshair, Zap, Globe, ChevronDown, Search } from 'lucide-react';
import DataDrawer from '../components/DataDrawer'; import type { DrawerType } from '../components/DataDrawer';


// ── KPI Tile ──────────────────────────────────────────────────────────────────
const KpiTile: React.FC<{label:string;value:any;color?:string;sub?:string;onClick?:()=>void;pulse?:boolean}> = ({label,value,color='var(--color-primary)',sub,onClick,pulse}) => (
  <div onClick={onClick} className={`hud-panel p-4 ${onClick?'cursor-pointer hover:bg-[rgba(0,240,255,0.06)] transition-colors group':''} relative overflow-hidden`}>
    {pulse && <span className="absolute top-3 right-3 w-2 h-2 rounded-full bg-[#05FFA1] animate-pulse"/>}
    {onClick && <ChevronDown size={12} className="absolute bottom-3 right-3 text-[var(--color-muted)] group-hover:text-[var(--color-primary)] transition-colors"/>}
    <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1">{label}</div>
    <div className="text-3xl font-display font-bold" style={{color}}>{typeof value==='number'?value.toLocaleString():value}</div>
    {sub && <div className="text-[10px] font-mono text-[var(--color-muted)] mt-1">{sub}</div>}
  </div>
);

// ── Main Page ─────────────────────────────────────────────────────────────────
const CommandCenter = () => {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<any[]>([]);
  const [stats,     setStats]     = useState<any>({});
  const [kpis,      setKpis]      = useState<any>({});
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [streamStatus, setStreamStatus] = useState<AlertStreamStatus>('connecting');
  const [drawer, setDrawer] = useState<{type: DrawerType, status?: string}|null>(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    // Alerts arrive over /ws/alerts. REST fills the list on load, after each
    // (re)connect, and every few seconds while the socket is down.
    const loadAnomalies = async () => {
      try {
        const aR = await getAnomalies();
        if (alive.current && Array.isArray(aR?.data)) setAnomalies(aR.data);
      } catch{ /* keep what is shown */ }
    };
    // Incidents, KPIs and ingestion health have no push channel yet.
    const loadSummary = async () => {
      if (!alive.current) return;
      try {
        const [iR, sR, kR] = await Promise.all([getIncidents(), getIngestionStats(), getKpis()]);
        if (!alive.current) return;
        if (iR?.data?.incidents) setIncidents(iR.data.incidents.slice(0,15)); // Increased to 15
        if (sR?.data)            setStats(sR.data);
        if (kR?.data)            setKpis(kR.data);
      } catch{ /* keep what is shown */ }
    };

    let streamLive = false;
    let summaryTimer: ReturnType<typeof setTimeout> | undefined;
    const unsubscribe = subscribeAlerts({
      onStatus: (status) => { streamLive = status === 'live'; setStreamStatus(status); },
      onResync: () => { loadAnomalies(); loadSummary(); },
      onAlert: (alert) => {
        const row = alertAsAnomaly(alert);
        setAnomalies(prev => [row, ...prev.filter(a => row.id == null || a.id !== row.id)].slice(0, 50));
        // A new alert usually moves the counts; refresh them once a burst settles.
        clearTimeout(summaryTimer);
        summaryTimer = setTimeout(loadSummary, 1000);
      },
    });

    loadAnomalies();
    loadSummary();
    const summaryIv = setInterval(loadSummary, 10000);
    // The demo account's alerts are generated client-side, so it keeps polling.
    const fallbackIv = setInterval(() => { if (!streamLive || isTestUser()) loadAnomalies(); }, 5000);

    // Listen for manual status changes or filter updates
    const onStateChange = () => { loadAnomalies(); loadSummary(); };
    window.addEventListener('sentinel_state_change', onStateChange);

    return () => {
      alive.current = false;
      unsubscribe();
      clearTimeout(summaryTimer);
      clearInterval(summaryIv);
      clearInterval(fallbackIv);
      window.removeEventListener('sentinel_state_change', onStateChange);
    };
  }, []);

  const [deviceFilter, setDeviceFilter] = useState<Set<string>|null>(null);

  useEffect(() => {
    const h = () => {
      const user = localStorage.getItem('sentinel_username') || 'anon';
      const saved = localStorage.getItem(`sentinel_device_filter_${user}`);
      setDeviceFilter(saved ? new Set(JSON.parse(saved)) : null);
    };
    window.addEventListener('sentinel_state_change', h);
    h();
    return () => window.removeEventListener('sentinel_state_change', h);
  }, []);

  const filteredIncidents = useMemo(() => {
    if (!deviceFilter || deviceFilter.size === 0) return incidents;
    return incidents.filter(i => deviceFilter.has(i.device_id));
  }, [incidents, deviceFilter]);

  const filteredAnomalies = useMemo(() => {
    if (!deviceFilter || deviceFilter.size === 0) return anomalies;
    return anomalies.filter(a => deviceFilter.has(a.device_id));
  }, [anomalies, deviceFilter]);

  const filteredFeed = useMemo(() => filteredAnomalies.slice(0,14), [filteredAnomalies]);

  const sevStyle = (s:string) => s==='CRITICAL'?'bg-[#FF4444] text-black font-bold':s==='HIGH'?'bg-[#FF8C00] text-black font-bold':'border border-[rgba(255,255,255,0.2)] text-[var(--color-muted)]';
  const feedColor= (s:string) => s==='CRITICAL'?'text-[#FF4444]':s==='HIGH'?'text-[#FF8C00]':'text-[#FFD700]';

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pr-2 pb-10 custom-scrollbar">
      {drawer && <DataDrawer type={drawer.type} statusFilter={drawer.status} onClose={()=>setDrawer(null)} incidents={incidents} anomalies={anomalies}/>}

      <header className="flex justify-between items-end border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Command Center</h2>
          <p className="text-[var(--color-primary)] font-mono text-sm mt-1">SOC_OVERVIEW_HUD · {streamStatus==='live' ? 'Alerts streaming live' : streamStatus==='connecting' ? 'Connecting to alert stream…' : 'Alert stream offline, retrying'} · Click tiles to drill down</p>
        </div>
        <div className="text-right">
          <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase">System Status</div>
          <div className={`text-lg font-bold font-display ${stats?.status==='HEALTHY'?'text-[var(--color-safe)]':'text-[var(--color-critical)]'}`}>
            {stats?.status || 'CONNECTING…'}
          </div>
        </div>
      </header>

      {/* KPI Tiles */}
      <div className="grid grid-cols-5 gap-4 shrink-0">
        <KpiTile label="Total Events 24h" value={kpis?.total_events_24h??0} color="var(--color-primary)" pulse
          sub={`${stats?.events_per_second?.toFixed(0)??0} evt/s · ${stats?.avg_latency_ms?.toFixed(1)??0}ms`}
          onClick={()=>setDrawer({type:'events'})}/>
        <KpiTile label="Active Threats" value={kpis?.total_anomalies_24h??0} color="#FF4444"
          sub={`${incidents.filter(i=>i.severity_label==='CRITICAL').length} critical · ${kpis?.open_incidents??0} open`}
          onClick={()=>setDrawer({type:'threats'})}/>
        <KpiTile label="Open Incidents" value={kpis?.open_incidents??0} color="#FF8C00"
          sub="Requires investigation"
          onClick={()=>setDrawer({type:'incidents', status:'OPEN'})}/>
        <KpiTile label="Closed Incidents" value={kpis?.closed_incidents??0} color="#05FFA1"
          sub="Remediated via playbook"
          onClick={()=>setDrawer({type:'incidents', status:'RESOLVED'})}/>
        <KpiTile label="Active Devices" value={deviceFilter && deviceFilter.size > 0 ? deviceFilter.size : (kpis?.active_devices??0)} color="#00F0FF"
          sub={deviceFilter && deviceFilter.size > 0 ? `Filtering ${deviceFilter.size} devices` : "Sending telemetry"}/>
      </div>

      <div className="grid grid-cols-12 gap-5 flex-1">
        {/* Incidents table */}
        <div className="col-span-8">
          <div className="hud-panel p-5 h-full flex flex-col">
            <h3 className="font-display text-lg text-[var(--color-primary)] mb-4 flex items-center gap-2 shrink-0">
              <ShieldAlert size={20}/> Top Active Incidents
              <span className="text-xs font-mono text-[var(--color-muted)]">(click row → Investigate)</span>
              <button onClick={()=>setDrawer({type:'incidents'})} className="ml-auto text-xs font-mono border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] px-3 py-1 hover:bg-[rgba(0,240,255,0.06)] transition-colors">
                View All
              </button>
            </h3>
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left">
                <thead className="text-[10px] font-mono text-[var(--color-muted)] border-b border-[rgba(0,240,255,0.2)]">
                  <tr>{['ID','Severity','Source IP','Attack Type','Playbook','Status','Action'].map(h=><th key={h} className="pb-3 px-2 font-normal">{h}</th>)}</tr>
                </thead>
                <tbody className="text-sm font-mono text-gray-300">
                  {/* Critical & High with Playbooks */}
                  <tr className="bg-[rgba(255,68,68,0.08)] border-b border-[rgba(255,68,68,0.2)]"><td colSpan={7} className="py-2 px-2 text-[10px] font-bold text-[#FF4444] uppercase tracking-wider">High Priority — Action Required</td></tr>
                  {filteredIncidents.filter(i => (i.severity_label==='CRITICAL'||i.severity_label==='HIGH') && i.status !== 'RESOLVED').map(inc=>(
                    <tr key={inc.id} onClick={()=>navigate(`/app/investigate?incident=${inc.id}`)}
                      className="border-b border-[rgba(255,68,68,0.1)] bg-[rgba(255,68,68,0.02)] hover:bg-[rgba(255,68,68,0.08)] cursor-pointer group transition-colors">
                      <td className="py-3 px-2 text-[var(--color-muted)] text-xs font-bold text-[#FF4444]">{inc.id}</td>
                      <td className="py-3 px-2"><span className={`px-2 py-0.5 text-[10px] rounded-sm ${sevStyle(inc.severity_label)}`}>{inc.severity_label}</span></td>
                      <td className="py-3 px-2 text-white">{inc.source_ip}</td>
                      <td className="py-3 px-2 text-[var(--color-primary)]">{inc.attack_type}</td>
                      <td className="py-3 px-2">
                        {inc.playbook ? (
                          <button onClick={(e) => { e.stopPropagation(); navigate(`/app/response?incident=${inc.id}&playbook=${inc.playbook}`); }}
                            className="text-[10px] text-[#05FFA1] flex items-center gap-1 hover:underline">
                            <Zap size={10}/> Available
                          </button>
                        ) : (
                          <button onClick={(e) => { e.stopPropagation(); navigate(`/app/response?incident=${inc.id}&mode=create`); }} 
                            className="text-[10px] text-[var(--color-muted)] hover:text-white underline">
                            Create
                          </button>
                        )}
                      </td>
                      <td className="py-3 px-2"><span className="text-[10px] px-2 py-0.5 border border-[#FF8C00] text-[#FF8C00]">{inc.status}</span></td>
                      <td className="py-3 px-2"><span className="flex items-center gap-1 text-xs text-[#FF4444] font-bold"><Crosshair size={13}/> Respond</span></td>
                    </tr>
                  ))}
                  
                  {/* Other Open */}
                  <tr className="bg-[rgba(0,240,255,0.05)] border-b border-[rgba(0,240,255,0.1)]"><td colSpan={7} className="py-2 px-2 text-[10px] font-bold text-[var(--color-primary)] uppercase tracking-wider">Active Investigations</td></tr>
                  {filteredIncidents.filter(i => !(i.severity_label==='CRITICAL'||i.severity_label==='HIGH') && i.status !== 'RESOLVED').map(inc=>(
                    <tr key={inc.id} onClick={()=>navigate(`/app/investigate?incident=${inc.id}`)}
                      className="border-b border-[rgba(255,255,255,0.05)] hover:bg-[rgba(0,240,255,0.08)] cursor-pointer group transition-colors">
                      <td className="py-3 px-2 text-[var(--color-muted)] text-xs">{inc.id}</td>
                      <td className="py-3 px-2"><span className={`px-2 py-0.5 text-[10px] rounded-sm ${sevStyle(inc.severity_label)}`}>{inc.severity_label}</span></td>
                      <td className="py-3 px-2 text-white">{inc.source_ip}</td>
                      <td className="py-3 px-2 text-[var(--color-primary)]">{inc.attack_type}</td>
                      <td className="py-3 px-2">
                        {inc.playbook ? (
                          <button onClick={(e) => { e.stopPropagation(); navigate(`/app/response?incident=${inc.id}&playbook=${inc.playbook}`); }}
                            className="text-[10px] text-[#05FFA1] flex items-center gap-1 hover:underline">
                            <Zap size={10}/> Available
                          </button>
                        ) : (
                          <button onClick={(e) => { e.stopPropagation(); navigate(`/app/response?incident=${inc.id}&mode=create`); }} 
                            className="text-[10px] text-[var(--color-muted)] hover:text-white underline">
                            Create
                          </button>
                        )}
                      </td>
                      <td className="py-3 px-2"><span className="text-[10px] px-2 py-0.5 border border-[rgba(255,255,255,0.15)] text-[var(--color-muted)]">{inc.status}</span></td>
                      <td className="py-3 px-2"><span className="flex items-center gap-1 text-xs text-[var(--color-primary)] opacity-50 group-hover:opacity-100 transition-opacity"><Search size={13}/> Investigate</span></td>
                    </tr>
                  ))}
                  
                  {/* Resolved */}
                  <tr className="bg-[rgba(5,255,161,0.05)] border-b border-[rgba(5,255,161,0.1)]"><td colSpan={7} className="py-2 px-2 text-[10px] font-bold text-[#05FFA1] uppercase tracking-wider">Resolved Incidents</td></tr>
                  {filteredIncidents.filter(i => i.status === 'RESOLVED').map(inc=>(
                    <tr key={inc.id} onClick={()=>navigate(`/app/investigate?incident=${inc.id}`)}
                      className="border-b border-[rgba(5,255,161,0.05)] bg-[rgba(5,255,161,0.01)] hover:bg-[rgba(5,255,161,0.05)] cursor-pointer group transition-colors opacity-70">
                      <td className="py-3 px-2 text-[var(--color-muted)] text-xs">{inc.id}</td>
                      <td className="py-3 px-2"><span className="px-2 py-0.5 text-[10px] rounded-sm border border-[rgba(255,255,255,0.2)] text-[var(--color-muted)]">{inc.severity_label}</span></td>
                      <td className="py-3 px-2 text-white">{inc.source_ip}</td>
                      <td className="py-3 px-2 text-[var(--color-muted)]">{inc.attack_type}</td>
                      <td className="py-3 px-2"><span className="text-[10px] text-[#05FFA1] opacity-50">Done</span></td>
                      <td className="py-3 px-2">
                        <span className="text-[10px] px-2 py-0.5 border border-[#05FFA1] text-[#05FFA1] bg-[rgba(5,255,161,0.1)]">
                          RESOLVED
                        </span>
                      </td>
                      <td className="py-3 px-2"><span className="flex items-center gap-1 text-xs text-[var(--color-muted)]"><Activity size={13}/> Details</span></td>
                    </tr>
                  ))}
                  {!filteredIncidents.length&&<tr><td colSpan={6} className="py-8 text-center text-[var(--color-muted)] text-xs">No active incidents matching filter.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div className="col-span-4 flex flex-col gap-4">
          <div className="hud-panel p-5">
            <h3 className="font-display text-base text-[var(--color-primary)] mb-4 flex items-center gap-2"><Cpu size={18}/> Ingestion Health</h3>
            {[
              { label:'Events/sec',  val:stats?.events_per_second?.toFixed(1)??0,   pct:Math.min((stats?.events_per_second||0)/5000,1), color:'#05FFA1' },
              { label:'Latency (ms)',val:stats?.avg_latency_ms?.toFixed(2)??0,      pct:Math.min((stats?.avg_latency_ms||0)/10,1),      color:'#00F0FF' },
              { label:'Drop Rate %', val:`${stats?.drop_rate_pct?.toFixed(2)??0}%`, pct:stats?.drop_rate_pct||0,                        color:'#FF4444' },
            ].map(({label,val,pct,color})=>(
              <div key={label} className="mb-3">
                <div className="flex justify-between text-xs font-mono text-[var(--color-muted)] mb-1"><span>{label}</span><span className="text-white">{val}</span></div>
                <div className="w-full h-1.5 bg-[rgba(255,255,255,0.06)] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-700" style={{width:`${pct*100}%`,backgroundColor:color}}/>
                </div>
              </div>
            ))}
          </div>

          <div className="hud-panel p-5 flex-1 flex flex-col min-h-0">
            <h3 className="font-display text-base text-[var(--color-primary)] mb-3 flex items-center gap-2 shrink-0">
              <Activity size={18}/> Live Threat Feed
              <span className="w-1.5 h-1.5 rounded-full bg-[#05FFA1] animate-pulse ml-auto"/>
            </h3>
            <div className="flex-1 overflow-y-auto custom-scrollbar space-y-1 min-h-0">
              {filteredFeed.length>0 ? filteredFeed.map((a,i)=>(
                <div key={`${a.id||i}`} onClick={()=>navigate(`/app/investigate?entity=${a.source_ip||a.id}`)}
                  className="text-xs font-mono py-1.5 px-2 border border-[rgba(255,255,255,0.04)] hover:bg-[rgba(0,240,255,0.06)] transition-colors cursor-pointer rounded group">
                  <div className="flex justify-between mb-0.5">
                    <span className="text-[var(--color-muted)] text-[10px]">{String(a.created_at||'').substring(11,19)||'NOW'}</span>
                    <span className={`text-[10px] font-bold ${feedColor(a.severity_label)}`}>[{a.severity_label}]</span>
                  </div>
                  <div className="text-[var(--color-primary)] truncate">{a.threat_type||'Unknown Anomaly'}</div>
                  <div className="flex justify-between items-center mt-0.5">
                    <span className="text-gray-400">{a.source_ip||'N/A'}</span>
                    <span onClick={e=>{e.stopPropagation();navigate(`/app/intel?ip=${a.source_ip}`);}}
                      className="flex items-center gap-1 text-[var(--color-muted)] hover:text-[var(--color-primary)]"><Globe size={10}/><span className="text-[9px]">Intel</span></span>
                  </div>
                </div>
              )) : (
                <div className="text-xs font-mono text-[var(--color-muted)] text-center py-6 flex flex-col items-center gap-2"><Zap size={20} className="opacity-30"/><span>{deviceFilter?.size ? 'No matches for filter' : 'Waiting for feed…'}</span></div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommandCenter;
