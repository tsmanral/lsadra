import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDevices, getAnomalies, deleteDevice, isTestUser } from '../services/api';
import { Database, Plus, Trash2, Power, PowerOff, MonitorSmartphone } from 'lucide-react';

const SEED_AGENTS = [
  { id: 'AGT-WIN-01', type: 'Windows Event Log', ip: '10.0.5.22',    status: 'ACTIVE',   lastSeen: '2s ago',  os: 'Windows Server 2022' },
  { id: 'AGT-LIN-02', type: 'Syslog / Auth',     ip: '45.33.2.1',   status: 'ACTIVE',   lastSeen: '12s ago', os: 'Ubuntu 22.04' },
  { id: 'AGT-NET-01', type: 'Zeek Network',       ip: '192.168.1.1', status: 'WARNING',  lastSeen: '4m ago',  os: 'Zeek 6.0' },
  { id: 'AGT-WIN-02', type: 'Windows Event Log',  ip: '10.0.5.23',   status: 'OFFLINE',  lastSeen: '14h ago', os: 'Windows 10 Pro' },
];

const Sources = () => {
  const navigate = useNavigate();
  const isTest = isTestUser();
  // IMPORTANT: For real users like demouser001, we start with an EMPTY list.
  const [agents, setAgents] = useState<any[]>(isTest ? SEED_AGENTS : []);
  const [anomCounts, setAnomCounts] = useState<Record<string, number>>({});
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  useEffect(() => {
    getDevices().then(r => {
      let data = r?.data || [];
      if (isTest && data.length === 0) {
        data = [
          { id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', source_type: 'Linux', ip_address: '192.168.1.45', os_type: 'Ubuntu 22.04', is_active: true, last_seen: new Date().toISOString() },
          { id: 'b997415c-9653-4f45-87bf-f4a84d936f76', source_type: 'Windows', ip_address: '10.0.0.12', os_type: 'Windows Server 2022', is_active: true, last_seen: new Date().toISOString() }
        ];
      }
      // Sync with real DB data
      if (Array.isArray(data)) {
        // If it's a real user, always use the DB result even if it's 0 devices.
        if (data.length > 0 || !isTest) {
          const mapped = data.map((d: any) => ({
            id: d.device_id || d.id,
            type: d.source_type || 'Unknown',
            ip: d.ip_address || '—',
            status: d.is_active ? 'ACTIVE' : 'OFFLINE',
            lastSeen: d.last_seen ? new Date(d.last_seen).toLocaleString() : '—',
            os: d.os_type || '—',
          }));
          setAgents(mapped);
        }
      }
    }).catch(() => {});

    getAnomalies().then(r => {
      if (Array.isArray(r?.data)) {
        const counts: Record<string, number> = {};
        r.data.forEach((a: any) => {
          const ip = a.source_ip;
          if (ip) counts[ip] = (counts[ip] || 0) + 1;
        });
        setAnomCounts(counts);
      }
    }).catch(() => {});
  }, [isTest]);

  const toggleStatus = (id: string) => {
    setAgents(prev => prev.map(a =>
      a.id === id ? { ...a, status: a.status === 'ACTIVE' ? 'OFFLINE' : 'ACTIVE', lastSeen: 'Just now' } : a
    ));
  };

  const removeAgent = async (id: string) => {
    try {
      await deleteDevice(id);
      setAgents(prev => prev.filter(a => a.id !== id));
      setConfirmRemove(null);
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Server error';
      alert('Failed to delete device: ' + msg);
      setConfirmRemove(null);
    }
  };

  const statusColor = (s: string) =>
    s === 'ACTIVE' ? 'text-emerald-400' : s === 'WARNING' ? 'text-amber-400' : 'text-slate-500';

  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-display font-black tracking-tighter text-white">MULTI-SOURCE</h1>
          <p className="text-slate-400 mt-1">Manage ingestion agents and data stream health</p>
        </div>
        <button className="flex items-center gap-2 bg-[var(--color-primary)] hover:bg-opacity-80 text-black px-6 py-3 rounded-xl font-bold transition-all transform hover:scale-105 active:scale-95 shadow-lg shadow-cyan-500/20">
          <Plus size={20}/>
          DEPLOY NEW AGENT
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Active Sources', value: agents.filter(a => a.status === 'ACTIVE').length, icon: <Database className="text-emerald-400"/> },
          { label: 'Offline', value: agents.filter(a => a.status === 'OFFLINE').length, icon: <PowerOff className="text-slate-500"/> },
          { label: 'Total Events/s', value: (agents.filter(a => a.status === 'ACTIVE').length * 42.5).toFixed(1), icon: <MonitorSmartphone className="text-cyan-400"/> },
          { label: 'Avg Latency', value: '14ms', icon: <Database className="text-purple-400"/> }
        ].map((stat, i) => (
          <div key={i} className="glass-panel p-6 rounded-2xl flex items-center justify-between border border-white/5">
            <div>
              <p className="text-sm font-bold text-slate-500 uppercase tracking-wider">{stat.label}</p>
              <p className="text-3xl font-display font-black text-white mt-1">{stat.value}</p>
            </div>
            <div className="p-4 bg-white/5 rounded-xl">{stat.icon}</div>
          </div>
        ))}
      </div>

      <div className="glass-panel rounded-3xl overflow-hidden border border-white/5">
        <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/5">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Database size={20} className="text-[var(--color-primary)]"/>
            Ingestion Nodes
          </h2>
          <span className="px-3 py-1 bg-white/5 rounded-full text-xs font-bold text-slate-400 uppercase tracking-widest border border-white/5">
            {agents.length} Nodes Connected
          </span>
        </div>

        <div className="grid grid-cols-1 gap-px bg-white/5">
          {agents.length === 0 ? (
            <div className="p-20 text-center space-y-4 bg-[var(--color-bg)]">
              <div className="inline-flex p-6 bg-white/5 rounded-full text-slate-600">
                <Database size={48}/>
              </div>
              <h3 className="text-2xl font-display font-bold text-white">No active sources detected</h3>
              <p className="text-slate-400 max-w-md mx-auto">
                Connect your first Linux or Windows agent using the deployment script to start ingesting telemetry.
              </p>
            </div>
          ) : (
            agents.map((agent) => (
              <div key={agent.id} className="p-6 bg-[var(--color-bg)] hover:bg-white/5 transition-all group border-b border-white/5 last:border-0">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-6">
                    <div className={`p-4 rounded-2xl bg-white/5 border border-white/5 transition-all group-hover:scale-110 ${statusColor(agent.status)}`}>
                      <MonitorSmartphone size={32}/>
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-display font-bold text-lg text-white">{agent.id}</h4>
                        <span className={`text-[10px] font-black px-2 py-0.5 rounded border ${agent.status === 'ACTIVE' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-slate-500/10 border-slate-500/20 text-slate-400'}`}>
                          {agent.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 mt-1">
                        <span className="text-sm text-slate-500 font-medium">OS: <span className="text-slate-300">{agent.os}</span></span>
                        <span className="text-sm text-slate-500 font-medium">IP: <span className="text-slate-300 font-mono tracking-tight">{agent.ip}</span></span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-12">
                    <div className="text-right">
                      <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Active Anomalies</p>
                      <p className={`text-2xl font-display font-black mt-1 ${anomCounts[agent.ip] ? 'text-rose-400 animate-pulse' : 'text-slate-700'}`}>
                        {anomCounts[agent.ip] || 0}
                      </p>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={() => toggleStatus(agent.id)}
                        className={`p-3 rounded-xl transition-all border ${agent.status === 'ACTIVE' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20' : 'bg-slate-500/10 border-slate-500/20 text-slate-500 hover:bg-slate-500/20'}`}
                        title="Toggle Connection"
                      >
                        {agent.status === 'ACTIVE' ? <Power size={20}/> : <PowerOff size={20}/>}
                      </button>
                      <button 
                        onClick={() => setConfirmRemove(agent.id)}
                        className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl hover:bg-rose-500/20 transition-all"
                        title="Remove Device"
                      >
                        <Trash2 size={20}/>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {confirmRemove && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="glass-panel p-8 rounded-3xl max-w-md w-full border border-white/10 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="p-4 bg-rose-500/10 text-rose-400 rounded-full w-fit mb-6 mx-auto">
              <Trash2 size={32}/>
            </div>
            <h3 className="text-2xl font-display font-bold text-white text-center mb-2">Remove Device?</h3>
            <p className="text-slate-400 text-center mb-8">
              This will permanently delete <span className="text-white font-mono">{confirmRemove}</span> and all its associated telemetry, incidents, and event history. This cannot be undone.
            </p>
            <div className="flex gap-4">
              <button 
                onClick={() => setConfirmRemove(null)}
                className="flex-1 px-6 py-4 rounded-2xl bg-white/5 text-white font-bold hover:bg-white/10 transition-all border border-white/5"
              >
                CANCEL
              </button>
              <button 
                onClick={() => removeAgent(confirmRemove)}
                className="flex-1 px-6 py-4 rounded-2xl bg-rose-500 text-white font-bold hover:bg-rose-600 transition-all shadow-lg shadow-rose-500/20"
              >
                REMOVE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Sources;
