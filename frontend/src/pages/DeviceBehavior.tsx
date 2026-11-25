import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDevices, saveActiveDeviceFilter, deleteDevice, updateDeviceStatus, isTestUser } from '../services/api';
import { Monitor, Server, Plus, CheckSquare, Square, Save, RotateCcw, Info, Power, PowerOff, Trash2 } from 'lucide-react';

const OS_GROUPS: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  Windows: { label: 'Windows',  icon: <Monitor size={16}/>,  color: '#4A9EFF' },
  Linux:   { label: 'Linux',    icon: <Server size={16}/>,   color: '#05FFA1' },
  Network: { label: 'Network',  icon: <Server size={16}/>,   color: '#B026FF' },
  Other:   { label: 'Other',    icon: <Server size={16}/>,   color: '#FFD700' },
};

const osGroup = (os: string) =>
  os?.toLowerCase().includes('windows') ? 'Windows' :
  os?.toLowerCase().includes('ubuntu') || os?.toLowerCase().includes('centos') || os?.toLowerCase().includes('linux') || os?.toLowerCase().includes('syslog') ? 'Linux' :
  os?.toLowerCase().includes('zeek') || os?.toLowerCase().includes('network') ? 'Network' : 'Other';

const SEED: any[] = [
  { device_id: '8a4be99a-200e-4511-a35c-264e0ce69aa8', source_type: 'Linux Syslog',     ip_address: '192.168.1.45', is_active: true, last_seen: new Date().toISOString(), os_type: 'Ubuntu 22.04 (Linux)' },
  { device_id: 'b997415c-9653-4f45-87bf-f4a84d936f76', source_type: 'Windows Event Log', ip_address: '10.0.0.12',    is_active: true, last_seen: new Date().toISOString(), os_type: 'Windows Server 2022' },
  { device_id: 'net-edge-001',                      source_type: 'Zeek Network',      ip_address: '172.16.0.1',   is_active: true, last_seen: new Date().toISOString(), os_type: 'Zeek Network OS' },
  { device_id: 'wks-112-pro',                       source_type: 'Windows Event Log', ip_address: '10.0.5.101',   is_active: true, last_seen: new Date().toISOString(), os_type: 'Windows 11 Pro' },
  { device_id: 'WKS-112-X',                         source_type: 'Windows Event Log', ip_address: '10.0.5.22',    is_active: true, last_seen: new Date().toISOString(), os_type: 'Windows 10 Enterprise' },
  { device_id: 'DC-01',                             source_type: 'Active Directory',  ip_address: '172.16.0.1',   is_active: true, last_seen: new Date().toISOString(), os_type: 'Windows Server (AD)' },
  { device_id: 'APP-SRV-02',                        source_type: 'Linux Syslog',      ip_address: '45.33.2.1',    is_active: true, last_seen: new Date().toISOString(), os_type: 'Ubuntu Linux 20.04' },
];

const DeviceBehavior = () => {
  const navigate = useNavigate();
  const isTest = isTestUser();
  const [devices, setDevices]   = useState<any[]>([]); // Start empty, fill from API or SEED
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [activeGroup, setActiveGroup] = useState<string>('All');
  const [saved, setSaved]       = useState(false);
  const [showAdd, setShowAdd]   = useState(false);
  const [newForm, setNewForm]   = useState({ name:'', ip:'', os:'Windows', type:'Windows Event Log' });
  const [filterActive, setFilterActive] = useState(false);

  useEffect(() => {
    const user = localStorage.getItem('sentinel_username') || 'anon';
    const key = `sentinel_device_filter_${user}`;
    const saved = localStorage.getItem(key);
    
    getDevices().then(r => {
      let currentDevices: any[] = [];
      if (Array.isArray(r?.data) && r.data.length > 0) {
        currentDevices = r.data.map((d: any) => ({
          // API rows are `devices` table rows: id, hostname, os_type, status, last_seen_at.
          device_id: d.id || d.device_id, source_type: d.source_type || d.os_type || 'Unknown',
          ip_address: d.ip_address || d.hostname || '—',
          is_active: d.is_active ?? (d.status ? d.status !== 'OFFLINE' : false),
          last_seen: d.last_seen ?? d.last_seen_at ?? null, os_type: d.os_type || '—',
        }));
      } else if (isTest) {
        currentDevices = SEED;
      }
      setDevices(currentDevices);

      // Validate saved filter against actual devices
      if (saved) {
        const parsed = JSON.parse(saved);
        const validIds = new Set(currentDevices.map(d => d.device_id));
        const filtered = parsed.filter((id: string) => validIds.has(id));
        
        if (filtered.length > 0) {
          setSelected(new Set(filtered));
          setFilterActive(true);
        } else {
          // If none of the saved IDs are valid, clear it
          setSelected(new Set());
          setFilterActive(false);
          localStorage.removeItem(key);
        }
      }
    }).catch(() => { 
      if (isTest) setDevices(SEED); 
    });
  }, []);

  const toggle = (id: string) =>
    setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });

  const saveFilter = () => {
    const arr = [...selected];
    saveActiveDeviceFilter(arr);
    setFilterActive(arr.length > 0);
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  };

  const clearFilter = () => {
    setSelected(new Set());
    saveActiveDeviceFilter([]);
    setFilterActive(false);
  };

  const addDevice = () => {
    if (!newForm.name.trim() || !newForm.ip.trim()) return;
    setDevices(prev => [...prev, {
      device_id: newForm.name.trim(),   // use exactly what the user typed
      source_type: newForm.type, ip_address: newForm.ip.trim(),
      is_active: true, last_seen: new Date().toISOString(), os_type: newForm.os,
    }]);
    setNewForm({ name:'', ip:'', os:'Windows Server 2022', type:'Windows Event Log' }); setShowAdd(false);
  };

  const toggleStatus = async (id: string) => {
    const device = devices.find(d => d.device_id === id);
    if (!device) return;
    const newActive = !device.is_active;
    
    // Optimistic update
    setDevices(prev => prev.map(d =>
      d.device_id === id ? { ...d, is_active: newActive, last_seen: new Date().toISOString() } : d
    ));

    try {
      await updateDeviceStatus(id, newActive);
    } catch (err) {
      console.error("Failed to update device status", err);
      // Revert on error
      setDevices(prev => prev.map(d =>
        d.device_id === id ? { ...d, is_active: !newActive } : d
      ));
    }
  };

  const removeDevice = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this device and all its history?')) return;
    try {
      await deleteDevice(id);
      setDevices(prev => prev.filter(d => d.device_id !== id));
    } catch (err: any) {
      alert('Failed to delete device. ' + (err.response?.data?.detail || 'Error'));
    }
  };

  const groups = ['All', 'Windows', 'Linux', 'Network', 'Other'];
  const visible = devices.filter(d =>
    activeGroup === 'All' || osGroup(d.os_type) === activeGroup
  );

  const grouped = groups.slice(1).reduce((acc, g) => {
    acc[g] = devices.filter(d => osGroup(d.os_type) === g);
    return acc;
  }, {} as Record<string, any[]>);

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      {/* Header */}
      <header className="flex justify-between items-end border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Device Behavior</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">
            Select devices to filter your dashboard view. Leave empty to show all.
            {filterActive && <span className="ml-2 text-[var(--color-primary)]">● Filter Active ({selected.size} devices)</span>}
          </p>
        </div>
        <div className="flex gap-2">
          {filterActive && (
            <button onClick={clearFilter}
              className="flex items-center gap-1.5 text-xs font-mono px-3 py-2 border border-[rgba(255,68,68,0.4)] text-[#FF4444] hover:bg-[rgba(255,68,68,0.08)] transition-colors">
              <RotateCcw size={12}/> Clear Filter
            </button>
          )}
          <button onClick={() => navigate('/app/connect')}
            className="hud-button flex items-center gap-2 text-sm">
            <Plus size={14}/> Add Device
          </button>
        </div>
      </header>

      {/* Info banner */}
      <div className="flex items-start gap-3 bg-[rgba(0,240,255,0.04)] border border-[rgba(0,240,255,0.15)] rounded p-4 text-xs font-mono text-[var(--color-muted)] shrink-0">
        <Info size={14} className="text-[var(--color-primary)] flex-shrink-0 mt-0.5"/>
        <p>Check devices below to <strong className="text-white">filter all dashboard views</strong> (Command Center, Analytics, Live Alerts) to show only events from selected devices.
        Multiple selections are supported. Leave all unchecked to see all devices.</p>
      </div>

      {/* Group summary tiles */}
      <div className="grid grid-cols-4 gap-3 shrink-0">
        {groups.slice(1).map(g => {
          const cfg = OS_GROUPS[g];
          const cnt = grouped[g]?.length || 0;
          const active = grouped[g]?.filter((d: any) => d.is_active).length || 0;
          return (
            <button key={g} onClick={() => setActiveGroup(activeGroup === g ? 'All' : g)}
              className={`hud-panel p-4 text-left border-l-2 transition-colors ${activeGroup === g ? 'bg-[rgba(0,240,255,0.06)]' : ''}`}
              style={{ borderLeftColor: cfg.color }}>
              <div className="flex items-center gap-2 text-[10px] font-mono text-[var(--color-muted)] uppercase mb-2">{cfg.icon}{g}</div>
              <div className="text-2xl font-display font-bold" style={{ color: cfg.color }}>{cnt}</div>
              <div className="text-[10px] font-mono text-[var(--color-muted)] mt-1">
                {active} Active {cnt - active > 0 && `· ${cnt - active} Inactive`}
              </div>
            </button>
          );
        })}
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 shrink-0">
        <span className="text-xs font-mono text-[var(--color-muted)]">Show:</span>
        {groups.map(g => (
          <button key={g} onClick={() => setActiveGroup(g)}
            className={`text-xs font-mono px-3 py-1 border transition-colors ${activeGroup === g ? 'border-[var(--color-primary)] text-[var(--color-primary)] bg-[rgba(0,240,255,0.06)]' : 'border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] hover:border-[rgba(0,240,255,0.3)]'}`}>
            {g} {g !== 'All' && `(${grouped[g]?.length||0})`}
          </button>
        ))}
        <span className="flex-1"/>
        <button onClick={() => {
          const allVisible = visible.map((d: any) => d.device_id);
          const allSelected = allVisible.every(id => selected.has(id));
          const next = new Set(selected);
          if (allSelected) allVisible.forEach(id => next.delete(id));
          else allVisible.forEach(id => next.add(id));
          setSelected(next);
        }} className="text-xs font-mono px-3 py-1 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.06)] rounded transition-colors">
          {visible.length > 0 && visible.every((d: any) => selected.has(d.device_id)) ? 'Deselect All' : 'Select All'}
        </button>
        <span className="text-xs font-mono text-[var(--color-muted)] ml-2">{selected.size} selected</span>
        <button onClick={saveFilter}
          className={`flex items-center gap-1.5 text-xs font-mono px-4 py-1.5 font-bold transition-colors ${saved ? 'bg-[#05FFA1] text-black' : 'bg-[var(--color-primary)] text-black'}`}>
          <Save size={12}/> {saved ? 'Saved!' : 'Apply Filter'}
        </button>
      </div>

      {/* Device grid */}
      <div className="grid grid-cols-12 gap-3">
        {visible.map(d => {
          const g = osGroup(d.os_type);
          const cfg = OS_GROUPS[g] || OS_GROUPS.Other;
          const isSel = selected.has(d.device_id);
          const seenMs = d.last_seen ? new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(d.last_seen) ? d.last_seen : `${String(d.last_seen).replace(' ', 'T')}Z`).getTime() : NaN;
          const relSince = Math.max(0, Math.round((Date.now() - seenMs) / 1000));
          const lastSeenStr = Number.isNaN(seenMs) ? 'never' : relSince < 60 ? `${relSince}s ago` : relSince < 3600 ? `${Math.round(relSince/60)}m ago` : relSince < 172800 ? `${Math.round(relSince/3600)}h ago` : `${Math.round(relSince/86400)}d ago`;

          return (
            <div key={d.device_id} onClick={() => toggle(d.device_id)}
              role="checkbox" aria-checked={isSel} tabIndex={0} aria-label={`Device ${d.device_id}`}
              onKeyDown={e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(d.device_id); } }}
              className={`col-span-4 hud-panel p-4 cursor-pointer transition-all border ${isSel ? 'border-[var(--color-primary)] bg-[rgba(0,240,255,0.06)]' : 'border-transparent hover:border-[rgba(0,240,255,0.2)]'}`}>
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  {isSel
                    ? <CheckSquare size={16} className="text-[var(--color-primary)] flex-shrink-0"/>
                    : <Square size={16} className="text-[var(--color-muted)] flex-shrink-0"/>}
                  <div>
                    <div className="font-display font-bold text-sm" style={{ color: cfg.color }}>{d.device_id}</div>
                    <div className="text-[10px] font-mono text-[var(--color-muted)]">{d.os_type}</div>
                  </div>
                </div>
                <span className={`text-[10px] font-bold px-2 py-0.5 border ${d.is_active ? 'border-[#05FFA1] text-[#05FFA1]' : 'border-[#FF4444] text-[#FF4444]'}`}>
                  {d.is_active ? 'ACTIVE' : 'OFFLINE'}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-y-1 text-[10px] font-mono">
                <span className="text-[var(--color-muted)]">Host / IP</span><span className="text-white">{d.ip_address}</span>
                <span className="text-[var(--color-muted)]">Type</span><span className="text-white truncate">{d.source_type}</span>
                <span className="text-[var(--color-muted)]">Last Seen</span><span className="text-white">{lastSeenStr}</span>
                <span className="text-[var(--color-muted)]">Group</span><span style={{ color: cfg.color }}>{g}</span>
              </div>
              {/* Activate/Deactivate toggle */}
              <div className="mt-3 pt-2 border-t border-[rgba(255,255,255,0.05)] flex gap-2" onClick={e=>e.stopPropagation()}>
                <button onClick={()=>toggleStatus(d.device_id)}
                  className={`flex-1 flex items-center justify-center gap-1.5 text-[10px] font-mono py-1.5 border transition-colors font-bold ${
                    d.is_active
                      ? 'border-[rgba(255,68,68,0.4)] text-[#FF4444] hover:bg-[rgba(255,68,68,0.08)]'
                      : 'border-[rgba(5,255,161,0.4)] text-[#05FFA1] hover:bg-[rgba(5,255,161,0.08)]'
                  }`}>
                  {d.is_active ? <><PowerOff size={10}/> Deactivate</> : <><Power size={10}/> Activate</>}
                </button>
                <button onClick={()=>removeDevice(d.device_id)}
                  className="px-3 py-1.5 border border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] hover:text-[#FF4444] hover:border-[#FF4444] transition-colors">
                  <Trash2 size={12}/>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Add Device inline form */}
      {showAdd && (
        <div className="hud-panel p-5 shrink-0">
          <h4 className="font-display text-sm text-[var(--color-primary)] uppercase mb-4">Register New Device</h4>
          <div className="grid grid-cols-4 gap-3 mb-4">
            {[
              { label:'Device Name / ID', key:'name', type:'text', placeholder:'e.g. AGT-LIN-04' },
              { label:'IP Address', key:'ip', type:'text', placeholder:'192.168.x.x' },
            ].map(({ label, key, type, placeholder }) => (
              <div key={key}>
                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">{label}</label>
                <input type={type} value={(newForm as any)[key]} placeholder={placeholder}
                  onChange={e => setNewForm(f => ({ ...f, [key]: e.target.value }))}
                  className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]"/>
              </div>
            ))}
            <div>
              <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">OS Type</label>
              <select value={newForm.os} onChange={e => setNewForm(f => ({ ...f, os: e.target.value }))}
                className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
                <option>Windows Server 2022</option><option>Windows 10 Pro</option>
                <option>Ubuntu 22.04</option><option>Ubuntu 20.04</option><option>CentOS 8</option>
                <option>Zeek 6.0</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Source Type</label>
              <select value={newForm.type} onChange={e => setNewForm(f => ({ ...f, type: e.target.value }))}
                className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
                <option>Windows Event Log</option><option>Syslog / Auth</option><option>Zeek Network</option><option>Custom Agent</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={addDevice} className="hud-button bg-[var(--color-primary)] text-black font-bold text-xs px-5">Add Device</button>
            <button onClick={() => setShowAdd(false)} className="hud-button border border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] text-xs px-5">Cancel</button>
          </div>
        </div>
      )}
      {!showAdd && (
        <button onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 text-xs font-mono text-[var(--color-muted)] hover:text-[var(--color-primary)] border border-dashed border-[rgba(255,255,255,0.1)] hover:border-[rgba(0,240,255,0.3)] rounded px-4 py-3 w-full justify-center transition-colors shrink-0">
          <Plus size={14}/> Add Device Manually
        </button>
      )}
    </div>
  );
};

export default DeviceBehavior;
