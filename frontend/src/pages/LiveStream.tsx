import React, { useState, useEffect, useRef } from 'react';
import { Filter, Play, Pause, AlertOctagon } from 'lucide-react';
import { getAnomalies, getEvents } from '../services/api';
import { subscribeAlerts, alertAsAnomaly } from '../services/alertStream';

import { useNavigate } from 'react-router-dom';

const LiveStream = () => {
  const [isPaused, setIsPaused] = useState(false);
  const [events, setEvents] = useState<any[]>([]);
  const navigate = useNavigate();

  const isTest = localStorage.getItem('sentinel_username') === 'testuser';

  // Dynamic Event Generator for Demo
  const generateRandomEvent = () => {
    const types = [
      { t: 'SSH_BRUTE_FORCE', s: 'HIGH', n: '150+ failed logins detected from 185.x.x.x' },
      { t: 'RANSOMWARE_INDICATOR', s: 'CRITICAL', n: 'Mass file renaming activity in /shares/finance' },
      { t: 'C2_CONNECTION', s: 'CRITICAL', n: 'Outbound HTTPS beacon to suspected Cobalt Strike C2' },
      { t: 'LATERAL_MOVEMENT', s: 'HIGH', n: 'SMB share enumeration from workstation WKS-112' },
      { t: 'SUSPICIOUS_SUDO', s: 'MEDIUM', n: 'User jdoe executed "sudo su -" from unexpected TTY' }
    ];
    const pick = types[Math.floor(Math.random() * types.length)];
    return {
      id: 'live_' + Date.now() + Math.random(),
      created_at: new Date().toISOString(),
      threat_type: pick.t,
      severity_label: pick.s,
      source_ip: `10.0.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
      device_id: ['Mock-Linux-01', 'Mock-Win-Server', 'Mock-Net-Edge'][Math.floor(Math.random()*3)],
      narrative: pick.n
    };
  };

  useEffect(() => {
    const load = async () => {
      try {
        const [anomRes] = await Promise.all([getAnomalies()]);
        if (events.length === 0) {
          setEvents(anomRes?.data || []);
        }
      } catch (err) { console.error("Failed to fetch live stream", err); }
    };

    load();
    if (!isPaused && isTest) {
      const interval = setInterval(() => {
        setEvents(prev => [generateRandomEvent(), ...prev].slice(0, 50));
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [isPaused, events.length]);

  // Real alerts are pushed over /ws/alerts; a paused console drops them.
  const pausedRef = useRef(isPaused);
  useEffect(() => { pausedRef.current = isPaused; }, [isPaused]);
  useEffect(() => subscribeAlerts({
    onAlert: (alert) => {
      if (pausedRef.current) return;
      setEvents(prev => [alertAsAnomaly(alert), ...prev].slice(0, 50));
    },
  }), []);

  return (
    <div className="flex flex-col h-screen -m-6 bg-[#03060a] relative overflow-hidden">
      {/* HUD Scanlines Effect */}
      <div className="absolute inset-0 pointer-events-none z-10 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] opacity-20"></div>

      <header className="flex justify-between items-center p-6 border-b border-[rgba(0,240,255,0.3)] bg-[rgba(0,10,20,0.8)] backdrop-blur-md z-20">
        <div>
          <div className="flex items-center space-x-3">
            <div className="w-2 h-2 rounded-full bg-[var(--color-critical)] animate-pulse shadow-[0_0_8px_var(--color-critical)]"></div>
            <h2 className="text-4xl font-display font-bold text-white tracking-[0.2em] uppercase">Live SOC Terminal</h2>
          </div>
          <p className="text-[var(--color-muted)] font-mono text-xs mt-2 uppercase tracking-widest opacity-70">
            Node: GLOBAL_INGESTION_HUB // Stream: REALTIME_BEHAVIORAL_FEED // Status: <span className="text-[var(--color-primary)]">ACTIVE_MONITORING</span>
          </p>
        </div>
        
        <div className="flex space-x-6 items-center">
          <div className="flex flex-col items-end mr-6 border-r border-[rgba(0,240,255,0.2)] pr-6">
            <span className="text-[10px] text-[var(--color-muted)] font-mono mb-1">TOTAL INGESTION RATE</span>
            <span className="text-2xl font-display text-[var(--color-primary)]">1,402.8 <span className="text-xs">EPS</span></span>
          </div>

          <div className="flex space-x-3">
             <button 
              onClick={() => setIsPaused(!isPaused)}
              className={`hud-button flex items-center px-6 py-2 transition-all duration-300 ${isPaused ? 'bg-[var(--color-critical)] text-white border-transparent' : 'bg-transparent border border-[var(--color-primary)] text-[var(--color-primary)]'}`}
            >
              {isPaused ? <Play size={16} className="mr-2"/> : <Pause size={16} className="mr-2"/>}
              {isPaused ? 'RESUME STREAM' : 'PAUSE CONSOLE'}
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 flex flex-col overflow-hidden z-20 p-6 pt-2">
        {/* Stream Headers */}
        <div className="flex items-center px-4 py-3 bg-[rgba(0,240,255,0.05)] border border-[rgba(0,240,255,0.1)] mb-2 text-[10px] font-display tracking-[0.2em] text-[var(--color-muted)] uppercase">
          <div className="w-24">UTC_TIMESTAMP</div>
          <div className="w-48">THREAT_IDENTIFIER</div>
          <div className="w-32">SEVERITY</div>
          <div className="w-40">SOURCE_IP_ADR</div>
          <div className="w-40">TARGET_DEVICE</div>
          <div className="flex-1">HEURISTIC_NARRATIVE</div>
          <div className="w-32 text-right">RESPONSE_OP</div>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar bg-[rgba(0,0,0,0.4)] border border-[rgba(0,240,255,0.1)]">
          {events.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center opacity-30">
              <div className="w-12 h-12 border-2 border-[var(--color-primary)] border-t-transparent rounded-full animate-spin mb-4"></div>
              <p className="font-mono text-sm">AWAITING_INGESTION_SYMBOLS...</p>
            </div>
          ) : (
            events.map((evt, idx) => (
              <div 
                key={evt.id} 
                className={`flex items-center px-4 py-3 border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.1)] transition-all group animate-in fade-in slide-in-from-right-4 duration-500`}
                style={{ animationDelay: `${idx * 50}ms` }}
              >
                <div className="w-24 font-mono text-[11px] text-gray-500">
                  {new Date(evt.created_at || Date.now()).toLocaleTimeString('en-GB', { hour12: false })}
                </div>
                
                <div className="w-48">
                  <span className={`font-display text-xs tracking-wider ${evt.severity_label === 'CRITICAL' ? 'text-[var(--color-critical)]' : evt.severity_label === 'HIGH' ? 'text-[var(--color-warning)]' : 'text-[var(--color-primary)]'}`}>
                    {evt.threat_type || 'RAW_EVENT'}
                  </span>
                </div>

                <div className="w-32">
                  <span className={`px-2 py-0.5 text-[9px] font-bold border ${
                    evt.severity_label === 'CRITICAL' ? 'border-[var(--color-critical)] text-[var(--color-critical)] shadow-[0_0_5px_rgba(255,0,0,0.3)]' : 
                    evt.severity_label === 'HIGH' ? 'border-[var(--color-warning)] text-[var(--color-warning)]' : 
                    'border-[var(--color-primary)] text-[var(--color-primary)]'
                  }`}>
                    {evt.severity_label || 'INFO'}
                  </span>
                </div>

                <div className="w-40 font-mono text-xs text-white opacity-80 group-hover:opacity-100 group-hover:text-[var(--color-primary)] cursor-pointer">
                  {evt.source_ip || '127.0.0.1'}
                </div>

                <div className="w-40 font-mono text-xs text-gray-400">
                  {evt.device_id || 'LOCAL_HOST'}
                </div>

                <div className="flex-1 font-mono text-xs text-gray-500 group-hover:text-gray-300 transition-colors">
                  {evt.narrative || 'Analyzing raw telemetry packets for behavioral drift...'}
                </div>

                <div className="w-32 text-right">
                  <button 
                    onClick={() => navigate(`/app/investigate/${evt.id}`)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity text-[10px] font-display text-[var(--color-primary)] border border-[var(--color-primary)] px-2 py-1 hover:bg-[var(--color-primary)] hover:text-black"
                  >
                    INVESTIGATE
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </main>

      {/* Footer Info Bar */}
      <footer className="p-3 px-6 bg-[rgba(0,240,255,0.05)] border-t border-[rgba(0,240,255,0.2)] flex justify-between items-center z-20">
        <div className="flex space-x-6 text-[10px] font-mono text-[var(--color-muted)]">
          <span className="flex items-center"><div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div> DB_CONNECTION: OPTIMAL</span>
          <span className="flex items-center"><div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div> ML_ENGINE: LOADED</span>
          <span>UPTIME: 142h 12m 04s</span>
        </div>
        <div className="text-[10px] font-mono text-[var(--color-primary)] tracking-widest">
          AI_SENTINEL_V4 // GLOBAL_THREAT_INTEL_READY
        </div>
      </footer>
    </div>
  );
};

export default LiveStream;
