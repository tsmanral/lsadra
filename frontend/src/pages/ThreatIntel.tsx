import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Globe, AlertTriangle, Activity, Database, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { isTestUser } from '../services/api';
// For demo purposes we use the builtin intel from python
const BUILTIN_INTEL: Record<string, any> = {
  "185.15.202.13": { abuse_score: 92, country_code: "RU", isp: "Rostelecom", domain: "rostelecom.ru", total_reports: 847, is_tor: false, last_reported: "2026-04-01T12:00:00" },
  "45.33.32.156": { abuse_score: 78, country_code: "US", isp: "Linode LLC", domain: "scanme.nmap.org", total_reports: 1203, is_tor: false, last_reported: "2026-04-02T08:30:00" },
  "103.20.150.2": { abuse_score: 85, country_code: "CN", isp: "China Telecom", domain: "chinatelecom.com.cn", total_reports: 432, is_tor: false, last_reported: "2026-03-30T18:45:00" },
  "89.187.160.10": { abuse_score: 65, country_code: "NL", isp: "DataCamp Limited", domain: "datacamp.co.uk", total_reports: 256, is_tor: true, last_reported: "2026-04-01T22:15:00" },
};

const ThreatIntel = () => {
  const isTest = isTestUser();
  const [searchParams] = useSearchParams();
  const initialIp = searchParams.get('ip') || '';
  
  const [searchIp, setSearchIp] = useState(initialIp);
  const [currentIntel, setCurrentIntel] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialIp) {
      handleLookup(initialIp);
    }
  }, [initialIp]);

  const handleLookup = (ipToLookup: string = searchIp) => {
    if (!ipToLookup) return;
    setLoading(true);
    // Simulate API call for intel for test user
    setTimeout(() => {
      if (!isTest) {
        setCurrentIntel(null);
        setLoading(false);
        return;
      }
      if (BUILTIN_INTEL[ipToLookup]) {
        setCurrentIntel({ ip: ipToLookup, ...BUILTIN_INTEL[ipToLookup] });
      } else {
        // Generate random mock intel for test user
        setCurrentIntel({
          ip: ipToLookup,
          abuse_score: Math.floor(Math.random() * 100),
          country_code: ['US', 'RU', 'CN', 'BR', 'DE'][Math.floor(Math.random() * 5)],
          isp: 'Unknown ISP',
          domain: 'unknown.com',
          total_reports: Math.floor(Math.random() * 500),
          is_tor: Math.random() > 0.8,
          last_reported: new Date().toISOString()
        });
      }
      setLoading(false);
    }, 500);
  };

  const mockCachedIntel = isTest ? Object.entries(BUILTIN_INTEL).map(([ip, data]) => ({ ip, ...data })) : [];
  
  const topAnomalousIps = isTest ? [
    { ip: '185.15.202.13', count: 423, severity: 0.9 },
    { ip: '45.33.32.156', count: 312, severity: 0.8 },
    { ip: '103.20.150.2', count: 145, severity: 0.85 },
    { ip: '89.187.160.10', count: 89, severity: 0.65 },
    { ip: '192.168.1.45', count: 45, severity: 0.4 },
  ] : [];

  return (
    <div className="flex flex-col h-full space-y-8 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <Globe className="text-[#FF4444] mr-3" size={32} />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Threat Intelligence</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Global IP reputation and cached threat data.</p>
        </div>
      </header>

      {/* Lookup Section */}
      <section className="bg-[rgba(255,255,255,0.02)] border border-[rgba(0,240,255,0.15)] rounded p-6">
        <h3 className="text-xl font-display text-white mb-4">IP Reputation Lookup</h3>
        <div className="flex space-x-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-3 text-[var(--color-muted)]" size={18} />
            <input 
              type="text" 
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              placeholder="Enter IP address (e.g. 45.33.32.156)"
              className="w-full bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.3)] rounded pl-10 pr-4 py-2 text-white font-mono focus:outline-none focus:border-[var(--color-primary)]"
            />
          </div>
          <button 
            onClick={() => handleLookup(searchIp)}
            disabled={loading}
            className="hud-button flex items-center bg-[var(--color-primary)] text-black font-bold"
          >
            <Search size={18} className="mr-2" />
            {loading ? 'Searching...' : 'Lookup'}
          </button>
        </div>

        {currentIntel && (
          <div className="mt-6 animate-fade-in">
            <div className="grid grid-cols-4 gap-4 mb-6">
              <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 border-l-4" style={{borderLeftColor: currentIntel.abuse_score > 50 ? '#FF4444' : currentIntel.abuse_score > 20 ? '#FFD700' : '#10B981'}}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><AlertTriangle size={14} className="mr-1"/> Abuse Score</div>
                <div className="text-3xl font-bold text-white">{currentIntel.abuse_score}</div>
              </div>
              <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 border-l-4 border-l-[#4A9EFF]">
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Globe size={14} className="mr-1"/> Country</div>
                <div className="text-3xl font-bold text-white">{currentIntel.country_code}</div>
              </div>
              <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 border-l-4 border-l-[#7C3AED]">
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Activity size={14} className="mr-1"/> Reports</div>
                <div className="text-3xl font-bold text-white">{currentIntel.total_reports}</div>
              </div>
              <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 border-l-4" style={{borderLeftColor: currentIntel.is_tor ? '#FF4444' : '#10B981'}}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Zap size={14} className="mr-1"/> Tor Exit Node</div>
                <div className="text-3xl font-bold text-white">{currentIntel.is_tor ? 'Yes ⚡' : 'No'}</div>
              </div>
            </div>
            
            <div className="bg-[rgba(0,0,0,0.3)] border border-[rgba(255,255,255,0.1)] rounded p-4">
              <h4 className="text-sm font-bold text-white mb-2">Full Intel Report</h4>
              <pre className="text-xs font-mono text-[var(--color-primary)] whitespace-pre-wrap">
                {JSON.stringify(currentIntel, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </section>

      {/* Cached Threat Intel Table */}
      <section>
        <h3 className="text-xl font-display text-white mb-4 flex items-center"><Database size={20} className="mr-2 text-[var(--color-primary)]"/> Cached Threat Intel</h3>
        <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded overflow-hidden">
          <table className="w-full text-left text-sm font-mono">
            <thead className="bg-[rgba(0,240,255,0.05)] border-b border-[rgba(0,240,255,0.15)] text-[var(--color-muted)]">
              <tr>
                <th className="p-3">IP</th>
                <th className="p-3">Risk</th>
                <th className="p-3">Abuse Score</th>
                <th className="p-3">Country</th>
                <th className="p-3">ISP</th>
                <th className="p-3">Reports</th>
                <th className="p-3">Tor</th>
              </tr>
            </thead>
            <tbody>
              {mockCachedIntel.map((row, i) => (
                <tr key={i} className="border-b border-[rgba(255,255,255,0.05)] hover:bg-[rgba(0,240,255,0.05)] transition-colors text-gray-300">
                  <td className="p-3 text-white cursor-pointer hover:text-[var(--color-primary)] underline decoration-dotted" onClick={() => handleLookup(row.ip)}>{row.ip}</td>
                  <td className="p-3">
                    {row.abuse_score > 50 ? <span className="text-[#FF4444]">🔴 High</span> : 
                     row.abuse_score > 20 ? <span className="text-[#FFD700]">🟡 Medium</span> : 
                     <span className="text-[#10B981]">🟢 Low</span>}
                  </td>
                  <td className="p-3">{row.abuse_score}</td>
                  <td className="p-3">{row.country_code}</td>
                  <td className="p-3 truncate max-w-[150px]">{row.isp}</td>
                  <td className="p-3">{row.total_reports}</td>
                  <td className="p-3">{row.is_tor ? '🧅 Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Anomalous IPs Chart */}
      <section>
        <h3 className="text-xl font-display text-white mb-4">Top Anomalous External IPs</h3>
        <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={topAnomalousIps} margin={{ top: 20, right: 30, left: 0, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
              <XAxis dataKey="ip" stroke="#8899aa" tick={{fontSize: 12}} dy={10} />
              <YAxis stroke="#8899aa" />
              <RechartsTooltip 
                contentStyle={{ backgroundColor: '#1A1F2E', borderColor: 'rgba(0,240,255,0.3)' }}
                cursor={{fill: 'rgba(255,255,255,0.05)'}}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {topAnomalousIps.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.severity > 0.7 ? '#FF4444' : entry.severity > 0.4 ? '#FFD700' : '#4A9EFF'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

    </div>
  );
};

export default ThreatIntel;
