import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Globe, AlertTriangle, Activity, Database, ShieldCheck, ShieldAlert, ListChecks } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { getIntelStatus, lookupIntelIp, searchKev, getFlaggedIps } from '../services/api';

// Every value on this page comes from /api/intel: the signed bundle (CISA KEV,
// MITRE ATT&CK), local runtime feeds, local geolocation, or AbuseIPDB when the
// operator set a key. Unknown is shown as unknown; nothing is simulated.

interface Verdict { level: string; reason: string }
interface FeedMatch { feed: string; name: string; category: string; indicator: string; label: string; first_seen: string; list_updated: string | null }
interface IpIntel {
  ip: string;
  valid: boolean;
  scope?: string;
  verdict?: Verdict;
  geo?: { country_code: string; country: string; city: string; source: string } | null;
  feed_matches?: FeedMatch[];
  abuseipdb?: { abuse_score: number; total_reports: number; isp: string; is_tor: boolean; queried_at: string } | null;
  sources_checked?: string[];
}
interface Source { id: string; name: string; version: string; records: number; license: string }
interface FeedStatus { feed: string; name: string; enabled: boolean; records: number; status: string; fetched_at: string | null }
interface IntelStatus {
  bundled: { available: boolean; file?: string; signed_by?: string; error?: string; sources?: Source[] };
  runtime: { feeds: FeedStatus[]; abuseipdb: { configured: boolean } };
  geo: { available: boolean; database_type?: string; build_date?: string; attribution?: string };
}
interface KevRow { cve_id: string; vendor: string; product: string; name: string; date_added: string; known_ransomware_use: boolean }
interface FlaggedIp { ip: string; anomalies: number; max_severity: number | null; last_seen: string; verdict: string; country_code: string; feed_matches: number; abuse_score: number | null }

const VERDICT_STYLE: Record<string, { color: string; label: string }> = {
  malicious: { color: '#FF4444', label: 'Malicious' },
  suspicious: { color: '#FFD700', label: 'Suspicious' },
  not_listed: { color: '#10B981', label: 'Not listed' },
  internal: { color: '#4A9EFF', label: 'Internal' },
  unknown: { color: '#8899AA', label: 'Unknown' },
};
const verdictStyle = (level?: string) => VERDICT_STYLE[level || 'unknown'] || VERDICT_STYLE.unknown;

const errorText = (e: unknown): string => {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === 'string' ? detail : 'Lookup failed.';
};

const card = 'bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 border-l-4';

const ThreatIntel = () => {
  const [searchParams] = useSearchParams();
  const initialIp = searchParams.get('ip') || '';
  const canQueryRemote = ['ADMIN', 'ANALYST'].includes(localStorage.getItem('sentinel_role') || '');

  const [searchIp, setSearchIp] = useState(initialIp);
  const [askRemote, setAskRemote] = useState(false);
  const [currentIntel, setCurrentIntel] = useState<IpIntel | null>(null);
  const [lookupError, setLookupError] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<IntelStatus | null>(null);
  const [kevQuery, setKevQuery] = useState('');
  const [kevRows, setKevRows] = useState<KevRow[]>([]);
  const [flagged, setFlagged] = useState<FlaggedIp[]>([]);

  const handleLookup = useCallback(async (ipToLookup: string, remote = false) => {
    const ip = ipToLookup.trim();
    if (!ip) return;
    setSearchIp(ip);
    setLoading(true);
    setLookupError('');
    try {
      const res = await lookupIntelIp(ip, remote);
      setCurrentIntel(res.data);
    } catch (e) {
      setCurrentIntel(null);
      setLookupError(errorText(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    getIntelStatus().then(r => setStatus(r.data)).catch(() => setStatus(null));
    getFlaggedIps(20).then(r => setFlagged(r.data)).catch(() => setFlagged([]));
  }, []);

  // Investigate links here as /app/intel?ip=<ip>; look that IP up on arrival.
  useEffect(() => {
    if (!initialIp) return;
    lookupIntelIp(initialIp)
      .then(r => setCurrentIntel(r.data))
      .catch(e => setLookupError(errorText(e)));
  }, [initialIp]);

  useEffect(() => {
    const t = setTimeout(() => {
      searchKev(kevQuery, 25).then(r => setKevRows(r.data)).catch(() => setKevRows([]));
    }, 250);
    return () => clearTimeout(t);
  }, [kevQuery]);

  const abuseConfigured = !!status?.runtime.abuseipdb.configured;
  const enabledFeeds = status?.runtime.feeds.filter(f => f.enabled) || [];
  const v = verdictStyle(currentIntel?.verdict?.level);

  return (
    <div className="flex flex-col h-full space-y-8 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <Globe className="text-[#FF4444] mr-3" size={32} />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Threat Intelligence</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Signed bundled intel, local feeds and local geolocation. No API key needed.</p>
        </div>
      </header>

      {/* Sources */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div className={card} style={{ borderLeftColor: status?.bundled.available ? '#10B981' : '#FF4444' }}>
          <div className="text-[var(--color-muted)] mb-2 flex items-center">
            {status?.bundled.available ? <ShieldCheck size={14} className="mr-1" /> : <ShieldAlert size={14} className="mr-1" />} Bundled intel
          </div>
          {status?.bundled.available ? (
            <>
              <div className="text-white mb-1">{status.bundled.file} · signature verified ({status.bundled.signed_by})</div>
              {status.bundled.sources?.map(s => (
                <div key={s.id} className="text-gray-400">{s.name} {s.version}: {s.records.toLocaleString()} records</div>
              ))}
            </>
          ) : (
            <div className="text-[#FF4444]">{status ? `Unavailable: ${status.bundled.error}` : 'Loading…'}</div>
          )}
        </div>
        <div className={card} style={{ borderLeftColor: enabledFeeds.length ? '#10B981' : '#8899AA' }}>
          <div className="text-[var(--color-muted)] mb-2 flex items-center"><ListChecks size={14} className="mr-1" /> IP reputation</div>
          {enabledFeeds.length ? enabledFeeds.map(f => (
            <div key={f.feed} className="text-gray-300">{f.name}: {f.records.toLocaleString()} ({f.status}{f.fetched_at ? `, ${f.fetched_at.slice(0, 16).replace('T', ' ')}` : ''})</div>
          )) : <div className="text-gray-400">No feeds enabled (LSADRA_INTEL_FEEDS).</div>}
          <div className="text-gray-400 mt-1">AbuseIPDB: {abuseConfigured ? 'key configured' : 'not configured'}</div>
        </div>
        <div className={card} style={{ borderLeftColor: status?.geo.available ? '#10B981' : '#8899AA' }}>
          <div className="text-[var(--color-muted)] mb-2 flex items-center"><Globe size={14} className="mr-1" /> Geolocation (local)</div>
          {status?.geo.available ? (
            <>
              <div className="text-white">{status.geo.database_type} · {status.geo.build_date}</div>
              <div className="text-gray-400 mt-1">{status.geo.attribution}</div>
            </>
          ) : <div className="text-gray-400">No local database. Run <code>python -m lsadra.intel geo-update</code>.</div>}
        </div>
      </section>

      {/* Lookup Section */}
      <section className="bg-[rgba(255,255,255,0.02)] border border-[rgba(0,240,255,0.15)] rounded p-6">
        <h3 className="text-xl font-display text-white mb-4">IP Lookup</h3>
        <div className="flex flex-wrap gap-4 mb-6 items-center">
          <div className="flex-1 min-w-[220px] relative">
            <Search className="absolute left-3 top-3 text-[var(--color-muted)]" size={18} />
            <input
              type="text"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleLookup(searchIp, askRemote); }}
              placeholder="Enter an IP address"
              className="w-full bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.3)] rounded pl-10 pr-4 py-2 text-white font-mono focus:outline-none focus:border-[var(--color-primary)]"
            />
          </div>
          {abuseConfigured && canQueryRemote && (
            <label className="flex items-center text-xs font-mono text-gray-300" title="Sends this IP to AbuseIPDB using your configured key">
              <input type="checkbox" className="mr-2" checked={askRemote} onChange={(e) => setAskRemote(e.target.checked)} />
              Ask AbuseIPDB
            </label>
          )}
          <button
            onClick={() => handleLookup(searchIp, askRemote)}
            disabled={loading}
            className="hud-button flex items-center bg-[var(--color-primary)] text-black font-bold"
          >
            <Search size={18} className="mr-2" />
            {loading ? 'Searching...' : 'Lookup'}
          </button>
        </div>

        {lookupError && <div className="text-[#FF4444] font-mono text-sm">{lookupError}</div>}

        {currentIntel && currentIntel.valid && (
          <div className="mt-6 animate-fade-in">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <div className={card} style={{ borderLeftColor: v.color }}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><AlertTriangle size={14} className="mr-1" /> Verdict</div>
                <div className="text-2xl font-bold" style={{ color: v.color }}>{v.label}</div>
              </div>
              <div className={card} style={{ borderLeftColor: '#4A9EFF' }}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Globe size={14} className="mr-1" /> Country</div>
                <div className="text-2xl font-bold text-white">{currentIntel.geo?.country_code || 'Unknown'}</div>
                {currentIntel.geo?.city && <div className="text-xs text-gray-400">{currentIntel.geo.city}</div>}
              </div>
              <div className={card} style={{ borderLeftColor: '#7C3AED' }}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><ListChecks size={14} className="mr-1" /> Feed matches</div>
                <div className="text-2xl font-bold text-white">{currentIntel.feed_matches?.length ?? 0}</div>
                <div className="text-xs text-gray-400">{currentIntel.sources_checked?.length ?? 0} source(s) checked</div>
              </div>
              <div className={card} style={{ borderLeftColor: '#7C3AED' }}>
                <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Activity size={14} className="mr-1" /> AbuseIPDB</div>
                <div className="text-2xl font-bold text-white">{currentIntel.abuseipdb ? `${currentIntel.abuseipdb.abuse_score}/100` : 'Not queried'}</div>
                {currentIntel.abuseipdb && <div className="text-xs text-gray-400">{currentIntel.abuseipdb.total_reports} reports</div>}
              </div>
            </div>
            <div className="text-sm text-gray-300 font-mono mb-4">{currentIntel.verdict?.reason}</div>
            {!!currentIntel.feed_matches?.length && (
              <table className="w-full text-left text-sm font-mono mb-4">
                <thead className="text-[var(--color-muted)]"><tr><th className="p-2">Source</th><th className="p-2">Listed as</th><th className="p-2">Label</th><th className="p-2">First seen</th></tr></thead>
                <tbody>
                  {currentIntel.feed_matches.map(m => (
                    <tr key={`${m.feed}-${m.indicator}`} className="border-t border-[rgba(255,255,255,0.05)] text-gray-300">
                      <td className="p-2">{m.name}</td><td className="p-2">{m.indicator}</td><td className="p-2">{m.label}</td><td className="p-2">{m.first_seen?.slice(0, 10)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <details className="bg-[rgba(0,0,0,0.3)] border border-[rgba(255,255,255,0.1)] rounded p-4">
              <summary className="text-sm font-bold text-white cursor-pointer">Full intel report</summary>
              <pre className="text-xs font-mono text-[var(--color-primary)] whitespace-pre-wrap mt-2">{JSON.stringify(currentIntel, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Flagged IPs */}
      <section>
        <h3 className="text-xl font-display text-white mb-4">Top Anomalous External IPs</h3>
        {flagged.length === 0 ? (
          <div className="text-[var(--color-muted)] font-mono text-sm">No external IPs in anomalies yet.</div>
        ) : (
          <>
            <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 h-80 mb-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={flagged} margin={{ top: 20, right: 30, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
                  <XAxis dataKey="ip" stroke="#8899aa" tick={{ fontSize: 12 }} dy={10} />
                  <YAxis stroke="#8899aa" allowDecimals={false} />
                  <RechartsTooltip contentStyle={{ backgroundColor: '#1A1F2E', borderColor: 'rgba(0,240,255,0.3)' }} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                  <Bar dataKey="anomalies" radius={[4, 4, 0, 0]}>
                    {flagged.map((entry) => (
                      <Cell key={entry.ip} fill={verdictStyle(entry.verdict).color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded overflow-hidden">
              <table className="w-full text-left text-sm font-mono">
                <thead className="bg-[rgba(0,240,255,0.05)] border-b border-[rgba(0,240,255,0.15)] text-[var(--color-muted)]">
                  <tr><th className="p-3">IP</th><th className="p-3">Verdict</th><th className="p-3">Anomalies</th><th className="p-3">Country</th><th className="p-3">Feed matches</th><th className="p-3">AbuseIPDB</th><th className="p-3">Last seen</th></tr>
                </thead>
                <tbody>
                  {flagged.map(row => (
                    <tr key={row.ip} className="border-b border-[rgba(255,255,255,0.05)] hover:bg-[rgba(0,240,255,0.05)] transition-colors text-gray-300">
                      <td className="p-3 text-white cursor-pointer hover:text-[var(--color-primary)] underline decoration-dotted" onClick={() => handleLookup(row.ip)}>{row.ip}</td>
                      <td className="p-3" style={{ color: verdictStyle(row.verdict).color }}>{verdictStyle(row.verdict).label}</td>
                      <td className="p-3">{row.anomalies}</td>
                      <td className="p-3">{row.country_code || '—'}</td>
                      <td className="p-3">{row.feed_matches}</td>
                      <td className="p-3">{row.abuse_score ?? '—'}</td>
                      <td className="p-3">{row.last_seen?.slice(0, 16)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {/* KEV */}
      <section>
        <h3 className="text-xl font-display text-white mb-4 flex items-center"><Database size={20} className="mr-2 text-[var(--color-primary)]" /> Known Exploited Vulnerabilities (CISA KEV)</h3>
        <input
          type="text"
          value={kevQuery}
          onChange={(e) => setKevQuery(e.target.value)}
          placeholder="Search CVE, vendor or product"
          className="w-full mb-4 bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.3)] rounded px-4 py-2 text-white font-mono focus:outline-none focus:border-[var(--color-primary)]"
        />
        <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded overflow-hidden">
          <table className="w-full text-left text-sm font-mono">
            <thead className="bg-[rgba(0,240,255,0.05)] border-b border-[rgba(0,240,255,0.15)] text-[var(--color-muted)]">
              <tr><th className="p-3">CVE</th><th className="p-3">Vendor</th><th className="p-3">Product</th><th className="p-3">Name</th><th className="p-3">Added</th><th className="p-3">Ransomware</th></tr>
            </thead>
            <tbody>
              {kevRows.map(r => (
                <tr key={r.cve_id} className="border-b border-[rgba(255,255,255,0.05)] text-gray-300">
                  <td className="p-3 text-white">
                    <a href={`https://nvd.nist.gov/vuln/detail/${r.cve_id}`} target="_blank" rel="noopener noreferrer" className="hover:text-[var(--color-primary)] underline decoration-dotted">{r.cve_id}</a>
                  </td>
                  <td className="p-3">{r.vendor}</td>
                  <td className="p-3">{r.product}</td>
                  <td className="p-3 truncate max-w-[320px]">{r.name}</td>
                  <td className="p-3">{r.date_added}</td>
                  <td className="p-3">{r.known_ransomware_use ? <span className="text-[#FF4444]">Known</span> : ''}</td>
                </tr>
              ))}
              {kevRows.length === 0 && (
                <tr><td colSpan={6} className="p-3 text-[var(--color-muted)]">No matching entries.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};

export default ThreatIntel;
