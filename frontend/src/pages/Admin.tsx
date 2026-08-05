import React, { useEffect, useState } from 'react';
import { Server, Activity, Shield, Users, Database, FlaskConical, Key, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { getUsers, updateUserRole, updateUserPassword, getStats, register, getHealth, getIncidents, getAnomalies, getKpis, getModelRegistry, retrainModel, getEntity } from '../services/api';

const MOCK_STATS = { normalized_events: 5340234, anomalies: 854, incidents: 42, devices: 45, model_registry: 2, feedback_labels: 5, users: 4, agents: 4 };

const Admin = () => {
  const [activeTab, setActiveTab]   = useState('users');
  const [users, setUsers]           = useState<any[]>([]);
  const [stats, setStats]           = useState<any>({});
  const [editRow, setEditRow]       = useState<string | null>(null);
  const [editRole, setEditRole]     = useState('ANALYST');
  const [editPass, setEditPass]     = useState('');
  const [saving, setSaving]         = useState(false);
  const [saveMsg, setSaveMsg]       = useState('');

  // Create user
  const [newUser, setNewUser] = useState({ username:'', password:'', role:'ANALYST' });
  const [createMsg, setCreateMsg] = useState('');

  // Testing
  const [testResults, setTestResults] = useState<any[]>([]);
  const [testing, setTesting]         = useState(false);

  useEffect(() => { fetchUsers(); fetchStats(); }, []);

  const fetchUsers = async () => {
    try {
      const r = await getUsers();
      if ((r as any)?.data) setUsers((r as any).data);
    } catch {}
  };

  const fetchStats = async () => {
    try {
      const r = await getStats();
      const statsD = Object.keys((r as any)?.data || {}).length > 0 ? (r as any).data : MOCK_STATS;
      setStats(statsD);
    } catch { setStats(MOCK_STATS); }
  };

  const startEdit = (u: any) => {
    setEditRow(u.id); setEditRole(u.role); setEditPass(''); setSaveMsg('');
  };

  const saveEdit = async (uid: string) => {
    setSaving(true); setSaveMsg('');
    try {
      await updateUserRole(uid, editRole);
      if (editPass.trim()) await updateUserPassword(uid, editPass.trim());
      setUsers(prev => prev.map(u => u.id === uid ? { ...u, role: editRole } : u));
      
      const currentUsr = localStorage.getItem('sentinel_username');
      const editedUsr = users.find(u => u.id === uid)?.username;
      
      setEditRow(null);
      setSaveMsg('✓ Saved');
      
      if (currentUsr === editedUsr) {
        window.alert('Your role has been updated. Reloading to apply changes...');
        window.location.reload();
      } else {
        window.alert('User updated successfully.');
      }
    } catch { setSaveMsg('✗ Failed'); }
    finally { setSaving(false); setTimeout(() => setSaveMsg(''), 3000); }
  };

  const handleCreate = async () => {
    if (!newUser.username || !newUser.password) { setCreateMsg('Username and password required.'); return; }
    try {
      await register(newUser);
      setCreateMsg(`✓ User "${newUser.username}" created.`);
      window.alert(`User "${newUser.username}" created successfully.`);
      setNewUser({ username:'', password:'', role:'ANALYST' });
      fetchUsers();
    } catch (e: any) { setCreateMsg(`✗ ${e?.response?.data?.detail || 'Failed'}`); }
    setTimeout(() => setCreateMsg(''), 4000);
  };

  const runTests = async () => {
    setTesting(true); setTestResults([]);
    const role = localStorage.getItem('sentinel_role') || 'UNKNOWN';
    const user = localStorage.getItem('sentinel_username') || 'UNKNOWN';
    const mockCreds = (() => { try { return JSON.parse(localStorage.getItem('sentinel_mock_creds') || '{}'); } catch { return {}; } })();

    const tests = [
      {
        name: 'Backend Reachability',
        category: 'Infrastructure',
        fn: () => getHealth(),
        warnDetail: 'FastAPI backend at http://localhost:8000 is unreachable.',
        warnImpact: 'All live API calls will fail. Dashboard is running in Mock/Demo mode.',
        warnFix: '1. Run: cd lsadra && python main.py\n2. Ensure port 8000 is not blocked\n3. Check .env for correct HOST/PORT settings',
      },
      {
        name: 'Mock Auth — admin',
        category: 'Authentication',
        fn: async () => {
          const cred = mockCreds['admin'] || { password:'admin' };
          if (cred.password !== 'admin' && !mockCreds['admin']) throw new Error('Seed cred used (admin/admin)');
          return { data: { ok: true, resolved: cred.password ? 'override' : 'seed', role: cred.role || 'ADMIN' } };
        },
        warnDetail: 'admin credentials not found in mock store — using seed default.',
        warnFix: 'Expected: login as admin / admin. If changed, use new password.',
      },
      {
        name: 'Mock Auth — testuser',
        category: 'Authentication',
        fn: async () => {
          const cred = mockCreds['testuser'] || { password:'testuser' };
          return { data: { ok: true, password_source: mockCreds['testuser'] ? 'override' : 'seed' } };
        },
        warnDetail: 'testuser not found in mock store.',
        warnFix: 'Login with testuser / testuser to access full mock data mode.',
      },
      {
        name: 'Mock Auth — jsmith',
        category: 'Authentication',
        fn: async () => {
          const cred = mockCreds['jsmith'];
          return { data: { ok: true, password_source: cred ? `override: "${cred.password}"` : 'seed: "jsmith"' } };
        },
        warnDetail: 'Password override for jsmith not found.',
        warnFix: 'If you changed jsmith password in Admin, the new password is stored locally. Login with the new password.',
      },
      {
        name: 'LocalStorage RBAC',
        category: 'Authorization',
        fn: async () => {
          if (!role || role === 'UNKNOWN') throw new Error('No role in localStorage');
          return { data: { username: user, role, token_present: !!localStorage.getItem('sentinel_token') } };
        },
        warnDetail: `Current session role is "${role}" for user "${user}". Token: ${localStorage.getItem('sentinel_token') ? 'present' : 'missing'}.`,
        warnFix: 'Log out and log back in. If role is wrong, Admin can change it under User Management.',
      },
      {
        name: 'Mock Data Layer — Incidents',
        category: 'Data Layer',
        fn: async () => {
          const r = await getIncidents() as any;
          const count = r?.data?.incidents?.length || 0;
          if (count === 0) throw new Error('No incidents in mock data');
          return { data: { incidents: count, first_id: r.data.incidents[0]?.id } };
        },
        warnDetail: 'No incidents returned from API or mock layer.',
        warnFix: '1. Login as testuser to activate mock data\n2. Check api.ts getMockData(\'/api/incidents\')\n3. Verify MOCK_ENTITIES is exported correctly',
      },
      {
        name: 'Mock Data Layer — Anomalies',
        category: 'Data Layer',
        fn: async () => {
          const r = await getAnomalies() as any;
          const count = Array.isArray(r?.data) ? r.data.length : 0;
          if (count === 0) throw new Error('No anomalies returned');
          return { data: { anomalies: count, sample: r.data[0]?.threat_type } };
        },
        warnDetail: 'No anomalies returned — live feed and threat tiles will show empty.',
        warnFix: '1. Ensure testuser is logged in (activates mock)\n2. Check getAnomalies() in api.ts\n3. Backend anomaly endpoint may need /api/dashboard/anomalies',
      },
      {
        name: 'Mock Data Layer — KPIs',
        category: 'Data Layer',
        fn: async () => {
          const r = await getKpis() as any;
          if (typeof r?.data?.total_events_24h !== 'number') throw new Error('KPI data missing total_events_24h');
          return { data: { events: r.data.total_events_24h?.toLocaleString(), anomalies: r.data.total_anomalies_24h } };
        },
        warnDetail: 'KPI tile data missing — Command Center and Analytics top cards will show 0.',
        warnFix: 'Check getKpis() mock path in api.ts. Ensure getMockData calls tickLive() for /api/dashboard/kpis.',
      },
      {
        name: 'Device Filter (localStorage)',
        category: 'Device Management',
        fn: async () => {
          const raw = localStorage.getItem('sentinel_device_filter');
          const filter = raw ? JSON.parse(raw) : null;
          return { data: { filter_active: !!filter, selected_devices: filter?.join(', ') || 'None (all devices shown)' } };
        },
        warnDetail: 'Device filter not set.',
        warnFix: 'Go to Device Behavior → check devices → Apply Filter. Dashboard views will scope to selected devices.',
      },
      {
        name: 'Model Registry Endpoint',
        category: 'ML Pipeline',
        fn: async () => {
          const r = await getModelRegistry() as any;
          const models = Array.isArray(r?.data) ? r.data : [];
          if (models.length === 0) throw new Error('No models in registry');
          return { data: { models: models.length, names: models.map((m: any) => m.model_name).join(', ') } };
        },
        warnDetail: 'Model registry returned empty — Model Analytics page will show nothing.',
        warnFix: '1. Check getModelRegistry() in api.ts\n2. Backend: GET /api/dashboard/models must return [{model_name, model_type, event_count, trained_at}]\n3. Run retrain to create initial models',
      },
      {
        name: 'Retrain Mock (Event Count)',
        category: 'ML Pipeline',
        fn: async () => {
          const r = await retrainModel() as any;
          if (r?.data?.status !== 'ok') throw new Error('Retrain returned non-ok status');
          return { data: { events: r.data.events?.toLocaleString(), message: r.data.message?.slice(0, 60) } };
        },
        warnDetail: 'Retrain endpoint returned an error or unreachable.',
        warnFix: '1. Backend must expose POST /api/dashboard/retrain\n2. In demo mode, isTestUser() or ADMIN role triggers mock\n3. Check retrainModel() in api.ts',
      },
      {
        name: 'Investigate Entity Pivot',
        category: 'Investigation',
        fn: async () => {
          const r = await getEntity('inc_101') as any;
          if (!r?.data?.entity) throw new Error('inc_101 not found in MOCK_ENTITIES');
          const nodes = r.data.relationships?.length || 0;
          return { data: { entity: r.data.entity, type: r.data.type, relationships: nodes, playbook: r.data.playbook } };
        },
        warnDetail: 'Entity inc_101 not found — Investigate pivots will loop or show no data.',
        warnFix: 'Check MOCK_ENTITIES in api.ts. Ensure inc_101, inc_102, inc_103, jsmith, WKS-112-X etc. are all defined.',
      },
    ];

    const results: any[] = [];
    for (const t of tests) {
      try {
        const r = await t.fn();
        results.push({
          name: t.name, category: t.category, status: 'PASS',
          detail: JSON.stringify((r as any)?.data).slice(0, 100),
          expanded: false,
        });
      } catch (e: any) {
        results.push({
          name: t.name, category: t.category, status: 'WARN',
          detail: e.message || 'Error',
          warnDetail: t.warnDetail || '',
          warnFix: t.warnFix || '',
          expanded: false,
        });
      }
      setTestResults([...results]);
      await new Promise(res => setTimeout(res, 250));
    }
    setTesting(false);
  };

  const toggleExpand = (i: number) => setTestResults(prev =>
    prev.map((t, idx) => idx === i ? { ...t, expanded: !t.expanded } : t)
  );

  const tabs = [
    { id:'users',   icon:<Users size={15}/>,        label:'User Management' },
    { id:'system',  icon:<Database size={15}/>,     label:'System Status' },
    { id:'testing', icon:<FlaskConical size={15}/>, label:'Testing' },
  ];

  const roleColor = (r: string) =>
    r === 'ADMIN' ? 'text-[#FF4444] border-[rgba(255,68,68,0.4)]' :
    r === 'ANALYST' ? 'text-[var(--color-primary)] border-[rgba(0,240,255,0.3)]' :
    'text-[var(--color-muted)] border-[rgba(255,255,255,0.1)]';

  return (
    <div className="flex flex-col h-full space-y-5 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <Server className="text-[var(--color-primary)] mr-3" size={28}/>
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Administration</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">RBAC · System Status · Diagnostics</p>
        </div>
      </header>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[rgba(0,240,255,0.15)] pb-0 shrink-0">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`flex items-center gap-2 text-xs font-mono uppercase tracking-widest px-4 py-2.5 border-b-2 transition-colors ${activeTab===t.id ? 'text-[var(--color-primary)] border-[var(--color-primary)]' : 'text-[var(--color-muted)] border-transparent hover:text-white'}`}>
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {/* USER MANAGEMENT */}
      {activeTab === 'users' && (
        <div className="space-y-8">
          {/* Existing Users */}
          <section>
            <h3 className="text-lg font-display text-white mb-3 flex items-center gap-2"><Shield size={18}/> Existing Users</h3>
            <div className="border border-[rgba(0,240,255,0.15)] rounded overflow-hidden">
              <table className="w-full text-sm font-mono">
                <thead className="bg-[rgba(0,240,255,0.04)] border-b border-[rgba(0,240,255,0.15)] text-[10px] text-[var(--color-muted)] uppercase">
                  <tr>
                    <th className="p-3 font-normal text-left">Username</th>
                    <th className="p-3 font-normal text-left">Role</th>
                    <th className="p-3 font-normal text-left">Created</th>
                    <th className="p-3 font-normal text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <React.Fragment key={u.id}>
                      <tr className="border-b border-[rgba(255,255,255,0.04)] hover:bg-[rgba(255,255,255,0.02)] transition-colors">
                        <td className="p-3 text-white font-bold">{u.username}</td>
                        <td className="p-3">
                          <span className={`text-[10px] px-2 py-0.5 border ${roleColor(u.role)}`}>{u.role}</span>
                        </td>
                        <td className="p-3 text-[var(--color-muted)] text-xs">{new Date(u.created_at).toLocaleDateString()}</td>
                        <td className="p-3">
                          <button onClick={() => editRow === u.id ? setEditRow(null) : startEdit(u)}
                            className="text-[10px] font-mono px-3 py-1 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] hover:bg-[rgba(0,240,255,0.06)] transition-colors flex items-center gap-1">
                            <Key size={10}/> {editRow === u.id ? 'Cancel' : 'Edit'}
                          </button>
                        </td>
                      </tr>
                      {editRow === u.id && (
                        <tr className="bg-[rgba(0,240,255,0.03)] border-b border-[rgba(0,240,255,0.15)]">
                          <td colSpan={4} className="p-4">
                            <div className="flex items-end gap-3">
                              <div>
                                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">New Role</label>
                                <select value={editRole} onChange={e => setEditRole(e.target.value)}
                                  className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
                                  {['ADMIN','ANALYST','VIEWER'].map(r => <option key={r} value={r}>{r}</option>)}
                                </select>
                              </div>
                              <div>
                                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">New Password (optional)</label>
                                <input type="password" value={editPass} onChange={e => setEditPass(e.target.value)}
                                  placeholder="Leave blank to keep current"
                                  className="bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none w-56"/>
                              </div>
                              <button onClick={() => saveEdit(u.id)} disabled={saving}
                                className="hud-button bg-[var(--color-primary)] text-black font-bold text-xs px-4 py-2">
                                {saving ? 'Saving…' : 'Save'}
                              </button>
                              {saveMsg && <span className={`text-xs font-mono ${saveMsg.startsWith('✓') ? 'text-[#05FFA1]' : 'text-[#FF4444]'}`}>{saveMsg}</span>}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Create User */}
          <section>
            <h3 className="text-lg font-display text-white mb-3 flex items-center gap-2"><Users size={18}/> Create New User</h3>
            <div className="hud-panel p-5">
              <div className="grid grid-cols-4 gap-4 mb-4">
                {[
                  { label:'Username', key:'username', type:'text' },
                  { label:'Password', key:'password', type:'password' },
                ].map(({ label, key, type }) => (
                  <div key={key}>
                    <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">{label}</label>
                    <input type={type} value={(newUser as any)[key]} onChange={e => setNewUser(u => ({ ...u, [key]: e.target.value }))}
                      className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]"/>
                  </div>
                ))}
                <div>
                  <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Role</label>
                  <select value={newUser.role} onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}
                    className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none">
                    {['ANALYST','ADMIN','VIEWER'].map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div className="flex items-end">
                  <button onClick={handleCreate} className="w-full hud-button bg-[var(--color-primary)] text-black font-bold text-xs">Create User</button>
                </div>
              </div>
              {createMsg && <p className={`text-xs font-mono ${createMsg.startsWith('✓') ? 'text-[#05FFA1]' : 'text-[#FF4444]'}`}>{createMsg}</p>}
            </div>
          </section>
        </div>
      )}

      {/* SYSTEM STATUS */}
      {activeTab === 'system' && (
        <div className="space-y-6">
          <h3 className="text-lg font-display text-white flex items-center gap-2"><Database size={18}/> Database Statistics</h3>
          <div className="grid grid-cols-4 gap-4">
            {Object.entries(stats).map(([k, v]) => (
              <div key={k} className="hud-panel p-4 border-l-2 border-l-[var(--color-primary)]">
                <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-2">{k.replace(/_/g,' ')}</div>
                <div className="text-2xl font-bold text-white">{typeof v === 'number' ? (v as number).toLocaleString() : String(v)}</div>
              </div>
            ))}
          </div>
          <div className="bg-[rgba(200,200,0,0.08)] border border-[#cccc00] p-4 text-[#cccc00] flex items-center gap-3 font-mono text-xs rounded">
            <AlertTriangle size={14}/>
            <span>TLS enforcement is disabled. Set <code>LSADRA_REQUIRE_TLS=true</code> for production deployment.</span>
          </div>
          <div className="bg-[rgba(5,255,161,0.05)] border border-[rgba(5,255,161,0.2)] p-4 font-mono text-xs text-[#05FFA1] rounded">
            Backend: FastAPI · DB: SQLite (LSADRA V4) · ML: Ensemble + Autoencoder (2 models active)
          </div>
        </div>
      )}

      {/* TESTING */}
      {activeTab === 'testing' && (
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-display text-white flex items-center gap-2"><FlaskConical size={18}/> Diagnostic Testing</h3>
            <button onClick={runTests} disabled={testing}
              className="hud-button flex items-center gap-2 bg-[var(--color-primary)] text-black font-bold text-sm">
              <Activity size={14}/> {testing ? 'Running…' : 'Run All Tests (12)'}
            </button>
          </div>

          <div className="hud-panel p-5">
            <p className="text-xs font-mono text-[var(--color-muted)] mb-4 leading-relaxed">
              Runs 12 diagnostic tests across 5 categories: Infrastructure · Authentication · Data Layer · Device Management · ML Pipeline.
              Click any <span className="text-[#FFD700]">WARN</span> or <span className="text-[#FF4444]">FAIL</span> row to expand the root cause and remediation steps.
            </p>
            {testResults.length === 0 && !testing && (
              <div className="text-center text-[var(--color-muted)] font-mono text-sm py-8">Click "Run All Tests" to begin diagnostics.</div>
            )}
            <div className="space-y-2">
              {testResults.map((t, i) => (
                <div key={i}>
                  <div
                    onClick={() => t.status !== 'PASS' && toggleExpand(i)}
                    className={`flex items-start gap-3 p-3 border rounded text-xs font-mono transition-colors ${
                      t.status === 'PASS'
                        ? 'border-[rgba(5,255,161,0.3)] bg-[rgba(5,255,161,0.04)]'
                        : t.status === 'WARN'
                        ? 'border-[rgba(255,215,0,0.3)] bg-[rgba(255,215,0,0.04)] cursor-pointer hover:bg-[rgba(255,215,0,0.08)]'
                        : 'border-[rgba(255,68,68,0.3)] bg-[rgba(255,68,68,0.04)] cursor-pointer hover:bg-[rgba(255,68,68,0.08)]'
                    }`}>
                    {t.status === 'PASS'
                      ? <CheckCircle size={14} className="text-[#05FFA1] flex-shrink-0 mt-0.5"/>
                      : t.status === 'WARN'
                      ? <AlertTriangle size={14} className="text-[#FFD700] flex-shrink-0 mt-0.5"/>
                      : <XCircle size={14} className="text-[#FF4444] flex-shrink-0 mt-0.5"/>}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <span className={`font-bold w-52 flex-shrink-0 ${
                          t.status==='PASS'?'text-[#05FFA1]':t.status==='WARN'?'text-[#FFD700]':'text-[#FF4444]'
                        }`}>{t.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 border border-[rgba(255,255,255,0.1)] text-[var(--color-muted)]">{t.category}</span>
                        <span className="text-[var(--color-muted)] truncate flex-1">{t.detail}</span>
                        {t.status !== 'PASS' && (
                          <span className="text-[var(--color-muted)] ml-auto flex-shrink-0">
                            {t.expanded ? '▲ collapse' : '▼ expand'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded detail panel */}
                  {t.expanded && t.status !== 'PASS' && (
                    <div className={`ml-6 mt-0.5 p-4 rounded-b border-x border-b text-xs font-mono space-y-3 ${
                      t.status === 'WARN'
                        ? 'border-[rgba(255,215,0,0.3)] bg-[rgba(255,215,0,0.03)]'
                        : 'border-[rgba(255,68,68,0.3)] bg-[rgba(255,68,68,0.03)]'
                    }`}>
                      {t.warnDetail && (
                        <div>
                          <div className="text-[10px] uppercase text-[var(--color-muted)] mb-1">Root Cause / Detail</div>
                          <div className="text-white leading-relaxed">{t.warnDetail}</div>
                        </div>
                      )}
                      {t.warnFix && (
                        <div>
                          <div className="text-[10px] uppercase text-[var(--color-muted)] mb-1">Remediation Steps</div>
                          <pre className="text-[#05FFA1] whitespace-pre-wrap leading-relaxed text-[11px]">{t.warnFix}</pre>
                        </div>
                      )}
                      <div className="text-[10px] text-[var(--color-muted)] pt-1 border-t border-[rgba(255,255,255,0.05)]">
                        Error: {t.detail}
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {testing && (
                <div className="flex items-center gap-3 p-3 border border-[rgba(0,240,255,0.2)] text-xs font-mono text-[var(--color-primary)]">
                  <span className="w-3 h-3 rounded-full border-2 border-[var(--color-primary)] border-t-transparent animate-spin flex-shrink-0"/>
                  Running next test…
                </div>
              )}
            </div>
            {testResults.length > 0 && !testing && (
              <div className="mt-4 pt-4 border-t border-[rgba(255,255,255,0.05)] flex items-center gap-6 text-xs font-mono">
                <span className="text-[#05FFA1] font-bold">✓ {testResults.filter(t=>t.status==='PASS').length} PASS</span>
                <span className="text-[#FFD700] font-bold">⚠ {testResults.filter(t=>t.status==='WARN').length} WARN</span>
                <span className="text-[#FF4444] font-bold">✗ {testResults.filter(t=>t.status==='FAIL').length} FAIL</span>
                <span className="text-[var(--color-muted)] ml-auto">Click WARN/FAIL rows to expand remediation</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Admin;
