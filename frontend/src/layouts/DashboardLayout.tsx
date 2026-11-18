import React, { useState } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, Activity, Search, AlertOctagon, Settings, Database, LogOut, User, X, Eye, EyeOff, FileText } from 'lucide-react';
import { exportReport, logout } from '../services/api';

const DashboardLayout = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const role = localStorage.getItem('sentinel_role') || 'ANALYST';
  const username = localStorage.getItem('sentinel_username') || 'T. Analyst';
  const initials = username.slice(0, 2).toUpperCase();

  const [showProfile, setShowProfile] = useState(false);
  const [editMode, setEditMode]       = useState(false);
  const [newDisplay, setNewDisplay]   = useState(username);
  const [newPass, setNewPass]         = useState('');
  const [showPass, setShowPass]       = useState(false);

  const navItems = [
    { name: 'Command Center',  path: '/app/dashboard',  icon: <Shield size={18}/> },
    { name: 'Live Alerts',     path: '/app/stream',     icon: <Activity size={18}/> },
    { name: 'Analytics',       path: '/app/analytics',  icon: <Activity size={18}/> },
    { name: 'Device Behavior', path: '/app/devices',    icon: <Database size={18}/> },
    { name: 'Model Analytics', path: '/app/models',     icon: <Database size={18}/> },
    { name: 'Threat Intel',    path: '/app/intel',      icon: <AlertOctagon size={18}/> },
    { name: 'Investigate',     path: '/app/investigate',icon: <Search size={18}/> },
    { name: 'Response',        path: '/app/response',   icon: <AlertOctagon size={18}/> },
    { name: 'Feedback',        path: '/app/feedback',   icon: <Activity size={18}/> },
    { name: 'Connect Device',  path: '/app/connect',    icon: <Settings size={18}/> },
    ...(role === 'ADMIN' ? [{ name: 'Admin', path: '/app/admin', icon: <Settings size={18}/> }] : []),
  ];

  const handleSignOut = async () => {
    await logout();  // ends the session on the server too (G-9)
    localStorage.clear();
    navigate('/login');
  };

  const handleSaveProfile = () => {
    if (newDisplay.trim()) localStorage.setItem('sentinel_username', newDisplay.trim());
    setEditMode(false);
    setShowProfile(false);
  };

  const handleExport = async () => {
    try {
      const res = await exportReport();
      const blob = (res as any).data;
      if (!blob) throw new Error('No data');
      const isTxt = blob.type === 'text/plain';
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `LSADRA-Report-${new Date().toISOString().split('T')[0]}${isTxt?'.txt':'.pdf'}`);
      document.body.appendChild(link);
      link.click();
      window.alert(`SOC Report generated (${isTxt?'Simulation TEXT':'Production PDF'}).`);
    } catch (err) {
      console.error(err);
      window.alert('Error generating report.');
    }
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-[var(--color-background)] text-[var(--color-text)]">
      {/* Sidebar */}
      <aside className="w-60 flex flex-col border-r border-[rgba(0,240,255,0.15)] bg-[var(--color-surface-dim)]">
        {/* Brand */}
        <div className="p-5 border-b border-[rgba(0,240,255,0.15)]">
          <h1 className="text-xl font-bold tracking-widest text-[var(--color-primary)] font-display uppercase">
            LSADRA
          </h1>
          <p className="text-[10px] text-[var(--color-muted)] mt-0.5 font-mono uppercase">V4 · SOC Platform</p>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-y-auto custom-scrollbar">
          <ul className="space-y-0.5">
            {navItems.map(item => {
              const isActive = location.pathname.startsWith(item.path);
              return (
                <li key={item.name}>
                  <Link to={item.path}
                    className={`flex items-center px-5 py-2.5 font-display uppercase tracking-wider text-xs transition-colors ${
                      isActive
                        ? 'bg-[rgba(0,240,255,0.08)] text-[var(--color-primary)] border-r-2 border-[var(--color-primary)]'
                        : 'text-[var(--color-muted)] hover:text-white hover:bg-[rgba(255,255,255,0.04)]'
                    }`}>
                    <span className="mr-3">{item.icon}</span>
                    {item.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* User Profile Footer */}
        <div className="border-t border-[rgba(0,240,255,0.15)] relative">
          <button
            onClick={() => setShowProfile(o => !o)}
            className="w-full flex items-center gap-3 p-4 hover:bg-[rgba(255,255,255,0.04)] transition-colors text-left group"
          >
            <div className="w-8 h-8 rounded-full bg-[var(--color-surface-high)] flex items-center justify-center border border-[var(--color-primary)] flex-shrink-0">
              <span className="font-display font-bold text-[var(--color-primary)] text-xs">{initials}</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold font-display truncate text-white">{username}</p>
              <p className="text-[10px] text-[var(--color-muted)] font-mono">{role} · Tier 2</p>
            </div>
            <Settings size={14} className="text-[var(--color-muted)] group-hover:text-[var(--color-primary)] transition-colors flex-shrink-0"/>
          </button>

          {/* Export Action */}
          <div className="px-5 py-3 border-t border-[rgba(0,240,255,0.08)]">
            <button onClick={handleExport} className="w-full flex items-center justify-center gap-2 py-2 border border-[rgba(0,240,255,0.4)] text-[var(--color-primary)] text-[10px] font-mono uppercase tracking-widest hover:bg-[rgba(0,240,255,0.06)] transition-colors rounded-sm">
              <FileText size={12}/> Generate SOC Report
            </button>
          </div>

          {/* Profile popup */}
          {showProfile && (
            <div className="absolute bottom-full left-0 right-0 mb-1 bg-[rgba(10,15,25,0.98)] border border-[rgba(0,240,255,0.3)] shadow-[0_0_30px_rgba(0,240,255,0.1)] z-50">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(255,255,255,0.06)]">
                <span className="text-xs font-mono text-[var(--color-primary)] uppercase tracking-widest">Account</span>
                <button onClick={() => { setShowProfile(false); setEditMode(false); }} className="text-[var(--color-muted)] hover:text-white">
                  <X size={14}/>
                </button>
              </div>

              {!editMode ? (
                <div className="p-4 space-y-3">
                  <div>
                    <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase">Username</div>
                    <div className="text-white font-mono text-sm">{username}</div>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase">Role</div>
                    <div className="text-[var(--color-primary)] font-mono text-sm">{role}</div>
                  </div>
                  <button onClick={() => setEditMode(true)}
                    className="w-full flex items-center justify-center gap-2 border border-[rgba(0,240,255,0.3)] text-[var(--color-primary)] py-2 text-xs font-mono hover:bg-[rgba(0,240,255,0.06)] transition-colors">
                    <User size={12}/> Edit Credentials
                  </button>
                  <button onClick={handleSignOut}
                    className="w-full flex items-center justify-center gap-2 border border-[rgba(255,68,68,0.4)] text-[#FF4444] py-2 text-xs font-mono hover:bg-[rgba(255,68,68,0.08)] transition-colors">
                    <LogOut size={12}/> Sign Out
                  </button>
                </div>
              ) : (
                <div className="p-4 space-y-3">
                  <div>
                    <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Display Name</label>
                    <input value={newDisplay} onChange={e => setNewDisplay(e.target.value)}
                      className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]"/>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">New Password</label>
                    <div className="relative">
                      <input type={showPass ? 'text' : 'password'} value={newPass} onChange={e => setNewPass(e.target.value)}
                        placeholder="Leave blank to keep current"
                        className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 pr-8 focus:outline-none focus:border-[var(--color-primary)]"/>
                      <button type="button" onClick={() => setShowPass(s => !s)}
                        className="absolute right-2 top-2 text-[var(--color-muted)]">
                        {showPass ? <EyeOff size={12}/> : <Eye size={12}/>}
                      </button>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={handleSaveProfile}
                      className="flex-1 bg-[var(--color-primary)] text-black text-xs font-bold py-2 font-mono">Save</button>
                    <button onClick={() => setEditMode(false)}
                      className="flex-1 border border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] text-xs py-2 font-mono hover:text-white transition-colors">Cancel</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto bg-[var(--color-background)] relative">
        <div className="absolute inset-0 pointer-events-none"
          style={{ backgroundImage: 'linear-gradient(rgba(0,240,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,240,255,0.03) 1px,transparent 1px)', backgroundSize: '40px 40px' }}/>
        <div className="p-8 relative z-10">
          <Outlet/>
        </div>
      </main>
    </div>
  );
};

export default DashboardLayout;
