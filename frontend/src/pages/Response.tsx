import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BookOpen, CheckCircle2, Clock, Zap, Play } from 'lucide-react';

const PLAYBOOKS: Record<string, any> = {
  AD_ELEVATION_RESPONSE: {
    name: 'AD_ELEVATION_RESPONSE',
    description: 'Active Directory Privilege Elevation — Unauthorized admin token impersonation detected.',
    severity: 'HIGH',
    incident_type: 'Privilege Escalation',
    telemetry: { network_load: '18%', auth_failures: '104/s', sys_health: '97.2%' },
    steps: [
      { id: 1, label: 'IDENTIFY SOURCE', description: 'Pinpoint origin workstation and user account of the escalation event.', status: 'done', time: '09:14:22 UTC', command: 'Get-ADUser -Filter \'SamAccountName -eq "svc_admin_temp"\' | Select-Object MemberOf' },
      { id: 2, label: 'ISOLATE COMPROMISED ENDPOINT', description: 'Apply network isolation policy to the source machine.', status: 'done', time: '09:16:45 UTC', command: 'Invoke-CarbonBlack-Isolate -DeviceID WKS-112-X' },
      { id: 3, label: 'REVOKE PRIVILEGED ACCESS', description: 'Remove user from all privileged groups in Active Directory.', status: 'active', time: null, command: 'Remove-ADGroupMember -Identity "Enterprise Admins" -Members "svc_admin_temp" -Confirm:$false' },
      { id: 4, label: 'RESET USER PASSWORD', description: 'Force password reset and invalidate existing sessions.', status: 'pending', time: null, command: 'Set-ADAccountPassword -Identity "svc_admin_temp" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Temp@1234!" -Force)' },
      { id: 5, label: 'BROADCAST ALERT TO OPS', description: 'Notify SOC team and log all remediation actions.', status: 'pending', time: null, command: 'Send-SOCAlert -Severity HIGH -Message "AD Elevation remediated for svc_admin_temp"' },
    ],
  },
  RANSOMWARE_RESPONSE: {
    name: 'RANSOMWARE_RESPONSE',
    description: 'Ransomware Containment — Mass file encryption & C2 callback detected from endpoint.',
    severity: 'CRITICAL',
    incident_type: 'Ransomware Activity',
    telemetry: { network_load: '87%', auth_failures: '842/s', sys_health: '34.1%' },
    steps: [
      { id: 1, label: 'KILL MALICIOUS PROCESS', description: 'Terminate the encryption process on the affected host.', status: 'done', time: '10:02:11 UTC', command: 'Stop-Process -Name "cryptolocker.exe" -Force -ComputerName WKS-112-X' },
      { id: 2, label: 'NETWORK ISOLATE HOST', description: 'Cut all network access from the infected machine immediately.', status: 'done', time: '10:02:45 UTC', command: 'Invoke-CarbonBlack-Isolate -DeviceID WKS-112-X' },
      { id: 3, label: 'BLOCK C2 OUTBOUND IPs', description: 'Add known C2 IPs to firewall block list.', status: 'active', time: null, command: 'netsh advfirewall firewall add rule name="Block C2" dir=out remoteip=185.15.202.13 action=block' },
      { id: 4, label: 'SNAPSHOT & PRESERVE EVIDENCE', description: 'Take forensic snapshot of memory and disk before cleanup.', status: 'pending', time: null, command: 'Invoke-Forensic-Snapshot -Host WKS-112-X -OutputPath \\\\FORENSIC-SRV\\evidence\\' },
      { id: 5, label: 'RESTORE FROM BACKUP', description: 'Restore encrypted files from last clean backup.', status: 'pending', time: null, command: 'Restore-FileShare -Source \\\\BACKUP-01\\daily -Target \\\\FILE-SRV-01\\shares\\finance' },
      { id: 6, label: 'FULL SYSTEM RE-IMAGE', description: 'Wipe and re-image compromised endpoint from golden image.', status: 'pending', time: null, command: 'Invoke-SCCM-OSD -ComputerName WKS-112-X -TaskSequence GoldenImage_2024Q1' },
    ],
  },
  BRUTE_FORCE_RESPONSE: {
    name: 'BRUTE_FORCE_RESPONSE',
    description: 'Brute Force Mitigation — Credential stuffing attack against domain controller.',
    severity: 'MEDIUM',
    incident_type: 'Brute Force',
    telemetry: { network_load: '12%', auth_failures: '847/s', sys_health: '99.1%' },
    steps: [
      { id: 1, label: 'IDENTIFY SOURCE IP', description: 'Confirm attacking IP and geolocation.', status: 'done', time: '08:55:01 UTC', command: 'Get-NetTCPConnection -RemotePort 389 | Where RemoteAddress -eq "172.16.0.50"' },
      { id: 2, label: 'BLOCK SOURCE IP', description: 'Add firewall rule to block the offending IP.', status: 'done', time: '08:56:12 UTC', command: 'netsh advfirewall firewall add rule name="BF Block" dir=in remoteip=172.16.0.50 action=block' },
      { id: 3, label: 'UNLOCK LOCKED ACCOUNTS', description: 'Unlock accounts locked due to brute force attempts.', status: 'active', time: null, command: 'Search-ADAccount -LockedOut | Unlock-ADAccount' },
      { id: 4, label: 'ENFORCE MFA', description: 'Force MFA enrollment on all privileged accounts.', status: 'pending', time: null, command: 'Set-MsolUser -UserPrincipalName admin@corp.local -StrongAuthenticationRequirements $enforceMFA' },
    ],
  },
};

const DEFAULT_PLAYBOOK = 'AD_ELEVATION_RESPONSE';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#FF4444',
  HIGH: '#FF8C00',
  MEDIUM: '#FFD700',
  LOW: '#05FFA1',
};

const getAllPlaybooks = () => {
  const local = (() => { try { return JSON.parse(localStorage.getItem('sentinel_playbooks') || '{}'); } catch { return {}; } })();
  return { ...PLAYBOOKS, ...local };
};

const Response = () => {
  const [searchParams] = useSearchParams();
  const allPlaybooks = getAllPlaybooks();
  const playbookKey = searchParams.get('playbook') || DEFAULT_PLAYBOOK;
  const entityName = searchParams.get('entity') || 'N/A';
  const incidentId = searchParams.get('incident') || (entityName.startsWith('inc_') ? entityName : null);
  
  const [selectedPlaybook, setSelectedPlaybook] = useState(playbookKey);
  const [playbook, setPlaybook] = useState<any>(null);
  const [steps, setSteps] = useState<any[]>([]);
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const consoleRef = useRef<HTMLDivElement>(null);

  const [isCreating, setIsCreating] = useState(false);
  const [newPb, setNewPb] = useState({ 
    name:'', desc:'', sev:'MEDIUM', type:'Custom', 
    steps: [{ id: 1, label: 'IDENTIFY', description: 'Analyze source', command: '' }] 
  });

  const savePlaybook = () => {
    if (!newPb.name || newPb.steps.some(s => !s.command)) return alert('Name and commands for all steps required.');
    const key = newPb.name.replace(/\s+/g, '_').toUpperCase();
    const pb = {
      name: key, description: newPb.desc, severity: newPb.sev, incident_type: newPb.type,
      telemetry: { network_load: '0%', auth_failures: '0/s', sys_health: '100%' },
      steps: newPb.steps.map((s, idx) => ({ ...s, id: idx + 1, status: idx === 0 ? 'active' : 'pending', time: null }))
    };
    const local = (() => { try { return JSON.parse(localStorage.getItem('sentinel_playbooks') || '{}'); } catch { return {}; } })();
    local[key] = pb;
    localStorage.setItem('sentinel_playbooks', JSON.stringify(local));
    setIsCreating(false);
    setSelectedPlaybook(key);
  };

  useEffect(() => {
    const pbs = getAllPlaybooks();
    const mode = searchParams.get('mode');
    
    if (mode === 'create') {
      setIsCreating(true);
      setNewPb(p => ({ ...p, name: `PB_${incidentId || 'NEW'}` }));
    }

    // Auto-select playbook if incident is provided and has an assigned PB
    if (incidentId && !searchParams.get('playbook')) {
      const allIncidents = (() => { try { return JSON.parse(sessionStorage.getItem('sentinel_cached_incidents') || '[]'); } catch { return []; } })();
      // We don't have easy access to the incident list here without a search
      // But we can check if the incident is one of the known ones
      const mapping: Record<string,string> = { inc_101:'RANSOMWARE_RESPONSE', inc_102:'AD_ELEVATION_RESPONSE', inc_104:'AD_ELEVATION_RESPONSE' };
      if (mapping[incidentId] && mapping[incidentId] !== selectedPlaybook) {
        setSelectedPlaybook(mapping[incidentId]);
        return;
      }
    }

    const pb = pbs[selectedPlaybook] || pbs[DEFAULT_PLAYBOOK];
    setPlaybook(pb);
    
    // Check persistence for incident status
    const statusStore = JSON.parse(localStorage.getItem('sentinel_incident_status') || '{}');
    const currentStatus = incidentId ? statusStore[incidentId] : 'OPEN';
    
    if (currentStatus === 'RESOLVED') {
      setSteps(pb.steps.map((s: any) => ({ ...s, status: 'done', time: 'PREVIOUSLY_RESOLVED' })));
      setConsoleLog([
        `[SYSTEM] Initializing ${pb.name}...`,
        `[INFO]   Incident ${incidentId} was previously RESOLVED.`,
        ``,
        `[INFO]   Steps are shown for reference only.`,
      ]);
    } else {
      setSteps(pb.steps.map((s: any) => ({ ...s })));
      setConsoleLog([
        `[SYSTEM] Initializing ${pb.name}...`,
        `[INFO]   Incident type: ${pb.incident_type}`,
        `[INFO]   Severity: ${pb.severity}`,
        `[INFO]   Operator session secured.`,
        ``,
        ...pb.steps.filter((s: any) => s.status === 'done').map((s: any) =>
          `[COMPLETED] Step ${s.id}: ${s.label} @ ${s.time}`
        ),
        ``,
        `[PENDING] Awaiting operator action on active step...`,
      ]);
    }
  }, [selectedPlaybook, incidentId, searchParams]);

  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [consoleLog]);

  const executeStep = (step: any) => {
    if (step.status !== 'active') return;
    setIsExecuting(true);
    const ts = new Date().toLocaleTimeString();

    setConsoleLog(prev => [...prev,
      ``,
      `[EXECUTING] ${step.label}...`,
      `> ${step.command}`,
    ]);

    setTimeout(() => {
      setConsoleLog(prev => [...prev,
        `[DRY-RUN] Step ${step.id} simulated at ${ts}. Nothing was run on any host.`,
      ]);
      setSteps(prev => prev.map((s, idx) => {
        const stepIdx = prev.findIndex(x => x.id === step.id);
        if (s.id === step.id) return { ...s, status: 'done', time: ts };
        if (idx === stepIdx + 1) return { ...s, status: 'active' };
        return s;
      }));
      setIsExecuting(false);
    }, 1500);
  };

  const executeAll = () => {
    setIsExecuting(true);
    const pendingSteps = steps.filter(s => s.status !== 'done');
    let delay = 0;
    pendingSteps.forEach((step, idx) => {
      delay += 1500;
      setTimeout(() => {
        const ts = new Date().toLocaleTimeString();
        setConsoleLog(prev => [...prev, `[DRY-RUN] Step ${step.id} simulated @ ${ts} (not executed)`]);
        setSteps(prev => prev.map(s => s.id === step.id ? { ...s, status: 'done', time: ts } : s));
        
        if (idx === pendingSteps.length - 1) {
          setIsExecuting(false);
          // Playbooks are a simulation: no step runs on a host, so the
          // incident is never resolved from here. The analyst carries out the
          // steps and resolves the incident once they have confirmed it.
          setConsoleLog(prev => [...prev, ``,
            `[DRY-RUN] Simulation finished. No action was taken on any host.`,
            ...(incidentId ? [`[SYSTEM] Incident ${incidentId} is unchanged. Resolve it once you have carried out and confirmed these steps.`] : []),
          ]);
        }
      }, delay);
    });
  };

  const progress = Math.round((steps.filter(s => s.status === 'done').length / Math.max(steps.length, 1)) * 100);
  const sevColor = SEVERITY_COLOR[playbook?.severity] || '#FFD700';

  return (
    <div className="flex flex-col h-full overflow-y-auto pb-10 pr-2 custom-scrollbar space-y-6">
      {/* Header */}
      <header className="flex justify-between items-start border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="text-xs font-mono text-[var(--color-muted)] uppercase">Entity: {entityName}</span>
            <div className="h-px w-8 bg-[rgba(255,255,255,0.1)]"/>
            <span className="text-[10px] font-bold px-2 py-0.5 font-mono" style={{ backgroundColor: `${sevColor}20`, color: sevColor, border: `1px solid ${sevColor}50` }}>
              {playbook?.severity}
            </span>
          </div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase flex items-center">
            <BookOpen className="text-[var(--color-primary)] mr-3" size={28}/>
            PLAYBOOK: {playbook?.name}
          </h2>
          <p className="text-[var(--color-muted)] font-mono text-xs mt-1 max-w-2xl">{playbook?.description}</p>
        </div>
        <div className="flex items-center gap-4 bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.2)] p-4">
          <div className="text-right pr-4 border-r border-[rgba(255,255,255,0.1)]">
            <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase">Progress</div>
            <div className="text-2xl font-bold font-display text-[var(--color-primary)]">{progress}%</div>
          </div>
          {!incidentId ? (
            <div className="text-[10px] font-mono text-[#FF4444] uppercase max-w-[120px] leading-tight">
              Select an incident to enable execution
            </div>
          ) : (
            <button
              onClick={executeAll}
              disabled={isExecuting || progress === 100}
              className="flex items-center hud-button bg-[var(--color-primary)] text-black font-bold disabled:opacity-50"
            >
              <Play size={16} className="mr-2"/> SIMULATE ALL (DRY-RUN)
            </button>
          )}
        </div>
      </header>

      {/* Playbook Selector */}
      <div className="flex gap-3 flex-wrap items-center relative">
        {Object.keys(allPlaybooks).map(key => (
          <button
            key={key}
            onClick={() => setSelectedPlaybook(key)}
            className={`text-xs font-mono px-4 py-2 border transition-colors ${selectedPlaybook === key ? 'border-[var(--color-primary)] text-[var(--color-primary)] bg-[rgba(0,240,255,0.05)]' : 'border-[rgba(255,255,255,0.1)] text-[var(--color-muted)] hover:border-[rgba(0,240,255,0.3)]'}`}
          >
            {key}
          </button>
        ))}
        {(localStorage.getItem('sentinel_role') === 'ADMIN' || incidentId) && (
          <button onClick={() => setIsCreating(true)} className="text-xs font-mono px-4 py-2 border border-dashed border-[var(--color-muted)] text-[var(--color-primary)] hover:border-[var(--color-primary)] transition-colors">
            + {incidentId ? 'Create Manual Playbook' : 'New Playbook'}
          </button>
        )}

        {isCreating && (
          <div className="hud-panel p-5 bg-[rgba(10,15,25,0.98)] shadow-2xl border border-[var(--color-primary)] absolute top-12 left-0 z-50 w-[600px] max-h-[80vh] overflow-y-auto custom-scrollbar">
            <h3 className="text-[var(--color-primary)] font-display uppercase tracking-widest font-bold mb-4">Create Custom Playbook</h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-2">
                <input placeholder="Playbook Name" value={newPb.name} onChange={e=>setNewPb({...newPb, name: e.target.value})} className="bg-black border border-[rgba(0,240,255,0.3)] text-white px-3 py-2 outline-none focus:border-[var(--color-primary)]" />
                <input placeholder="Incident Type" value={newPb.type} onChange={e=>setNewPb({...newPb, type: e.target.value})} className="bg-black border border-[rgba(0,240,255,0.3)] text-white px-3 py-2 outline-none focus:border-[var(--color-primary)]" />
              </div>
              <textarea placeholder="Description" value={newPb.desc} onChange={e=>setNewPb({...newPb, desc: e.target.value})} className="w-full bg-black border border-[rgba(0,240,255,0.3)] text-white px-3 py-2 h-14 outline-none focus:border-[var(--color-primary)]" />
              
              <div className="border-t border-[rgba(255,255,255,0.1)] pt-3">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-[var(--color-primary)] uppercase font-bold text-[10px]">Remediation Steps</span>
                  <button onClick={() => setNewPb({...newPb, steps: [...newPb.steps, { id: newPb.steps.length+1, label: 'ACTION', description: '', command: '' }]})} className="text-[10px] text-white border border-white px-2 py-0.5 hover:bg-white hover:text-black transition-colors">+ Add Step</button>
                </div>
                {newPb.steps.map((s, i) => (
                  <div key={i} className="bg-[rgba(255,255,255,0.03)] p-3 border border-[rgba(255,255,255,0.05)] mb-2 space-y-2">
                    <div className="flex gap-2">
                      <input placeholder="Step Label (e.g. BLOCK_IP)" value={s.label} onChange={e => {
                        const ns = [...newPb.steps]; ns[i].label = e.target.value.toUpperCase(); setNewPb({...newPb, steps: ns});
                      }} className="flex-1 bg-black border border-[rgba(255,255,255,0.1)] text-white px-2 py-1 outline-none" />
                      <button onClick={() => {
                        const ns = newPb.steps.filter((_, idx) => idx !== i); setNewPb({...newPb, steps: ns});
                      }} className="text-red-400 hover:text-red-300">×</button>
                    </div>
                    <input placeholder="Brief Description" value={s.description} onChange={e => {
                      const ns = [...newPb.steps]; ns[i].description = e.target.value; setNewPb({...newPb, steps: ns});
                    }} className="w-full bg-black border border-[rgba(255,255,255,0.1)] text-white px-2 py-1 outline-none" />
                    <textarea placeholder="Remediation Command" value={s.command} onChange={e => {
                      const ns = [...newPb.steps]; ns[i].command = e.target.value; setNewPb({...newPb, steps: ns});
                    }} className="w-full bg-black border border-[rgba(255,255,255,0.1)] text-[var(--color-primary)] px-2 py-1 h-12 outline-none font-mono text-[10px]" />
                  </div>
                ))}
              </div>

              <div className="flex gap-2 justify-end pt-2 border-t border-[rgba(255,255,255,0.1)]">
                <button onClick={() => setIsCreating(false)} className="px-4 py-2 border border-[rgba(255,255,255,0.2)] text-[var(--color-muted)] hover:text-white transition-colors">Cancel</button>
                <button onClick={savePlaybook} className="px-4 py-2 bg-[var(--color-primary)] text-black font-bold shadow-[0_0_10px_var(--color-primary)]">Finalize & Save</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      <div className="h-1 w-full bg-[rgba(255,255,255,0.05)]">
        <div
          className="h-full transition-all duration-700"
          style={{ width: `${progress}%`, backgroundColor: sevColor, boxShadow: `0 0 8px ${sevColor}` }}
        />
      </div>

      <div className="grid grid-cols-12 gap-6 flex-1">
        {/* Left: Step Checklist */}
        <div className="col-span-5 flex flex-col gap-4">
          <div className="hud-panel p-5">
            <h3 className="text-sm font-display text-[var(--color-primary)] uppercase font-bold mb-4 flex items-center">
              <Zap size={16} className="mr-2"/> Phased Remediation Log
            </h3>
            <div className="space-y-2">
              {steps.map((step) => (
                <div
                  key={step.id}
                  className={`flex items-center justify-between p-4 border-l-4 transition-colors ${
                    step.status === 'done' ? 'border-[#05FFA1] bg-[rgba(5,255,161,0.04)]' :
                    step.status === 'active' ? 'border-[var(--color-primary)] bg-[rgba(0,240,255,0.07)] shadow-[0_0_15px_rgba(0,240,255,0.05)]' :
                    'border-[rgba(255,255,255,0.1)] opacity-50'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-7 h-7 flex items-center justify-center flex-shrink-0 ${
                      step.status === 'done' ? 'bg-[rgba(5,255,161,0.15)] text-[#05FFA1]' :
                      step.status === 'active' ? 'bg-[var(--color-primary)] text-black' :
                      'text-[var(--color-muted)]'
                    }`}>
                      {step.status === 'done' ? <CheckCircle2 size={14}/> :
                       step.status === 'active' ? <Zap size={14}/> :
                       <Clock size={14}/>}
                    </div>
                    <div>
                      <div className={`text-xs font-bold font-mono uppercase ${step.status === 'done' ? 'text-gray-400' : step.status === 'active' ? 'text-white' : 'text-[var(--color-muted)]'}`}>
                        {step.label}
                      </div>
                      {step.status === 'done' && (
                        <div className="text-[10px] font-mono text-[var(--color-muted)]">{step.time}</div>
                      )}
                    </div>
                  </div>
                  {step.status === 'active' && (
                    <button
                      onClick={() => executeStep(step)}
                      disabled={isExecuting}
                      className="text-[10px] font-bold font-mono px-3 py-1 border border-[var(--color-primary)] text-[var(--color-primary)] hover:bg-[var(--color-primary)] hover:text-black transition-colors uppercase disabled:opacity-50"
                    >
                      Simulate
                    </button>
                  )}
                  {step.status === 'pending' && (
                    <span className="text-[10px] font-mono text-[rgba(255,255,255,0.2)] uppercase">Waiting</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Telemetry Sparklines */}
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(playbook?.telemetry || {}).map(([key, val]) => (
              <div key={key} className="hud-panel p-3 border-l-2 border-[var(--color-primary)]">
                <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-1">{key.replace('_', ' ')}</div>
                <div className="text-lg font-bold text-[var(--color-primary)] font-mono">{val as string}</div>
                <div className="h-4 flex items-end gap-[2px] mt-2">
                  {Array.from({length: 9}).map((_, i) => (
                    <div key={i} className="flex-1 bg-[var(--color-primary)] opacity-20 rounded-sm" style={{height: `${Math.random()*100}%`}}/>
                  ))}
                  <div className="flex-1 bg-[var(--color-primary)] opacity-100 rounded-sm h-full shadow-[0_0_4px_var(--color-primary)]"/>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Automation Console */}
        <div className="col-span-7">
          <div className="hud-panel flex flex-col h-full min-h-[500px]">
            <div className="flex items-center justify-between px-4 py-2 border-b border-[rgba(0,240,255,0.1)] bg-[rgba(0,0,0,0.3)]">
              <div className="flex items-center gap-4">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 bg-[#FF4444]"/>
                  <div className="w-3 h-3 bg-[#FFD700]"/>
                  <div className="w-3 h-3 bg-[#05FFA1]"/>
                </div>
                <span className="text-[11px] font-mono text-[var(--color-muted)] uppercase tracking-widest font-bold">AUTOMATION_CONSOLE_v4.2</span>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-mono text-[var(--color-muted)]">
                <span className="w-2 h-2 rounded-full bg-[var(--color-primary)] animate-pulse"/>
                <span>STREAMING</span>
              </div>
            </div>

            <div ref={consoleRef} className="flex-1 p-5 overflow-y-auto font-mono text-xs leading-relaxed bg-[rgba(0,0,0,0.5)]">
              {consoleLog.map((line, i) => (
                <div key={i} className={`mb-0.5 ${
                  line.startsWith('[EXECUTING]') || line.startsWith('[AUTO]') ? 'text-[var(--color-primary)] font-bold' :
                  line.startsWith('[OK]') || line.startsWith('[COMPLETED]') ? 'text-[#05FFA1]' :
                  line.startsWith('[SYSTEM]') ? 'text-[var(--color-muted)]' :
                  line.startsWith('[PENDING]') ? 'text-[var(--color-warning)] animate-pulse' :
                  line.startsWith('>') ? 'text-white' :
                  'text-gray-500'
                }`}>
                  {line || '\u00A0'}
                </div>
              ))}
              {isExecuting && (
                <div className="text-[var(--color-primary)] animate-pulse flex items-center">
                  <span className="mr-2">_</span> Executing...
                </div>
              )}
              {!isExecuting && (
                <div className="mt-4 border-t border-[rgba(255,255,255,0.05)] pt-3 flex items-center">
                  <span className="text-[var(--color-primary)] mr-2">LSADRA_CMD &gt;</span>
                  <span className="w-2 h-4 bg-[var(--color-primary)] inline-block"/>
                </div>
              )}
            </div>

            {/* Active Step Command Preview */}
            {steps.find(s => s.status === 'active') && (
              <div className="border-t border-[rgba(0,240,255,0.1)] p-4 bg-[rgba(0,0,0,0.3)]">
                <div className="text-[10px] font-mono text-[var(--color-muted)] uppercase mb-2">Next Command Preview</div>
                <div className="text-xs font-mono text-white bg-[rgba(255,255,255,0.03)] rounded p-3 border border-[rgba(255,255,255,0.05)] break-all">
                  {steps.find(s => s.status === 'active')?.command}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Response;
