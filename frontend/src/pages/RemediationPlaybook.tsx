import React from 'react';
import { useParams } from 'react-router-dom';
import { Terminal, Shield, CheckCircle, Circle, PlayCircle, Zap } from 'lucide-react';

const RemediationPlaybook = () => {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="flex flex-col h-full space-y-6">
      <header className="flex justify-between items-start border-b border-[rgba(0,240,255,0.3)] pb-4">
        <div>
          <p className="text-[var(--color-primary)] font-mono text-sm mb-1 uppercase tracking-widest">Remediation Playbook</p>
          <div className="flex items-center space-x-3 mb-2">
            <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">AD_ELEVATION_RESPONSE</h2>
            <span className="border border-[var(--color-warning)] text-[var(--color-warning)] font-display font-bold uppercase px-3 py-1 bg-[rgba(255,214,0,0.1)] shadow-[0_0_8px_rgba(255,214,0,0.3)]">ACTIVE</span>
          </div>
          <p className="text-[var(--color-muted)] font-mono text-sm">Target Incident: {id || 'INC-4092'}</p>
        </div>
        <div className="flex space-x-3">
          <button className="font-display font-bold uppercase tracking-widest bg-[var(--color-critical)] text-black px-6 py-3 hover:bg-white transition-colors flex items-center shadow-[0_0_15px_rgba(255,42,109,0.5)]">
            <Zap size={18} className="mr-2" /> Execute All Automations
          </button>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-6 flex-1 min-h-0">
        {/* Left Col: Checklist */}
        <div className="col-span-5 space-y-4 overflow-y-auto">
          <div className="flex justify-between items-center text-xs font-mono text-[var(--color-muted)] mb-2 px-2">
            <span>OPERATOR: T. Analyst</span>
            <span>ETA: 4m 12s</span>
          </div>
          
          <div className="space-y-3">
            {/* Completed */}
            <div className="hud-panel p-4 flex items-center justify-between border-l-4 border-l-[var(--color-safe)] opacity-70">
              <div className="flex items-center space-x-3">
                <CheckCircle className="text-[var(--color-safe)]" size={20} />
                <span className="font-display text-lg tracking-wider text-white line-through decoration-[var(--color-safe)]">Identify Source Endpoint</span>
              </div>
              <span className="font-mono text-xs text-[var(--color-safe)]">COMPLETED</span>
            </div>

            <div className="hud-panel p-4 flex items-center justify-between border-l-4 border-l-[var(--color-safe)] opacity-70">
              <div className="flex items-center space-x-3">
                <CheckCircle className="text-[var(--color-safe)]" size={20} />
                <span className="font-display text-lg tracking-wider text-white line-through decoration-[var(--color-safe)]">Isolate Compromised Endpoint</span>
              </div>
              <span className="font-mono text-xs text-[var(--color-safe)]">COMPLETED</span>
            </div>

            {/* Active */}
            <div className="hud-panel p-4 flex items-center justify-between border-l-4 border-l-[var(--color-warning)] shadow-[0_0_15px_rgba(255,214,0,0.1)] relative overflow-hidden">
               <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-r from-[rgba(255,214,0,0.1)] to-transparent pointer-events-none"></div>
              <div className="flex items-center space-x-3 relative z-10">
                <PlayCircle className="text-[var(--color-warning)] animate-pulse" size={20} />
                <span className="font-display text-lg tracking-wider text-white">Revoke Privileged Access</span>
              </div>
              <button className="relative z-10 border border-[var(--color-warning)] text-[var(--color-warning)] font-display text-sm uppercase px-4 py-1 hover:bg-[var(--color-warning)] hover:text-black transition-colors">
                Revoke Now
              </button>
            </div>

            {/* Pending */}
            <div className="hud-panel p-4 flex items-center justify-between border-l-4 border-l-[rgba(255,255,255,0.2)] opacity-50">
              <div className="flex items-center space-x-3">
                <Circle className="text-gray-500" size={20} />
                <span className="font-display text-lg tracking-wider text-gray-400">Reset User Password</span>
              </div>
              <span className="font-mono text-xs text-gray-500">PENDING</span>
            </div>

            <div className="hud-panel p-4 flex items-center justify-between border-l-4 border-l-[rgba(255,255,255,0.2)] opacity-50">
              <div className="flex items-center space-x-3">
                <Circle className="text-gray-500" size={20} />
                <span className="font-display text-lg tracking-wider text-gray-400">Broadcast Alert to Ops</span>
              </div>
              <span className="font-mono text-xs text-gray-500">PENDING</span>
            </div>
          </div>
        </div>

        {/* Right Col: Terminal Console */}
        <div className="col-span-7 hud-panel flex flex-col overflow-hidden">
          <div className="bg-[#0a0f18] px-4 py-2 border-b border-[rgba(0,240,255,0.15)] flex items-center justify-between">
            <span className="font-display text-sm text-[var(--color-primary)] tracking-widest flex items-center"><Terminal size={14} className="mr-2"/> AUTOMATION_CONSOLE · SIMULATION</span>
            <span className="w-2 h-2 rounded-full bg-[var(--color-safe)] shadow-[0_0_5px_var(--color-safe)] animate-pulse"></span>
          </div>
          <div className="p-4 font-mono text-xs text-gray-300 flex-1 overflow-y-auto bg-black">
            <div className="text-[var(--color-muted)] mb-4">Glass Sentinel Automation Runtime v4.2.0</div>
            <div className="mb-1 text-white">&gt; Executing step: Identify Source Endpoint</div>
            <div className="mb-1 text-[var(--color-primary)]">[INFO] Correlating events for INC-4092...</div>
            <div className="mb-1 text-[var(--color-primary)]">[INFO] Source IP identified: 192.168.1.105</div>
            <div className="mb-4 text-[var(--color-safe)]">[DRY-RUN] Step simulated, not executed.</div>
            
            <div className="mb-1 text-white">&gt; Executing step: Isolate Compromised Endpoint</div>
            <div className="mb-1 text-[var(--color-primary)]">[SIMULATED] Network containment via EDR API (not run)</div>
            <div className="mb-1 text-[var(--color-primary)]">[SIMULATED] Firewall group update (not run)</div>
            <div className="mb-4 text-[var(--color-safe)]">[DRY-RUN] Isolation simulated. No host was isolated.</div>

            <div className="mb-1 text-white">&gt; Waiting for manual trigger: Revoke Privileged Access</div>
            <div className="mb-1 text-[var(--color-warning)] blink">[WAITING] Action required by operator...</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RemediationPlaybook;
