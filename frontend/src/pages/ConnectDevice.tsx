import React, { useEffect, useState } from 'react';
import { Terminal, Key, Copy, CheckCircle2, Shield, Settings } from 'lucide-react';
import { generateToken, getServerIdentity } from '../services/api';

const ConnectDevice = () => {
  const [token, setToken] = useState<string | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  useEffect(() => { getServerIdentity().then((id) => setFingerprint(id.cert_sha256)); }, []);
  const [hashes, setHashes] = useState<{ installer: string; agent: string; extra: Record<string, string> } | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const hostIP = window.location.hostname;
  // Same scheme as this page: an HTTPS dashboard yields an HTTPS install command.
  const scheme = window.location.protocol === 'https:' ? 'https' : 'http';
  const serverAddress = `${scheme}://${hostIP}:8000`;
  const insecure = scheme === 'http';

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const res = await generateToken();
      setToken(res.data.token);
      setHashes(res.data.installer_sha256 && res.data.agent_sha256
        ? { installer: res.data.installer_sha256, agent: res.data.agent_sha256, extra: res.data.extra_files || {} }
        : null);
      setCopied(false);
    } catch (err) {
      console.error("Failed to generate token", err);
      alert("Failed to generate token");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Mirrors lsadra/onboarding/agent_files.py: the installer is saved to a file and
  // its SHA-256 checked before sudo runs it; the installer then checks the agent.
  const linuxCommand = token && hashes
    ? `curl -fsSLo lsadra-install.sh ${serverAddress}/static/installer_linux.sh` +
      ` && echo '${hashes.installer}  lsadra-install.sh' | sha256sum -c -` +
      ` && sudo bash lsadra-install.sh --token ${token} --server ${serverAddress}` +
      ` --agent-sha256 ${hashes.agent}` +
      Object.keys(hashes.extra).sort().map(name => ` --file ${name}=${hashes.extra[name]}`).join('') +
      (insecure ? ' --allow-insecure-http' : '')
    : 'Generate a token above to get the install command.';
  const windowsCommand = `python windows_agent_simulator.py`;

  return (
    <div className="flex flex-col h-full space-y-8 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <Terminal className="text-[var(--color-primary)] mr-3" size={32} />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Connect Device</h2>
        </div>
      </header>

      <section className="bg-[rgba(255,255,255,0.02)] border border-[rgba(0,240,255,0.15)] rounded p-6">
        <div className="flex items-start">
          <Shield className="text-[var(--color-primary)] mr-4 mt-1" size={24} />
          <div>
            <h3 className="text-xl font-display text-white mb-2">Secure Registration</h3>
            <p className="text-[var(--color-muted)] font-mono text-sm mb-6 max-w-3xl">
              Add a new device to your LSADRA workspace. Generate a one-time registration token below, then run the installer on your target machine. The agent registers with this server and begins streaming logs to the ingestion pipeline.
            </p>
            
            <button 
              onClick={handleGenerate}
              disabled={loading}
              className="hud-button flex items-center bg-[var(--color-primary)] text-black font-bold mb-6"
            >
              <Key size={18} className="mr-2" />
              {loading ? 'Generating...' : 'Generate New Token'}
            </button>

            {token && (
              <div className="bg-[rgba(10,15,25,0.8)] border border-[#05FFA1] rounded p-4 mb-8 flex justify-between items-center">
                <div>
                  <div className="text-xs text-[#05FFA1] font-mono mb-1 uppercase tracking-widest">Active Token (Valid for 15 mins)</div>
                  <div className="text-2xl font-mono text-white tracking-wider">{token}</div>
                </div>
                <button 
                  onClick={() => copyToClipboard(token)}
                  className="p-2 hover:bg-[rgba(255,255,255,0.1)] rounded transition-colors"
                >
                  {copied ? <CheckCircle2 className="text-[#05FFA1]" /> : <Copy className="text-[var(--color-muted)]" />}
                </button>
              </div>
            )}

            {token && (
              <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.3)] rounded p-4 mb-8">
                <div className="text-xs text-[var(--color-primary)] font-mono mb-1 uppercase tracking-widest">Server certificate fingerprint (SHA-256)</div>
                {fingerprint ? (
                  <>
                    <div className="text-sm font-mono text-white break-all">{fingerprint}</div>
                    <p className="text-xs text-[var(--color-muted)] font-mono mt-2">
                      Set this as <code>server_cert_sha256</code> in the agent config (or LSADRA_SERVER_CERT_SHA256 for the Windows agent). The agent then refuses any server that presents a different certificate.
                    </p>
                  </>
                ) : (
                  <p className="text-xs text-[var(--color-muted)] font-mono">
                    This server is not serving TLS itself (loopback, or TLS ends at a proxy), so there is no certificate to pin here.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-8">
        <section>
          <h3 className="text-xl font-display text-white flex items-center mb-4">
            <Settings size={20} className="mr-2 text-[var(--color-primary)]"/> Linux Installation
          </h3>
          <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 relative group">
            <button 
              onClick={() => copyToClipboard(linuxCommand)}
              className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity p-2 hover:bg-[rgba(255,255,255,0.1)] rounded"
            >
              <Copy size={16} className="text-[var(--color-muted)]" />
            </button>
            <pre className="font-mono text-sm text-[var(--color-primary)] whitespace-pre-wrap break-all">
              {linuxCommand}
            </pre>
          </div>
          <p className="text-xs text-[var(--color-muted)] mt-2 font-mono">Run this command as root or with sudo privileges. It checks the installer's SHA-256 before running it, and the installer checks the agent's.</p>
          {insecure && (
            <p className="text-xs text-[#FF4444] mt-2 font-mono">This dashboard is served over plain HTTP, so the device key travels unencrypted. Use it only on a trusted local network; serve LSADRA over HTTPS otherwise.</p>
          )}
        </section>

        <section>
          <h3 className="text-xl font-display text-white flex items-center mb-4">
            <Settings size={20} className="mr-2 text-[var(--color-primary)]"/> Windows Installation
          </h3>
          <div className="bg-[rgba(10,15,25,0.8)] border border-[rgba(0,240,255,0.15)] rounded p-4 relative group">
            <button 
              onClick={() => copyToClipboard(windowsCommand)}
              className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity p-2 hover:bg-[rgba(255,255,255,0.1)] rounded"
            >
              <Copy size={16} className="text-[var(--color-muted)]" />
            </button>
            <pre className="font-mono text-sm text-[var(--color-primary)] whitespace-pre-wrap break-all">
              {windowsCommand}
            </pre>
          </div>
          <p className="text-xs text-[var(--color-muted)] mt-2 font-mono">Run this script in PowerShell to simulate Windows Event Log ingestion.</p>
        </section>
      </div>

    </div>
  );
};

export default ConnectDevice;
