import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { login, register, LoginError } from '../services/api';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await login({ username, password, ...(needTotp ? { totp_code: totpCode } : {}) });
      const { access_token, role } = response.data;
      localStorage.setItem('sentinel_token', access_token);
      localStorage.setItem('sentinel_role',  role);
      navigate('/app/dashboard');
    } catch (err: any) {
      if (err instanceof LoginError && err.code === 'totp_required') {
        setNeedTotp(true);  // password accepted; ask for the authenticator code
        return;
      }
      setTotpCode('');
      const msg = err?.message || err?.response?.data?.detail || 'Invalid credentials';
      alert(`Login failed: ${msg}`);
    }
  };


  const handleRegister = async () => {
    if (!username || !password) {
      alert("Please enter a username and password to register.");
      return;
    }
    try {
      await register({ username, password });
      alert("Registration successful! You can now initialize (login).");
    } catch (err: any) {
      console.error('Registration failed', err);
      alert(err.response?.data?.detail || "Registration failed. Username may be taken.");
    }
  };

  return (
    <div className="flex h-screen w-full items-center justify-center bg-[var(--color-background)]">
      {/* Background Grid */}
      <div className="absolute inset-0 pointer-events-none" 
           style={{
             backgroundImage: 'linear-gradient(rgba(0, 240, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 240, 255, 0.03) 1px, transparent 1px)',
             backgroundSize: '40px 40px'
           }}>
      </div>
      
      <div className="hud-panel p-10 w-full max-w-md relative z-10 shadow-[0_0_30px_rgba(0,240,255,0.1)]">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-full border-2 border-[var(--color-primary)] flex items-center justify-center mb-4 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Shield size={32} className="text-[var(--color-primary)]" />
          </div>
          <h1 className="text-3xl font-bold tracking-widest text-white font-display uppercase">
            Glass Sentinel
          </h1>
          <p className="text-[var(--color-primary)] font-mono text-xs tracking-widest mt-1 uppercase">Authentication Required</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-6">
          <div>
            <label className="block text-[var(--color-muted)] text-xs font-display uppercase tracking-widest mb-1">Operator ID</label>
            <input 
              type="text" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[var(--color-surface-lowest)] border-b-2 border-[var(--color-outline-variant)] focus:border-[var(--color-primary)] outline-none text-white font-mono px-4 py-2 transition-colors"
              placeholder="Enter Username"
              required
            />
          </div>
          <div>
            <label className="block text-[var(--color-muted)] text-xs font-display uppercase tracking-widest mb-1">Passphrase</label>
            <input 
              type="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[var(--color-surface-lowest)] border-b-2 border-[var(--color-outline-variant)] focus:border-[var(--color-primary)] outline-none text-white font-mono px-4 py-2 transition-colors"
              placeholder="••••••••"
              required
            />
          </div>
          {needTotp && (
            <div>
              <label className="block text-[var(--color-muted)] text-xs font-display uppercase tracking-widest mb-1">Authenticator Code</label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, ''))}
                className="w-full bg-[var(--color-surface-lowest)] border-b-2 border-[var(--color-outline-variant)] focus:border-[var(--color-primary)] outline-none text-white font-mono px-4 py-2 transition-colors"
                placeholder="123456"
                autoFocus
                required
              />
            </div>
          )}

          <div className="flex space-x-4 pt-4">
            <button 
              type="submit" 
              className="hud-button flex-1 text-black bg-[var(--color-primary)] hover:bg-white transition-colors"
            >
              Initialize
            </button>
            <button 
              type="button" 
              onClick={handleRegister}
              className="hud-button flex-1 bg-transparent border border-[var(--color-primary)] text-[var(--color-primary)]"
            >
              Register
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;
