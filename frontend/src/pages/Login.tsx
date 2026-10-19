import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { login, register } from '../services/api';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await login({ username, password });
      const { access_token, role } = response.data;
      localStorage.setItem('sentinel_token', access_token);
      localStorage.setItem('sentinel_role',  role);
      navigate('/app/dashboard');
    } catch (err: any) {
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
