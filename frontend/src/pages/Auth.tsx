import React, { useState } from 'react';
import { Lock, Mail, UserPlus, ArrowRight, AlertCircle } from 'lucide-react';
import { apiFetch, setToken } from '../api';

interface AuthProps {
  onLoginSuccess: () => void;
}

export const Auth: React.FC<AuthProps> = ({ onLoginSuccess }) => {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;

    setLoading(true);
    setError('');

    const path = isSignUp ? '/auth/register' : '/auth/login';
    const options = {
      method: 'POST',
      body: JSON.stringify({ email: email.trim(), password }),
    };

    try {
      const res = await apiFetch(path, options);

      if (res.status === 401 || res.status === 403 || res.status === 409) {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Authentication failed. Check your credentials.');
        setLoading(false);
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Request failed. Ensure the backend server is running.');
        setLoading(false);
        return;
      }

      const data = await res.json();
      if (!data.token) {
        setError('The server did not return a session token.');
        setLoading(false);
        return;
      }

      setToken(data.token);
      onLoginSuccess();
    } catch (err) {
      setError('Cannot reach the backend server. Is uvicorn running on 127.0.0.1:8001?');
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-background text-slate-100 font-sans relative px-4">
      {/* Decorative grid bg */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-30 pointer-events-none" />

      <div className="w-full max-w-md glass-card p-8 space-y-6 relative z-10">
        {/* Brand */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="w-16 h-16 rounded-2xl overflow-hidden flex items-center justify-center shadow-xl shadow-slate-900/50 border border-slate-800/80 mb-2">
            <img src="/logo.png" alt="CyberAgent Logo" className="w-full h-full object-cover" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">Welcome to CyberAgent</h1>
            <p className="text-slate-400 text-xs mt-1">Scope-gated, evidence-backed scan platform</p>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs text-slate-400 font-medium">Work Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 w-4 h-4 text-slate-600" />
              <input
                type="email"
                required
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-900 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-emerald-500/80 transition-colors"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs text-slate-400 font-medium">Security Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-600" />
              <input
                type="password"
                required
                minLength={8}
                placeholder={isSignUp ? 'At least 8 characters' : '••••••••••••'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-900 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-emerald-500/80 transition-colors"
              />
            </div>
          </div>

          {error && (
            <div className="flex gap-2 bg-red-950/20 border border-red-800/20 p-3 rounded-lg text-[10px] text-red-400">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-slate-955 font-bold text-xs px-4 py-2.5 rounded-lg flex items-center justify-center gap-1.5 cursor-pointer transition-colors shadow-lg shadow-emerald-500/10"
          >
            <span>{loading ? 'Authenticating...' : isSignUp ? 'Create Corporate Account' : 'Authenticate Session'}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </form>

        {/* Foot switch link */}
        <div className="text-center pt-2">
          <button
            onClick={() => setIsSignUp(!isSignUp)}
            className="text-[10px] text-slate-500 hover:text-slate-300 font-medium transition-colors cursor-pointer"
          >
            {isSignUp ? 'Already registered? Log in here' : 'Need corporate access? Sign up here'}
          </button>
        </div>
      </div>
    </div>
  );
};