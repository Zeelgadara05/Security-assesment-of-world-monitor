import React, { useState } from 'react';
import { Lock, Mail, ArrowRight, ShieldCheck, ScanSearch, AlertCircle } from 'lucide-react';
import { apiFetch, setToken } from '../api';
import { Input } from '../components/Field';
import { Button } from '../components/Button';

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

    try {
      const res = await apiFetch(path, {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), password }),
      });

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
    } catch {
      setError('Cannot reach the backend server. Ensure it is running and reachable.');
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-bg px-4 py-10 font-sans text-text">
      <div className="grid w-full max-w-[880px] grid-cols-1 md:grid-cols-2 border border-line rounded-lg overflow-hidden bg-surface">
        {/* Intro / brand side */}
        <div className="hidden md:flex flex-col justify-between p-8 bg-surface-2 border-r border-line">
          <div>
            <div className="flex items-center gap-2.5 mb-8">
              <span className="w-8 h-8 rounded overflow-hidden border border-line flex items-center justify-center">
                <img src="/logo.png" alt="" className="w-full h-full object-cover" />
              </span>
              <div className="leading-none">
                <span className="text-sm font-semibold tracking-tight">CyberAgent</span>
                <span className="block text-[9px] text-faint font-mono uppercase tracking-[0.18em] mt-1">
                  Scan Platform
                </span>
              </div>
            </div>

            <span className="eyebrow mb-3 block">Scope-gated Assessment</span>
            <h2 className="text-xl font-semibold leading-snug text-text">
              Automated security assessments, backed by evidence.
            </h2>
            <p className="text-[12.5px] text-muted leading-relaxed mt-3">
              Orchestrate your declared scanning tooling against authorized targets only. Every finding is created from
              real tool observations — never invented.
            </p>
          </div>

          <ul className="space-y-2.5">
            <li className="flex items-center gap-2.5 text-[12px] text-muted">
              <ScanSearch className="w-4 h-4 text-accent" strokeWidth={1.75} aria-hidden="true" />
              Stage-driven asynchronous scan pipeline
            </li>
            <li className="flex items-center gap-2.5 text-[12px] text-muted">
              <ShieldCheck className="w-4 h-4 text-accent" strokeWidth={1.75} aria-hidden="true" />
              Authorized-scope enforcement on every trigger
            </li>
          </ul>
        </div>

        {/* Form side */}
        <div className="p-8 sm:p-10">
          <span className="eyebrow mb-2 block">{isSignUp ? 'Registration' : 'Gate Access'}</span>
          <h1 className="text-lg font-semibold text-text">
            {isSignUp ? 'Create corporate account' : 'Sign in to your workspace'}
          </h1>
          <p className="text-[12px] text-muted mt-1 mb-6">
            {isSignUp ? 'Register with your work email to operate the scan platform.' : 'Authenticate to access assessment operations.'}
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              label="Work email"
              type="email"
              required
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <Input
              label="Password"
              type="password"
              required
              minLength={8}
              autoComplete={isSignUp ? 'new-password' : 'current-password'}
              placeholder={isSignUp ? 'At least 8 characters' : '••••••••••••'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            {error && (
              <div className="flex gap-2 border border-critical/40 bg-critical/10 rounded px-3 py-2.5 text-[11px] text-critical">
                <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <Button type="submit" variant="primary" disabled={loading} className="w-full">
              {loading ? 'Authenticating…' : isSignUp ? 'Create account' : 'Sign in'}
              {!loading && <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />}
            </Button>
          </form>

          <div className="mt-5 pt-4 border-t border-line flex items-center gap-1.5 text-[11px] text-faint">
            <Lock className="w-3 h-3 shrink-0" aria-hidden="true" />
            <span>
              {isSignUp ? 'Already registered? ' : 'Need access? '}
              <button
                type="button"
                onClick={() => {
                  setIsSignUp((v) => !v);
                  setError('');
                }}
                className="text-muted hover:text-text underline underline-offset-2 cursor-pointer transition-colors"
              >
                {isSignUp ? 'Sign in here' : 'Sign up here'}
              </button>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};