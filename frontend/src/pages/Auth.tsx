import React, { useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, ShieldCheck, ScanSearch, AlertCircle, Fingerprint, Activity } from 'lucide-react';
import { apiFetch, setToken } from '../api';
import { Input } from '../components/Field';
import { Button } from '../components/Button';

interface AuthProps {
  onLoginSuccess: () => void;
}

const PILLARS = [
  { icon: ScanSearch, title: 'Stage-driven pipeline', copy: 'Asynchronous scanning from recon to reporting, every stage recorded.' },
  { icon: ShieldCheck, title: 'Authorized scope only', copy: 'Every trigger is scope-gated and rejected with 403 when out of bounds.' },
  { icon: Activity, title: 'Evidence-backed findings', copy: 'Findings are derived from real observations — never invented.' },
];

export const Auth: React.FC<AuthProps> = ({ onLoginSuccess }) => {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const reduceMotion = useReducedMotion();

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

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const rawDetail = errData?.detail;
        const detail =
          typeof rawDetail === 'string'
            ? rawDetail
            : Array.isArray(rawDetail) && typeof rawDetail[0]?.msg === 'string'
              ? rawDetail[0].msg.replace(/^Value error,\s*/, '')
              : null;
        if (res.status === 409 && isSignUp) {
          setError(detail || 'An account with this email already exists. Please sign in instead.');
          setIsSignUp(false);
        } else if (res.status === 401) {
          setError(detail || 'Invalid email or password.');
        } else if (res.status === 403) {
          setError(detail || 'You do not have permission to do that.');
        } else if (res.status === 422) {
          setError(detail || 'Please check the email and password you entered.');
        } else {
          setError(detail || 'Request failed. Ensure the backend server is running.');
        }
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
    <div className="relative flex min-h-[100dvh] items-center justify-center px-4 py-12 sm:px-6">
      <motion.div
        className="grid w-full max-w-[1000px] grid-cols-1 gap-4 lg:grid-cols-[1.05fr_0.95fr]"
        initial={reduceMotion ? false : { opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
      >
        {/* Brand / narrative */}
        <div className="panel hidden flex-col justify-between p-9 lg:flex">
          <div>
            <div className="mb-10 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center overflow-hidden rounded-2xl border border-line bg-surface-2">
                <img src="/logo.png" alt="" className="h-full w-full object-cover" />
              </span>
              <span className="flex flex-col leading-none">
                <span className="text-[16px] font-semibold tracking-tight">CyberAgent</span>
                <span className="mt-1 font-mono text-[9px] uppercase tracking-[0.22em] text-faint">Assessment Platform</span>
              </span>
            </div>

            <span className="chip mb-5">Scope-gated assessment</span>
            <h2 className="display max-w-[14ch] text-[34px] font-semibold text-text">
              Security assessments, backed by evidence.
            </h2>
            <p className="mt-4 max-w-[48ch] text-[13px] leading-relaxed text-muted">
              Orchestrate your declared scanning tooling against authorized targets only. Every finding is created from
              real tool observations — never invented.
            </p>
          </div>

          <ul className="mt-10 space-y-3.5">
            {PILLARS.map((p) => {
              const Icon = p.icon;
              return (
                <li key={p.title} className="flex items-start gap-3">
                  <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-line bg-surface-2 text-accent">
                    <Icon className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
                  </span>
                  <span>
                    <span className="block text-[12.5px] font-medium text-text">{p.title}</span>
                    <span className="mt-0.5 block text-[11.5px] leading-relaxed text-faint">{p.copy}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Form — double-bezel */}
        <div className="rounded-[2rem] border border-line bg-white/[0.02] p-1.5 shadow-[0_40px_80px_-48px_rgba(0,0,0,0.95)]">
          <div className="panel h-full rounded-[calc(2rem-0.375rem)] p-8 sm:p-10">
            <div className="mb-8 flex items-center gap-2.5 lg:hidden">
              <span className="flex h-9 w-9 items-center justify-center overflow-hidden rounded-xl border border-line bg-surface-2">
                <img src="/logo.png" alt="" className="h-full w-full object-cover" />
              </span>
              <span className="text-[15px] font-semibold tracking-tight">CyberAgent</span>
            </div>

            <span className="eyebrow mb-3 block">{isSignUp ? 'Registration' : 'Gate access'}</span>
            <h1 className="display text-[24px] font-semibold text-text">
              {isSignUp ? 'Create your account' : 'Sign in to your workspace'}
            </h1>
            <p className="mt-2 mb-8 text-[12.5px] leading-relaxed text-muted">
              {isSignUp
                ? 'Register with your work email to operate the scan platform.'
                : 'Authenticate to access assessment operations.'}
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              <Input
                label="Work email"
                type="email"
                required
                autoComplete="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
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
                disabled={loading}
              />

              {error && (
                <div className="flex gap-2.5 rounded-xl border border-critical/35 bg-critical/[0.07] px-3.5 py-3 text-[11.5px] leading-relaxed text-critical">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.5} aria-hidden="true" />
                  <span>{error}</span>
                </div>
              )}

              <Button
                type="submit"
                variant="primary"
                disabled={loading}
                className="w-full"
                trailing={!loading ? <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.75} /> : undefined}
              >
                {loading ? 'Authenticating…' : isSignUp ? 'Create account' : 'Sign in'}
              </Button>
            </form>

            <div className="mt-7 flex items-center gap-2 border-t border-line pt-5 text-[11.5px] text-faint">
              <Fingerprint className="h-3.5 w-3.5 shrink-0" strokeWidth={1.5} aria-hidden="true" />
              <span>
                {isSignUp ? 'Already registered? ' : 'Need access? '}
                <button
                  type="button"
                  onClick={() => {
                    setIsSignUp((v) => !v);
                    setError('');
                  }}
                  className="text-muted underline underline-offset-4 transition-colors duration-500 ease-spring hover:text-text"
                >
                  {isSignUp ? 'Sign in here' : 'Sign up here'}
                </button>
              </span>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
