import React, { useEffect, useState } from 'react';
import { Shield, Lock, ServerCog, UserRound } from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { Link } from 'react-router-dom';

export const Settings: React.FC = () => {
  const [overview, setOverview] = useState<{ email?: string; role?: string }>({});

  useEffect(() => {
    apiFetch('/auth/me')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setOverview(data))
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace / Settings"
        title="System settings"
        description="Configuration is driven by backend environment variables. No credentials are stored in this UI."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Credentials */}
        <div className="lg:col-span-2 space-y-4">
          <section className="panel rounded-md p-4">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5 mb-3">
              <ServerCog className="w-3.5 h-3.5" aria-hidden="true" />
              External API credentials
            </h2>
            <div className="border border-line rounded p-3 text-[11.5px] text-muted space-y-2 leading-relaxed bg-bg">
              <p>
                This build does not configure third-party AI or intelligence APIs. Provider keys
                (OpenAI/Groq/Shodan) are placeholders only and are never stored, sent, or transmitted by this UI.
              </p>
              <p>
                Scanning tool availability (subfinder, nmap, nuclei, …) and orchestration behavior are controlled
                by environment variables on the backend (<code className="font-mono">SIMULATION_MODE</code>,
                scanner binaries on the server PATH, <code className="font-mono">ADMIN_*</code> bootstrap config).
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
              {['OpenAI compatible API key', 'Groq API key'].map((label) => (
                <div key={label} className="space-y-1.5">
                  <label className="block text-[11.5px] font-medium text-muted">{label}</label>
                  <input
                    type="password"
                    readOnly
                    placeholder="•••••••••••••• (unused placeholder)"
                    className="w-full bg-bg border border-line rounded px-3 py-2 text-[12px] text-faint placeholder:text-faint/60 cursor-not-allowed"
                  />
                </div>
              ))}
              <div className="space-y-1.5 md:col-span-2">
                <label className="block text-[11.5px] font-medium text-muted">Shodan API key</label>
                <input
                  type="password"
                  readOnly
                  placeholder="sh-•••••••••••• (unused placeholder)"
                  className="w-full bg-bg border border-line rounded px-3 py-2 text-[12px] text-faint placeholder:text-faint/60 cursor-not-allowed"
                />
              </div>
            </div>
          </section>

          <section className="panel rounded-md p-4">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5 mb-3">
              <Lock className="w-3.5 h-3.5" aria-hidden="true" />
              Execution guardrails
            </h2>
            <div className="space-y-3">
              <p className="text-[11.5px] text-faint leading-relaxed">
                Orchestrator simulation mode: when enabled, scanning adapters emit simulated outcomes. When disabled,
                missing scanner binaries are reported as NOT INSTALLED and never faked. The live toggle is the backend{' '}
                <code className="font-mono">SIMULATION_MODE</code> variable.
              </p>
              <p className="text-[11.5px] text-faint leading-relaxed">
                Strict input filtering: targets are validated to domains, IPv4, and CIDR. Scan scope enforcement
                rejects out-of-scope targets with HTTP 403.
              </p>
            </div>
          </section>
        </div>

        {/* Account */}
        <div className="space-y-4">
          <section className="panel rounded-md p-4">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5 mb-3">
              <UserRound className="w-3.5 h-3.5" aria-hidden="true" />
              Session
            </h2>
            <dl className="space-y-2 text-[12px]">
              <div className="flex justify-between gap-3">
                <dt className="text-faint">Account</dt>
                <dd className="text-muted truncate">{overview.email || '…'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-faint">Role</dt>
                <dd className="text-muted">{overview.role || '…'}</dd>
              </div>
            </dl>
          </section>

          <section className="panel rounded-md p-4 space-y-2">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5 mb-2">
              <Shield className="w-3.5 h-3.5" aria-hidden="true" />
              Scanner availability
            </h2>
            <p className="text-[11.5px] text-faint leading-relaxed">
              Which scanner binaries are actually installed on the host. Detection uses real
              <code className="font-mono"> shutil.which </code>
              probes.
            </p>
            <Link
              to="/tools"
              className="inline-flex items-center gap-1.5 text-[11px] text-accent hover:text-accent/80 font-medium no-underline"
            >
              Open tool health →
            </Link>
          </section>
        </div>
      </div>
    </div>
  );
};