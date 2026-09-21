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
          <section className="panel p-5">
            <h2 className="flex items-center gap-1.5 mb-3 text-[12.5px] font-semibold text-text">
              <ServerCog className="w-3.5 h-3.5" aria-hidden="true" />
              External providers
            </h2>
            <div className="space-y-2 rounded-xl border border-line bg-bg p-3.5 text-[11.5px] leading-relaxed text-muted">
              <p>
                No third-party AI or intelligence provider is wired into this build. The ML
                advisory layer ships without a model and only reports coverage-gap guidance
                derived from persisted assessment state.
              </p>
              <p>
                Scanner availability (subfinder, nmap, nuclei, …) and orchestration behaviour
                are controlled by backend environment variables (<code className="font-mono">SIMULATION_MODE</code>,
                scanner binaries on the server PATH, <code className="font-mono">ADMIN_*</code> bootstrap config).
              </p>
            </div>
          </section>

          <section className="panel p-5">
            <h2 className="flex items-center gap-1.5 mb-3 text-[12.5px] font-semibold text-text">
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
                Strict input filtering: targets are validated to domains, IPv4, and CIDR. Scope enforcement
                rejects out-of-scope targets with HTTP 403.
              </p>
            </div>
          </section>
        </div>

        {/* Account */}
        <div className="space-y-4">
          <section className="panel p-5">
            <h2 className="flex items-center gap-1.5 mb-3 text-[12.5px] font-semibold text-text">
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

          <section className="panel p-5 space-y-2">
            <h2 className="flex items-center gap-1.5 mb-2 text-[12.5px] font-semibold text-text">
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
              className="inline-flex items-center gap-1.5 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
            >
              Open tool health →
            </Link>
          </section>
        </div>
      </div>
    </div>
  );
};