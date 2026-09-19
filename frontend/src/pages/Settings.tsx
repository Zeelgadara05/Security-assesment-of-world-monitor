import React, { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Shield, Radio, Key, Save, Server, Info } from 'lucide-react';
import { apiFetch } from '../api';

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
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">System Settings</h2>
        <p className="text-slate-400 text-sm">Configuration is driven by backend environment variables. No credentials are stored in this UI.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API keys config form */}
        <div className="glass-card p-6 lg:col-span-2 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-900 pb-3">
            <Info className="w-4.5 h-4.5 text-emerald-500" />
            <h3 className="text-sm font-semibold text-slate-200">External API Credentials</h3>
          </div>

          <div className="space-y-4">
            <div className="bg-slate-950/60 border border-slate-900 rounded-lg p-4 text-xs text-slate-400 space-y-2">
              <p>
                This build does not configure third-party AI or intelligence APIs. Third-party provider
                keys (OpenAI/Groq/Shodan) are placeholders only and are never stored, sent, or transmitted by this UI.
              </p>
              <p className="text-slate-500">
                Scanning tool availability (subfinder, nmap, nuclei, ...) and orchestration behavior are controlled
                by environment variables on the backend (<code className="font-mono">SIMULATION_MODE</code>,
                scanner binaries on the server PATH, <code className="font-mono">ADMIN_*</code> bootstrap config).
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">OpenAI Compatible API Key</label>
                <input
                  type="password"
                  readOnly
                  placeholder="sk-•••••••••••• (unused placeholder)"
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-500 placeholder-slate-700 focus:outline-none cursor-not-allowed"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">Groq API Key</label>
                <input
                  type="password"
                  readOnly
                  placeholder="gsk_•••••••••••• (unused placeholder)"
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-500 placeholder-slate-700 focus:outline-none cursor-not-allowed"
                />
              </div>

              <div className="space-y-1.5 md:col-span-2">
                <label className="text-xs text-slate-400 font-medium">Shodan API Key</label>
                <input
                  type="password"
                  readOnly
                  placeholder="sh-•••••••••••• (unused placeholder)"
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-500 placeholder-slate-700 focus:outline-none cursor-not-allowed"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Global toggles */}
        <div className="glass-card p-6 space-y-4 h-fit">
          <div className="flex items-center gap-2 border-b border-slate-900 pb-3">
            <Shield className="w-4.5 h-4.5 text-emerald-500" />
            <h3 className="text-sm font-semibold text-slate-200">Execution Guardrails</h3>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-0.5">
                <span className="font-semibold text-slate-200 block">Orchestrator Simulation Mode</span>
                <span className="text-slate-500 leading-normal block">
                  When enabled, scanning adapters emit simulated outcomes. When disabled, missing scanner binaries are
                  reported as NOT INSTALLED and never faked. Checked state is informational; the live toggle is the
                  backend <code className="font-mono">SIMULATION_MODE</code> variable.
                </span>
              </div>
            </div>

            <div className="flex items-start justify-between gap-3 pt-3 border-t border-slate-900/60">
              <div className="space-y-0.5">
                <span className="font-semibold text-slate-200 block">Strict Input Filtering</span>
                <span className="text-slate-500 leading-normal block">
                  Targets are validated to domains, IPv4, and CIDR. Scan scope enforcement (project scope list) rejects
                  out-of-scope targets with HTTP 403.
                </span>
              </div>
            </div>
          </div>

          <div className="border-t border-slate-900 pt-3">
            <p className="text-[10px] text-slate-500">
              Signed in as <span className="font-semibold text-slate-300">{overview.email || 'loading...'}</span>
              {overview.role ? ` (role: ${overview.role})` : ''}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};