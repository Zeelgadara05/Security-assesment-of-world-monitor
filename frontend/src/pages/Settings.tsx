import React, { useState } from 'react';
import { Settings as SettingsIcon, Shield, Radio, Key, Save, Server } from 'lucide-react';

export const Settings: React.FC = () => {
  const [openaiKey, setOpenaiKey] = useState('sk-proj-••••••••••••••••••••');
  const [groqKey, setGroqKey] = useState('gsk_••••••••••••••••••••');
  const [shodanKey, setShodanKey] = useState('sh_••••••••••••••••••••');
  const [simulationMode, setSimulationMode] = useState(true);
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">System Settings</h2>
        <p className="text-slate-400 text-sm">Configure AI keys, security scans constraints and external tool APIs.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API keys config form */}
        <div className="glass-card p-6 lg:col-span-2 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-900 pb-3">
            <Key className="w-4.5 h-4.5 text-emerald-500" />
            <h3 className="text-sm font-semibold text-slate-200">API Key Credentials</h3>
          </div>

          <form onSubmit={handleSave} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">OpenAI Compatible API Key</label>
                <input
                  type="password"
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-emerald-500/80 transition-colors"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">Groq API Key</label>
                <input
                  type="password"
                  value={groqKey}
                  onChange={(e) => setGroqKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-emerald-500/80 transition-colors"
                />
              </div>

              <div className="space-y-1.5 md:col-span-2">
                <label className="text-xs text-slate-400 font-medium">Shodan API Key</label>
                <input
                  type="password"
                  value={shodanKey}
                  onChange={(e) => setShodanKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-emerald-500/80 transition-colors"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-slate-900">
              <span className="text-xs text-slate-500 font-medium">Changes apply globally to active agent pipelines.</span>
              <button
                type="submit"
                className="bg-emerald-500 hover:bg-emerald-600 text-slate-955 font-semibold text-xs px-4 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{saved ? 'Settings Saved' : 'Save Configurations'}</span>
              </button>
            </div>
          </form>
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
                  Simulate scanning tool outcomes. Keeps executions 100% safe, fast, and does not require local packages.
                </span>
              </div>
              <input
                type="checkbox"
                checked={simulationMode}
                onChange={(e) => setSimulationMode(e.target.checked)}
                className="w-4 h-4 rounded text-emerald-500 accent-emerald-500 cursor-pointer bg-slate-950 border-slate-800"
              />
            </div>

            <div className="flex items-start justify-between gap-3 pt-3 border-t border-slate-900/60">
              <div className="space-y-0.5">
                <span className="font-semibold text-slate-200 block">Strict Input Filtering</span>
                <span className="text-slate-500 leading-normal block">
                  Enforces DNS mapping lookup validations to prevent running commands on arbitrary IP addresses.
                </span>
              </div>
              <input
                type="checkbox"
                checked
                disabled
                className="w-4 h-4 rounded text-emerald-500 accent-emerald-500 cursor-not-allowed bg-slate-950 border-slate-800 opacity-60"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
