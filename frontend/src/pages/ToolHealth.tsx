import React, { useState, useEffect } from 'react';
import { Cpu, CheckCircle, XCircle, RefreshCw, Activity, AlertTriangle } from 'lucide-react';
import { apiFetch } from '../api';

const CATEGORY_LABELS: Record<string, string> = {
  recon: 'Recon',
  dns: 'DNS',
  service: 'Service',
  http: 'HTTP',
  vulnerability: 'Vulnerability',
  probe: 'Stdlib Probe',
};

export const ToolHealth: React.FC = () => {
  const [data, setData] = useState<{ tools: any[]; simulation_mode: boolean } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchInventory = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch('/tools/inventory');
      if (res.ok) {
        setData(await res.json());
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load tool inventory.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInventory();
  }, []);

  const tools = data?.tools ?? [];
  const installed = tools.filter((t) => t.installed).length;
  const missing = tools.filter((t) => !t.installed).length;
  const categories = [...new Set(tools.map((t) => t.category))];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Tool Health</h2>
          <p className="text-slate-400 text-sm">Live scanner availability. Detection is honest — via real <code className="font-mono">shutil.which</code> probes on the host.</p>
        </div>
        <button
          onClick={fetchInventory}
          className="flex items-center gap-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors text-slate-300"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Re-probe</span>
        </button>
      </div>

      {error && (
        <div className="flex gap-2 bg-red-950/20 border border-red-800/20 p-3 rounded-lg text-xs text-red-400">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary metric */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-5 flex flex-col justify-between h-28">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Registered Tools</span>
            <Cpu className="w-5 h-5 text-emerald-500" />
          </div>
          <span className="text-4xl font-extrabold text-white">{tools.length}</span>
        </div>
        <div className="glass-card p-5 flex flex-col justify-between h-28">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Installed / Callable</span>
            <CheckCircle className="w-5 h-5 text-emerald-500" />
          </div>
          <span className="text-4xl font-extrabold text-emerald-500">{installed}</span>
        </div>
        <div className="glass-card p-5 flex flex-col justify-between h-28">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Missing / Not Installed</span>
            <XCircle className="w-5 h-5 text-amber-500" />
          </div>
          <span className="text-4xl font-extrabold text-amber-500">{missing}</span>
        </div>
      </div>

      {data && (
        <div className="glass-card p-4 flex items-center gap-3 text-xs">
          <Activity className="w-4 h-4 text-emerald-500" />
          <span className="text-slate-300">
            Execution mode: <strong className="font-mono text-white">{data.simulation_mode ? 'SIMULATION' : 'REAL'}</strong>
          </span>
          <span className="text-slate-600">— {data.simulation_mode ? 'adapters emit simulated outcomes.' : 'missing binaries are reported as NOT INSTALLED and never faked.'}</span>
        </div>
      )}

      {/* Tool cards grouped by category */}
      <div className="space-y-6">
        {loading ? (
          <div className="text-slate-500 text-xs text-center py-16">Probing tool binaries...</div>
        ) : (
          categories.map((cat) => (
            <div key={cat} className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-300">{CATEGORY_LABELS[cat] || cat}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {tools.filter((t) => t.category === cat).map((tool) => (
                  <div
                    key={tool.tool}
                    className={`glass-card p-4 flex items-start justify-between gap-3 border ${
                      tool.installed ? 'border-slate-850' : 'border-slate-900 opacity-80'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${tool.installed ? 'bg-emerald-500' : 'bg-amber-500/70'}`} />
                        <span className="font-mono text-xs font-bold text-white">{tool.tool}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 space-y-0.5">
                        {tool.binary && (
                          <p>binary: <code className="font-mono text-slate-400">{tool.binary}</code></p>
                        )}
                        {tool.version && (
                          <p>version: <code className="font-mono text-emerald-400">{tool.version}</code></p>
                        )}
                        {tool.path && (
                          <p className="truncate" title={tool.path}>path: <code className="font-mono text-slate-400">{tool.path}</code></p>
                        )}
                        {(tool.note || (!tool.installed && !tool.binary)) && (
                          <p className="text-amber-400/80">{tool.note || 'stdlib probe — no external binary required'}</p>
                        )}
                      </div>
                    </div>
                    <span
                      className={`text-[9px] px-2 py-0.5 rounded-full font-bold border flex-shrink-0 ${
                        tool.installed
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                      }`}
                    >
                      {tool.installed ? 'INSTALLED' : 'NOT INSTALLED'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};