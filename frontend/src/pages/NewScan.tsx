import React, { useState, useEffect, useRef } from 'react';
import { ShieldAlert, Play, Terminal, ArrowRight, CheckCircle, AlertCircle, RefreshCw, XCircle, Cpu } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, authUrl } from '../api';

const TOOLS = [
  { id: 'subfinder', label: 'Subfinder', desc: 'subdomain enumeration' },
  { id: 'assetfinder', label: 'Assetfinder', desc: 'asset discovery' },
  { id: 'dnsx', label: 'DNSx', desc: 'DNS resolution' },
  { id: 'nmap', label: 'Nmap', desc: 'port scanning' },
  { id: 'httpx', label: 'HTTPx', desc: 'http probing' },
  { id: 'gau', label: 'GAU', desc: 'url archive fetch' },
  { id: 'whatweb', label: 'WhatWeb', desc: 'tech fingerprinting' },
  { id: 'nuclei', label: 'Nuclei', desc: 'vuln template matching' },
];

const PROFILES = [
  { id: 'standard', label: 'Standard', desc: 'Balanced discovery + verification' },
  { id: 'recon', label: 'Recon', desc: 'Enumeration focused, lighter analysis' },
  { id: 'audit', label: 'Full Audit', desc: 'Deep analysis, more tool stages' },
];

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

export const NewScan: React.FC = () => {
  const [target, setTarget] = useState('');
  const [selectedTools, setSelectedTools] = useState<Record<string, boolean>>(
    Object.fromEntries(TOOLS.map((t) => [t.id, true]))
  );
  const [severity, setSeverity] = useState<string>('');
  const [profile, setProfile] = useState<string>('standard');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanId, setScanId] = useState<number | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [toolLogs, setToolLogs] = useState<string[]>([]);
  const [status, setStatus] = useState('Pending');
  const [stage, setStage] = useState('Queued');
  const [coverage, setCoverage] = useState<number | null>(null);
  const [percent, setPercent] = useState<number | null>(null);
  const [score, setScore] = useState<number | null>(null);
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [scopeTarget, setScopeTarget] = useState('');
  const [scopeError, setScopeError] = useState('');
  const [cancelling, setCancelling] = useState(false);

  const logTerminalRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const navigate = useNavigate();

  const fetchScope = async () => {
    try {
      const res = await apiFetch('/scans/scope');
      if (res.ok) {
        const data = await res.json();
        setScopeList(Array.isArray(data?.scope) ? data.scope : []);
      }
    } catch (err) {
      console.error('Error fetching scope:', err);
    }
  };

  const addScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scopeTarget.trim()) return;
    setScopeError('');
    try {
      const res = await apiFetch('/scans/scope', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scopeTarget.trim() })
      });
      if (res.ok) {
        setScopeTarget('');
        await fetchScope();
      } else {
        const errData = await res.json().catch(() => null);
        setScopeError(errData?.detail || 'Could not add target to scope.');
      }
    } catch (err) {
      setScopeError('Server connection failed.');
    }
  };

  useEffect(() => {
    fetchScope();
  }, []);

  const toggleTool = (id: string) => {
    setSelectedTools((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError('');
    setLogs(['[System] Creating scan job...']);
    setToolLogs([]);
    setScanId(null);
    setStatus('Pending');
    setStage('Queued');
    setCoverage(null);
    setPercent(null);
    setScore(null);

    try {
      const res = await apiFetch('/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          tools: selectedTools,
          severity: severity || null,
          profile: profile || null,
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const detail = typeof errData?.detail === 'string' ? errData.detail : (errData?.detail?.msg || errData?.detail || 'Failed to create scan.');
        if (res.status === 403) {
          throw new Error(`Target outside authorized scope: ${detail}`);
        }
        if (res.status === 401) {
          throw new Error('Session expired. Please log in again.');
        }
        throw new Error(detail);
      }

      const data = await res.json();
      setScanId(data.scan_id);
      setStatus(data.status);
      setStage(data.stage || 'Queued');
      startSSEStream(data.scan_id);
    } catch (err: any) {
      setError(err.message || 'Server connection failed.');
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      const res = await apiFetch(`/scans/${scanId}/cancel`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setLogs((prev) => [...prev, `\n[System] Cancellation requested (${data.message || 'stage abandoned'}).`]);
      } else {
        const errData = await res.json().catch(() => null);
        setLogs((prev) => [...prev, `\n[Error] Cancel failed: ${errData?.detail || 'unknown'}`]);
      }
    } catch {
      setLogs((prev) => [...prev, '\n[Error] Cancel failed: server unreachable.']);
    } finally {
      setCancelling(false);
    }
  };

  const startSSEStream = (id: number) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = new EventSource(authUrl(`/scans/${id}/events`));
    eventSourceRef.current = es;

    const finish = () => {
      es.close();
      setLoading(false);
    };

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'error') {
          setError(data.error);
          finish();
          return;
        }

        if (data.type === 'stage') {
          setStage(data.stage);
          setStatus(data.status);
          setLogs((prev) => [...prev, `\n[Stage] ${data.stage} (${data.status})`]);
        }

        if (data.type === 'tool') {
          const line = `${data.tool} -> ${data.status}`;
          setToolLogs((prev) => [...prev, line]);
          setLogs((prev) => [...prev, `\n[Tool] ${line}`]);
        }

        if (data.type === 'finding') {
          setLogs((prev) => [...prev, `\n[Finding] ${data.severity}: ${data.title}`]);
        }

        if (data.type === 'progress') {
          setPercent(data.percent ?? null);
          setCoverage(data.coverage ?? null);
          if (data.security_score !== undefined && data.security_score !== null) {
            setScore(data.security_score);
          }
        }

        if (data.type === 'done') {
          setStatus(data.status);
          setStage(data.stage);
          setCoverage(data.coverage ?? null);
          setScore(data.security_score ?? null);
          setLogs((prev) => [...prev, `\n[Done] ${data.status} — coverage ${data.coverage ?? 0}%`]);
          finish();
        }
      } catch (err) {
        console.error('Error parsing SSE event data:', err);
      }
    };

    es.onerror = () => {
      es.close();
      setLoading(false);
      setLogs((prev) => [...prev, '\n[System Error] Lost Server connection stream. Scan runs in background.']);
    };
  };

  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [logs, toolLogs]);

  const isRunning = loading && status !== 'Completed' && status !== 'Failed' && status !== 'Cancelled';
  const allowedToolsCount = TOOLS.filter((t) => selectedTools[t.id]).length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Start New Scanning Job</h2>
        <p className="text-slate-400 text-sm">Configure scope-constrained tooling and queue an asynchronous scan pipeline.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Launch Scan Form */}
        <div className="glass-card p-6 space-y-4 h-fit">
          <h3 className="text-sm font-semibold text-slate-300">Scan Configuration</h3>
          <form onSubmit={handleTrigger} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="target-input" className="text-xs text-slate-400 font-medium">Target Host / IP Address</label>
              <input
                id="target-input"
                type="text"
                placeholder="e.g. sandbox.cyberagent.ai, 192.168.1.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>

            {/* Tool selection */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 font-medium">Scanner Tools ({allowedToolsCount}/{TOOLS.length})</label>
              <div className="grid grid-cols-2 gap-1.5">
                {TOOLS.map((tool) => (
                  <label
                    key={tool.id}
                    className={`flex items-start gap-2 p-2 rounded-lg border text-[10px] cursor-pointer transition-colors ${
                      selectedTools[tool.id]
                        ? 'bg-slate-900 border-emerald-500/40 text-slate-200'
                        : 'bg-slate-950 border-slate-800 text-slate-500'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={!!selectedTools[tool.id]}
                      onChange={() => toggleTool(tool.id)}
                      disabled={loading}
                      className="mt-0.5 accent-emerald-500"
                    />
                    <span className="leading-tight">
                      <span className="block font-semibold text-[10px]">{tool.label}</span>
                      <span className="block text-slate-600">{tool.desc}</span>
                    </span>
                  </label>
                ))}
              </div>
              <p className="text-[9px] text-slate-600">Missing binaries are reported as Not Installed and never simulated.</p>
            </div>

            {/* Severity + profile */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-slate-400 font-medium">Severity Floor</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  disabled={loading}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 transition-colors"
                >
                  <option value="">All severities</option>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-slate-400 font-medium">Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  disabled={loading}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 transition-colors"
                >
                  {PROFILES.map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
              </div>
            </div>

            {error && (
              <div className="flex gap-2 bg-red-950/20 border border-red-800/20 p-3 rounded-lg text-xs text-red-400">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !target.trim() || allowedToolsCount === 0}
              className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-slate-950 font-semibold text-sm px-4 py-2.5 rounded-lg flex items-center justify-center gap-2 cursor-pointer transition-colors shadow-lg shadow-emerald-500/10"
            >
              <Play className="w-4 h-4" />
              <span>{loading ? 'Executing scan pipeline...' : 'Queue Scan Pipeline'}</span>
            </button>
          </form>

          {scanId && (
            <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Scan ID:</span>
                <span className="text-slate-300 font-mono font-bold">#{scanId}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Current Status:</span>
                <span className={`font-semibold ${
                  status === 'Completed' ? 'text-emerald-500' :
                  status === 'Cancelled' ? 'text-slate-400' :
                  status === 'Failed' ? 'text-red-500' :
                  isRunning ? 'text-amber-500 animate-pulse' : 'text-slate-400'
                }`}>{status}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Lifecycle Stage:</span>
                <span className="text-slate-300 font-mono">{stage}</span>
              </div>

              {percent !== null && (
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px]">
                    <span className="text-slate-500">Job Progress</span>
                    <span className="text-slate-300 font-mono">{percent}%</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 transition-all duration-500"
                      style={{ width: `${Math.min(100, Math.max(0, percent ?? 0))}%` }}
                    />
                  </div>
                </div>
              )}

              {coverage !== null && (
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Coverage:</span>
                  <span className="font-bold text-slate-300">{coverage}%</span>
                </div>
              )}

              {score !== null && (
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Security Score:</span>
                  <span className={`font-bold ${
                    score >= 80 ? 'text-emerald-500' : score >= 50 ? 'text-warning' : 'text-danger'
                  }`}>{score}/100</span>
                </div>
              )}

              {isRunning && !cancelling && (
                <button
                  onClick={handleCancel}
                  className="w-full mt-1 bg-red-950/30 border border-red-800/40 text-red-400 hover:bg-red-950/50 text-xs font-semibold px-3 py-2 rounded-lg flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Request Cancellation</span>
                </button>
              )}

              {(status === 'Completed' || status === 'Cancelled' || status === 'Failed') && (
                <button
                  onClick={() => navigate(`/scans`)}
                  className="w-full mt-1 bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 text-xs font-semibold px-3 py-2 rounded-lg flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <span>Review Findings</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          )}
        </div>

        {/* Authorized scope manager */}
        <div className="glass-card p-6 space-y-4 h-fit">
          <h3 className="text-sm font-semibold text-slate-300">Authorized Scope</h3>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Triggers are only allowed for declared targets / IPs / CIDR blocks. Add a
            host, an IP, or a block to authorize it.
          </p>

          <form onSubmit={addScope} className="flex gap-2">
            <input
              type="text"
              placeholder="e.g. example.com, 192.168.1.0/24"
              value={scopeTarget}
              onChange={(e) => setScopeTarget(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
            />
            <button
              type="submit"
              disabled={!scopeTarget.trim()}
              className="bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:bg-slate-950 disabled:text-slate-600 text-slate-300 text-xs font-semibold px-3 py-2 rounded-lg cursor-pointer transition-colors flex-shrink-0"
            >
              Add
            </button>
          </form>

          {scopeError && (
            <div className="flex gap-2 bg-red-950/20 border border-red-800/20 p-2.5 rounded-lg text-[10px] text-red-400">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{scopeError}</span>
            </div>
          )}

          {scopeList.length === 0 ? (
            <p className="text-[10px] text-slate-600">No scope declared yet.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {scopeList.map((entry) => (
                <span
                  key={entry}
                  className="text-[10px] font-mono bg-slate-900 border border-slate-800 text-emerald-400 px-2 py-1 rounded"
                >
                  {entry}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Live streaming panel */}
        <div className="glass-card p-6 lg:col-span-2 space-y-4 flex flex-col h-[400px]">
          <div className="flex justify-between items-center flex-shrink-0">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-500" />
              <h3 className="text-sm font-semibold text-slate-300">Live Pipeline Events</h3>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full font-mono uppercase tracking-wider">
              Server Sent Events (SSE)
            </span>
          </div>

          <div className="flex gap-3 flex-1 min-h-0">
            {/* Tool status column */}
            <div className="w-1/3 bg-slate-950/40 border border-slate-850 rounded-lg p-3 overflow-y-auto space-y-1.5 flex-shrink-0">
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-bold uppercase tracking-wider sticky top-0 bg-slate-950/90 py-1">
                <Cpu className="w-3 h-3" />
                <span>Tool Status ({toolLogs.length})</span>
              </div>
              {toolLogs.length === 0 ? (
                <p className="text-[10px] text-slate-600">// No tool completions yet. Queued job launches tools asynchronously.</p>
              ) : (
                toolLogs.map((line, i) => {
                  const [name, statusLabel] = line.split(' -> ');
                  const isNotInstalled = statusLabel?.trim() === 'Not Installed';
                  const isOk = statusLabel?.trim() === 'Completed';
                  return (
                    <div key={i} className="text-[10px] font-mono flex justify-between items-center gap-2 border-b border-slate-900/60 pb-1.5">
                      <span className="text-slate-300 truncate">{name || line}</span>
                      <span className={`flex-shrink-0 ${
                        isOk ? 'text-emerald-500' : isNotInstalled ? 'text-amber-500/80' : 'text-slate-500'
                      }`}>{statusLabel}</span>
                    </div>
                  );
                })
              )}
            </div>

            {/* Event log */}
            <div
              ref={logTerminalRef}
              className="flex-1 bg-slate-950/60 border border-slate-850 rounded-lg p-4 font-mono text-xs text-emerald-400 overflow-y-auto whitespace-pre-wrap leading-relaxed shadow-inner min-h-0"
            >
              {logs.length === 0 ? (
                <span className="text-slate-600">// Ready. Enter target hostname above and queue a scan pipeline...</span>
              ) : (
                logs.join('')
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};