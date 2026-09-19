import React, { useState, useEffect, useRef } from 'react';
import { ShieldAlert, Play, Terminal, ArrowRight, CheckCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, authUrl } from '../api';

export const NewScan: React.FC = () => {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanId, setScanId] = useState<number | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState('Pending');
  const [score, setScore] = useState<number | null>(null);
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [scopeTarget, setScopeTarget] = useState('');
  const [scopeError, setScopeError] = useState('');

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

  const handleTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError('');
    setLogs(['[System] Requesting scan creation...']);
    setScanId(null);
    setStatus('Pending');
    setScore(null);

    try {
      const res = await apiFetch('/scans/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const detail = typeof errData?.detail === 'string' ? errData.detail : (errData?.detail?.msg || errData?.detail || 'Failed to trigger scan.');
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
      startSSEStream(data.scan_id);
    } catch (err: any) {
      setError(err.message || 'Server connection failed.');
      setLoading(false);
    }
  };

  const startSSEStream = (id: number) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = new EventSource(authUrl(`/scans/${id}/stream`));
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.error) {
          setError(data.error);
          es.close();
          setLoading(false);
          return;
        }

        if (data.logs) {
          setLogs((prev) => [...prev, data.logs]);
        }

        if (data.status) {
          setStatus(data.status);
        }

        if (data.score !== undefined) {
          setScore(data.score);
        }

        if (data.done) {
          es.close();
          setLoading(false);
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

  // Autoscroll terminal
  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Start New Scanning Journey</h2>
        <p className="text-slate-400 text-sm">Enter a target network domain or IP block. CyberAgent AI Planner will decide and run the toolset.</p>
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
            
            {error && (
              <div className="flex gap-2 bg-red-950/20 border border-red-800/20 p-3 rounded-lg text-xs text-red-400">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-slate-950 font-semibold text-sm px-4 py-2.5 rounded-lg flex items-center justify-center gap-2 cursor-pointer transition-colors shadow-lg shadow-emerald-500/10"
            >
              <Play className="w-4 h-4" />
              <span>{loading ? 'Executing scan pipeline...' : 'Trigger Scan Workflow'}</span>
            </button>
          </form>

          {scanId && (
            <div className="pt-4 border-t border-slate-800/80 space-y-3">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Scan ID:</span>
                <span className="text-slate-300 font-mono font-bold">#{scanId}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Current Status:</span>
                <span className={`font-semibold ${
                  status === 'Completed' ? 'text-emerald-500' :
                  status === 'Running' ? 'text-amber-500 animate-pulse' :
                  status === 'Failed' ? 'text-red-500' : 'text-slate-400'
                }`}>{status}</span>
              </div>
              {score !== null && (
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Security Score:</span>
                  <span className={`font-bold ${
                    score >= 80 ? 'text-emerald-500' : score >= 50 ? 'text-warning' : 'text-danger'
                  }`}>{score}/100</span>
                </div>
              )}

              {status === 'Completed' && (
                <button
                  onClick={() => navigate(`/scans`)}
                  className="w-full mt-2 bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 text-xs font-semibold px-3 py-2 rounded-lg flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
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
        <div className="glass-card p-6 lg:col-span-2 space-y-4 flex flex-col h-[400px]">
          <div className="flex justify-between items-center flex-shrink-0">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-500" />
              <h3 className="text-sm font-semibold text-slate-300">Live Agent Streaming Logs</h3>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full font-mono uppercase tracking-wider">
              Server Sent Events (SSE)
            </span>
          </div>

          <div
            ref={logTerminalRef}
            className="flex-1 bg-slate-950/60 border border-slate-850 rounded-lg p-4 font-mono text-xs text-emerald-400 overflow-y-auto whitespace-pre-wrap leading-relaxed shadow-inner"
          >
            {logs.length === 0 ? (
              <span className="text-slate-600">// Ready. Enter target hostname above and initiate scans to read live output...</span>
            ) : (
              logs.join('')
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
