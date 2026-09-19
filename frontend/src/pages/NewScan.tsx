import React, { useState, useEffect, useRef } from 'react';
import {
  Radar,
  Crosshair,
  Terminal,
  BriefcaseBusiness,
  AlertCircle,
  CheckCircle2,
  Circle,
  ChevronRight,
} from 'lucide-react';
import { apiFetch, authUrl } from '../api';
import { PageHeader } from '../components/PageHeader';
import { Button } from '../components/Button';
import { Input } from '../components/Field';
import { Select } from '../components/Field';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';

const TOOLS = [
  { id: 'subfinder', group: 'Recon', label: 'Subfinder', desc: 'subdomain enumeration' },
  { id: 'assetfinder', group: 'Recon', label: 'Assetfinder', desc: 'asset discovery' },
  { id: 'dnsx', group: 'DNS', label: 'DNSx', desc: 'DNS resolution' },
  { id: 'nmap', group: 'Service', label: 'Nmap', desc: 'port scanning' },
  { id: 'httpx', group: 'HTTP', label: 'HTTPx', desc: 'http probing' },
  { id: 'gau', group: 'HTTP', label: 'GAU', desc: 'url archive fetch' },
  { id: 'whatweb', group: 'HTTP', label: 'WhatWeb', desc: 'tech fingerprinting' },
  { id: 'nuclei', group: 'Vulnerability', label: 'Nuclei', desc: 'vuln template matching' },
];

const PROFILES = [
  { id: 'standard', label: 'Standard', desc: 'Balanced discovery + verification' },
  { id: 'recon', label: 'Recon', desc: 'Enumeration focused, lighter analysis' },
  { id: 'audit', label: 'Full Audit', desc: 'Deep analysis, more tool stages' },
];

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

const TOOL_GROUPS = ['Recon', 'DNS', 'Service', 'HTTP', 'Vulnerability'];

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
        body: JSON.stringify({ target: scopeTarget.trim() }),
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
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const detail =
          typeof errData?.detail === 'string' ? errData.detail : errData?.detail?.msg || errData?.detail || 'Failed to create scan.';
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
    if (eventSourceRef.current) eventSourceRef.current.close();
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
          if (data.security_score !== undefined && data.security_score !== null) setScore(data.security_score);
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
      setLogs((prev) => [...prev, '\n[System Error] Lost server connection stream. Scan runs in background.']);
    };
  };

  useEffect(() => {
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (logTerminalRef.current) logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
  }, [logs, toolLogs]);

  const isRunning = loading && status !== 'Completed' && status !== 'Failed' && status !== 'Cancelled';
  const allowedToolsCount = TOOLS.filter((t) => selectedTools[t.id]).length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / New Assessment"
        title="Queue a new assessment"
        description="Configure scope-constrained tooling and queue an asynchronous scan pipeline."
      />

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* Configuration */}
        <div className="xl:col-span-4 space-y-4">
          <form onSubmit={handleTrigger} className="panel rounded-md p-4 space-y-4">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Scan Configuration</h2>

            <Input
              label="Target host / IP / CIDR"
              placeholder="sandbox.example.com, 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
              autoComplete="off"
              spellCheck={false}
            />

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-[11.5px] font-medium text-muted">Scanner tools</label>
                <span className="mono-cell text-[10px] text-faint">
                  {allowedToolsCount}/{TOOLS.length} selected
                </span>
              </div>
              <div className="space-y-2">
                {TOOL_GROUPS.map((group) => {
                  const groupTools = TOOLS.filter((t) => t.group === group);
                  return (
                    <div key={group}>
                      <p className="eyebrow mb-1">{group}</p>
                      <div className="border border-line rounded overflow-hidden divide-y divide-line/70">
                        {groupTools.map((tool) => (
                          <label
                            key={tool.id}
                            className={`flex items-start gap-2 px-2.5 py-2 cursor-pointer transition-colors ${
                              selectedTools[tool.id] ? 'bg-surface-2' : 'bg-transparent'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={!!selectedTools[tool.id]}
                              onChange={() => toggleTool(tool.id)}
                              disabled={loading}
                              className="mt-0.5 accent-accent"
                            />
                            <span className="leading-tight">
                              <span className="block text-[11px] font-medium text-text">{tool.label}</span>
                              <span className="block text-[10px] text-faint">{tool.desc}</span>
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="text-[10px] text-faint leading-relaxed">
                Missing binaries are reported as Not Installed and never simulated.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Select label="Severity floor" value={severity} onChange={(e) => setSeverity(e.target.value)} disabled={loading}>
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </Select>
              <Select label="Profile" value={profile} onChange={(e) => setProfile(e.target.value)} disabled={loading}>
                {PROFILES.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </Select>
            </div>

            {error && (
              <div className="flex gap-2 border border-critical/40 bg-critical/10 rounded px-3 py-2.5 text-[11px] text-critical">
                <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <Button type="submit" variant="primary" disabled={loading || !target.trim() || allowedToolsCount === 0} className="w-full">
              <Radar className="w-3.5 h-3.5" aria-hidden="true" />
              {loading ? 'Executing pipeline…' : 'Queue scan pipeline'}
            </Button>
          </form>

          {/* Scope manager */}
          <div className="panel rounded-md p-4 space-y-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
              <Crosshair className="w-3.5 h-3.5" aria-hidden="true" />
              Authorized Scope
            </h2>
            <p className="text-[11px] text-faint leading-relaxed">
              Only declared targets can be scanned. Out-of-scope triggers are rejected with HTTP 403.
            </p>
            <form onSubmit={addScope} className="flex gap-2">
              <input
                type="text"
                placeholder="example.com, 192.168.1.0/24"
                value={scopeTarget}
                onChange={(e) => setScopeTarget(e.target.value)}
                className="flex-1 bg-bg border border-line rounded px-3 py-2 text-[12px] text-text placeholder:text-faint/70 focus:outline-none focus:border-accent/60 transition-colors"
                aria-label="Scope target"
              />
              <Button type="submit" size="sm" disabled={!scopeTarget.trim()}>Add</Button>
            </form>
            {scopeError && (
              <p className="text-[11px] text-critical">{scopeError}</p>
            )}
            {scopeList.length === 0 ? (
              <EmptyState title="No scope declared" description="Targets are rejected until authorized here." />
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {scopeList.map((entry) => (
                  <span key={entry} className="mono-cell text-[10px] text-accent border border-line rounded px-2 py-0.5">
                    {entry}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Live events */}
        <div className="xl:col-span-8 panel rounded-md p-4 flex flex-col min-h-0" style={{ maxHeight: 720 }}>
          <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
              Live pipeline events
            </h2>
            <span className="mono-cell text-[10px] text-faint">SSE</span>
          </div>

          {scanId && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pb-4">
              <Meta label="Scan ID" value={`#${scanId}`} mono />
              <Meta label="Status" value={status} status />
              <Meta label="Stage" value={stage} mono />
              <Meta label="Coverage" value={coverage !== null ? `${coverage}%` : '—'} mono />
            </div>
          )}

          <div className="flex-1 min-h-[220px] grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Tool status */}
            <div className="border border-line rounded bg-bg p-3 overflow-y-auto">
              <div className="flex items-center gap-1.5 pb-2">
                <BriefcaseBusiness className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <span className="block text-[10px] text-faint uppercase tracking-[0.12em] font-mono">Tool progress</span>
                <span className="mono-cell text-[9px] text-faint ml-auto">{toolLogs.length}</span>
              </div>
              {toolLogs.length === 0 ? (
                <p className="text-[10px] text-faint mt-2">Waiting for tool completions…</p>
              ) : (
                <ul className="space-y-1">
                  {toolLogs.map((line, i) => {
                    const [name, val] = line.split(' -> ');
                    return (
                      <li key={i} className="flex items-center justify-between gap-2 text-[10.5px] font-mono">
                        <span className="text-muted truncate">{name}</span>
                        <ToolStatus value={val?.trim()} />
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* Event log */}
            <div
              ref={logTerminalRef}
              className="md:col-span-2 border border-line rounded bg-bg p-3 font-mono text-[11px] text-accent/90 overflow-y-auto whitespace-pre-wrap leading-relaxed"
              role="log"
              aria-label="Pipeline event log"
            >
              {logs.length === 0 ? (
                <span className="text-faint">// Ready. Enter a target and queue a scan pipeline…</span>
              ) : (
                logs.join('')
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-line mt-3">
            {scanId && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="inline-flex items-center gap-1.5 text-[11px] text-critical border border-critical/40 rounded px-2.5 py-1.5 hover:bg-critical/10 transition-colors disabled:opacity-50 cursor-pointer"
              >
                <Circle className="w-3 h-3" aria-hidden="true" />
                {cancelling ? 'Requesting…' : 'Request cancellation'}
              </button>
            )}
            {(status === 'Completed' || status === 'Cancelled' || status === 'Failed') && (
              <Button size="sm" onClick={() => (window.location.href = '/scans')}>
                Review findings
                <ChevronRight className="w-3 h-3" aria-hidden="true" />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const Meta: React.FC<{ label: string; value: string; mono?: boolean; status?: boolean }> = ({ label, value, mono, status }) => (
  <div className="border border-line rounded px-2.5 py-1.5">
    <p className="eyebrow">{label}</p>
    {status ? (
      <StatusBadge status={value} />
    ) : (
      <p className={`text-[12px] font-medium text-text mt-0.5 ${mono ? 'font-mono' : ''}`}>{value || '—'}</p>
    )}
  </div>
);

const ToolStatus: React.FC<{ value?: string }> = ({ value }) => {
  const val = (value || '').toLowerCase();
  if (val === 'completed' || val === 'success') {
    return <span className="flex items-center gap-1 text-accent"><CheckCircle2 className="w-3 h-3" />{value}</span>;
  }
  if (val === 'not installed') {
    return <span className="text-medium">{value}</span>;
  }
  return <span className="text-faint">{value || 'queued'}</span>;
};