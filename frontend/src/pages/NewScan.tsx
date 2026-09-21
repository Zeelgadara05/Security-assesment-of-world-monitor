import React, { useState, useEffect, useRef } from 'react';
import {
  Crosshair,
  Terminal,
  BriefcaseBusiness,
  AlertCircle,
  CheckCircle2,
  Ban,
  Circle,
  ChevronRight,
  ChevronLeft,
  Globe,
  Plus,
  ShieldCheck,
  Target,
  Lock,
} from 'lucide-react';
import { apiFetch, authUrl } from '../api';
import { useNavigate } from 'react-router-dom';
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

type AssessmentType = 'world_monitor' | 'custom_target' | '';

const STEPS = ['Path', 'Configure', 'Authorize'];

const hostOf = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
};

export const NewScan: React.FC = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [assessmentType, setAssessmentType] = useState<AssessmentType>('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [target, setTarget] = useState('');
  const [selectedTools, setSelectedTools] = useState<Record<string, boolean>>(
    Object.fromEntries(TOOLS.map((t) => [t.id, true]))
  );
  const [severity, setSeverity] = useState<string>('');
  const [profile, setProfile] = useState<string>('standard');
  const [activeTesting, setActiveTesting] = useState<boolean>(false);
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
  const [toolStatus, setToolStatus] = useState<{
    installed: any[];
    missing: any[];
    installed_count: number;
    missing_count: number;
  } | null>(null);
  const [toolStatusLoading, setToolStatusLoading] = useState(true);
  const [wmTargets, setWmTargets] = useState<any[]>([]);
  const [wmTargetId, setWmTargetId] = useState<string>('');
  const [wmBase, setWmBase] = useState('');
  const [wmApi, setWmApi] = useState('');
  const [wmOpenapi, setWmOpenapi] = useState('');
  const [wmSaving, setWmSaving] = useState(false);
  const [wmError, setWmError] = useState('');

  const logTerminalRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const selectedWm = wmTargets.find((t) => String(t.id) === wmTargetId);
  const effectiveTarget = assessmentType === 'world_monitor'
    ? (selectedWm ? hostOf(selectedWm.base_url) : '')
    : target.trim();

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

  const fetchToolStatus = async () => {
    setToolStatusLoading(true);
    try {
      const res = await apiFetch('/tools/status');
      if (res.ok) {
        const data = await res.json();
        setToolStatus({
          installed: data.installed || [],
          missing: data.missing || [],
          installed_count: data.installed_count || 0,
          missing_count: data.missing_count || 0,
        });
      }
    } catch (err) {
      console.error('Error fetching tool status:', err);
    } finally {
      setToolStatusLoading(false);
    }
  };

  const reprobeTools = async () => {
    setToolStatusLoading(true);
    try {
      await apiFetch('/tools/refresh', { method: 'POST' });
    } catch (err) {
      console.error('Error refreshing tool path:', err);
    }
    await fetchToolStatus();
  };

  const fetchWmTargets = async () => {
    try {
      const res = await apiFetch('/world-monitor/targets');
      if (res.ok) {
        const data = await res.json();
        setWmTargets(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Error fetching World Monitor targets:', err);
    }
  };

  const addWmTarget = async (e?: React.SyntheticEvent) => {
    e?.preventDefault();
    if (!wmBase.trim()) return;
    setWmError('');
    setWmSaving(true);
    const body: Record<string, string> = { base_url: wmBase.trim() };
    if (wmApi.trim()) body.api_base_url = wmApi.trim();
    if (wmOpenapi.trim()) body.openapi_url = wmOpenapi.trim();
    try {
      const res = await apiFetch('/world-monitor/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        const created = await res.json();
        setWmBase('');
        setWmApi('');
        setWmOpenapi('');
        await fetchWmTargets();
        if (created?.id !== undefined) setWmTargetId(String(created.id));
      } else {
        const errData = await res.json().catch(() => null);
        const detail =
          typeof errData?.detail === 'string' ? errData.detail : errData?.detail?.[0]?.msg || 'Could not register deployment.';
        setWmError(detail);
      }
    } catch {
      setWmError('Server connection failed.');
    } finally {
      setWmSaving(false);
    }
  };

  useEffect(() => {
    fetchScope();
    fetchToolStatus();
    fetchWmTargets();
  }, []);

  const toggleTool = (id: string) => {
    setSelectedTools((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const canConfigure = assessmentType !== '' && (assessmentType === 'world_monitor' ? !!wmTargetId : !!target.trim());
  const allowedToolsCount = TOOLS.filter((t) => selectedTools[t.id]).length;
  const canSubmit = canConfigure && acknowledged && allowedToolsCount > 0 && !loading;

  const handleTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setLoading(true);
    setError('');
    setLogs(['[System] Creating assessment job...']);
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
          target: effectiveTarget,
          tools: selectedTools,
          severity: severity || null,
          profile: profile || null,
          active_testing: activeTesting,
          assessment_type: assessmentType,
          authorization_acknowledged: acknowledged,
          world_monitor: assessmentType === 'world_monitor' && wmTargetId ? { target_id: Number(wmTargetId) } : null,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const detail =
          typeof errData?.detail === 'string' ? errData.detail : errData?.detail?.msg || errData?.detail || 'Failed to create assessment.';
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
      setLogs((prev) => [...prev, '\n[System Error] Lost server connection stream. Assessment runs in background.']);
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
  const inScope = effectiveTarget ? scopeList.includes(effectiveTarget) : false;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Assessments / New Assessment"
        title="Start an assessment"
        description="Choose an authorized path — a registered World Monitor deployment, or your own in-scope custom target — then configure the profile and confirm authorization."
      />

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* Configuration wizard */}
        <div className="xl:col-span-4 space-y-4">
          <form onSubmit={handleTrigger} className="panel space-y-5 p-5">
            {/* Stepper */}
            <ol className="flex items-center gap-1.5">
              {STEPS.map((label, i) => {
                const n = i + 1;
                const active = step === n;
                const done = step > n;
                return (
                  <li key={label} className="flex flex-1 items-center gap-1.5">
                    <span
                      className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold ${
                        done ? 'border-accent/40 bg-accent/15 text-accent' : active ? 'border-accent text-accent' : 'border-line text-faint'
                      }`}
                    >
                      {done ? '✓' : n}
                    </span>
                    <span className={`text-[10.5px] ${active ? 'text-text' : 'text-faint'}`}>{label}</span>
                    {n < STEPS.length && <span className="h-px flex-1 bg-line" />}
                  </li>
                );
              })}
            </ol>

            {/* Step 1 — path */}
            {step === 1 && (
              <div className="space-y-3">
                <p className="text-[11.5px] leading-relaxed text-muted">
                  Both paths run the same evidence-first assessment engine. Pick the one that matches your authorization.
                </p>
                <PathCard
                  icon={<Globe className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
                  title="World Monitor deployment"
                  description="Assess a registered World Monitor instance. Probes stay confined to the deployment host."
                  selected={assessmentType === 'world_monitor'}
                  onSelect={() => setAssessmentType('world_monitor')}
                />
                <PathCard
                  icon={<Target className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
                  title="Custom authorized target"
                  description="Assess a host, IP or CIDR that you have declared in your authorized scope."
                  selected={assessmentType === 'custom_target'}
                  onSelect={() => setAssessmentType('custom_target')}
                />
                <Button type="button" variant="primary" className="w-full" disabled={!assessmentType} onClick={() => setStep(2)}>
                  Continue
                  <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
                </Button>
              </div>
            )}

            {/* Step 2 — configure */}
            {step === 2 && assessmentType === 'custom_target' && (
              <div className="space-y-4">
                <Input
                  label="Target host / IP / CIDR"
                  placeholder="sandbox.example.com, 192.168.1.1"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={loading}
                  autoComplete="off"
                  spellCheck={false}
                />
                {target.trim() && !inScope && (
                  <p className="text-[10.5px] leading-relaxed text-medium">
                    Not in declared scope yet — add it below before launching, or the server will reject it with 403.
                  </p>
                )}
                <ToolPicker
                  selectedTools={selectedTools}
                  toggleTool={toggleTool}
                  disabled={loading}
                  allowedToolsCount={allowedToolsCount}
                />
                <OptionsRow
                  severity={severity}
                  setSeverity={setSeverity}
                  profile={profile}
                  setProfile={setProfile}
                  activeTesting={activeTesting}
                  setActiveTesting={setActiveTesting}
                  disabled={loading}
                />
                <WizardNav onBack={() => setStep(1)} onNext={() => setStep(3)} nextDisabled={!canConfigure} />
              </div>
            )}

            {step === 2 && assessmentType === 'world_monitor' && (
              <div className="space-y-4">
                <Select
                  label="Registered deployment"
                  value={wmTargetId}
                  onChange={(e) => setWmTargetId(e.target.value)}
                  disabled={loading || wmSaving}
                >
                  <option value="">Select a deployment…</option>
                  {wmTargets.map((t) => (
                    <option key={t.id} value={String(t.id)}>
                      #{t.id} {t.base_url} ({t.status})
                    </option>
                  ))}
                </Select>
                {selectedWm && (
                  <div className="rounded-xl border border-line px-3 py-2.5">
                    <p className="eyebrow mb-1">Assessment target</p>
                    <p className="font-mono text-[11px] text-text">{effectiveTarget || '—'}</p>
                    {effectiveTarget && !inScope && (
                      <p className="mt-1.5 text-[10.5px] leading-relaxed text-medium">
                        The deployment host is not in the declared scope — add it below or the server will reject it.
                      </p>
                    )}
                  </div>
                )}
                <details className="overflow-hidden rounded-xl border border-line">
                  <summary className="flex cursor-pointer items-center gap-1.5 px-2.5 py-2 text-[11px] text-muted">
                    <Plus className="w-3 h-3" aria-hidden="true" />
                    Register a deployment
                  </summary>
                  <div className="space-y-2 px-2.5 pb-2.5 pt-1">
                    <Input label="Base URL" placeholder="http://127.0.0.1:9000" value={wmBase} onChange={(e) => setWmBase(e.target.value)} disabled={wmSaving} autoComplete="off" spellCheck={false} />
                    <Input label="API base URL (optional)" placeholder="http://127.0.0.1:9000/api" value={wmApi} onChange={(e) => setWmApi(e.target.value)} disabled={wmSaving} autoComplete="off" spellCheck={false} />
                    <Input label="OpenAPI URL (optional)" placeholder="http://127.0.0.1:9000/openapi.json" value={wmOpenapi} onChange={(e) => setWmOpenapi(e.target.value)} disabled={wmSaving} autoComplete="off" spellCheck={false} />
                    {wmError && <p className="text-[11px] text-critical">{wmError}</p>}
                    <Button type="button" size="sm" onClick={addWmTarget} disabled={wmSaving || !wmBase.trim()}>
                      {wmSaving ? 'Registering…' : 'Register deployment'}
                    </Button>
                  </div>
                </details>
                <ToolPicker
                  selectedTools={selectedTools}
                  toggleTool={toggleTool}
                  disabled={loading}
                  allowedToolsCount={allowedToolsCount}
                />
                <OptionsRow
                  severity={severity}
                  setSeverity={setSeverity}
                  profile={profile}
                  setProfile={setProfile}
                  activeTesting={activeTesting}
                  setActiveTesting={setActiveTesting}
                  disabled={loading}
                />
                <WizardNav onBack={() => setStep(1)} onNext={() => setStep(3)} nextDisabled={!canConfigure} />
              </div>
            )}

            {/* Step 3 — authorize */}
            {step === 3 && (
              <div className="space-y-4">
                <div className="space-y-2 rounded-xl border border-line p-3.5">
                  <SummaryRow label="Path" value={assessmentType === 'world_monitor' ? 'World Monitor deployment' : 'Custom authorized target'} />
                  <SummaryRow label="Target" value={effectiveTarget || '—'} mono />
                  <SummaryRow label="Profile" value={PROFILES.find((p) => p.id === profile)?.label || profile} />
                  <SummaryRow label="Scanners" value={`${allowedToolsCount}/${TOOLS.length}`} />
                  <SummaryRow label="Active testing" value={activeTesting ? 'Enabled' : 'Disabled'} />
                </div>

                <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-accent/30 bg-accent/[0.05] px-3 py-3">
                  <input
                    type="checkbox"
                    checked={acknowledged}
                    onChange={(e) => setAcknowledged(e.target.checked)}
                    disabled={loading || isRunning}
                    className="mt-0.5 accent-accent"
                  />
                  <span className="leading-tight">
                    <span className="flex items-center gap-1.5 text-[11px] font-medium text-text">
                      <Lock className="w-3 h-3" aria-hidden="true" />
                      I am authorized to assess this target
                    </span>
                    <span className="mt-1 block text-[10px] leading-relaxed text-faint">
                      This acknowledgement is recorded for audit. Scope enforcement still happens server-side — out-of-scope targets are rejected with 403.
                    </span>
                  </span>
                </label>

                {error && (
                  <div className="flex gap-2 rounded-xl border border-critical/35 bg-critical/[0.07] px-3.5 py-3 text-[11.5px] leading-relaxed text-critical">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                    <span>{error}</span>
                  </div>
                )}

                <div className="flex gap-2">
                  <Button type="button" onClick={() => setStep(2)} disabled={loading || isRunning}>
                    <ChevronLeft className="w-3.5 h-3.5" aria-hidden="true" />
                    Back
                  </Button>
                  <Button type="submit" variant="primary" disabled={!canSubmit} className="flex-1">
                    <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                    {loading ? 'Running assessment…' : 'Launch assessment'}
                  </Button>
                </div>
              </div>
            )}

            {step < 3 && error && (
              <div className="flex gap-2 rounded-xl border border-critical/35 bg-critical/[0.07] px-3.5 py-3 text-[11.5px] leading-relaxed text-critical">
                <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}
          </form>

          {/* Scope manager */}
          <div className="panel space-y-3 p-5">
            <h2 className="text-[12.5px] font-semibold text-text flex items-center gap-1.5">
              <Crosshair className="w-3.5 h-3.5" aria-hidden="true" />
              Authorized Scope
            </h2>
            <p className="text-[11px] text-faint leading-relaxed">
              Only declared targets can be assessed. Out-of-scope launches are rejected with HTTP 403.
            </p>
            <form onSubmit={addScope} className="flex gap-2">
              <input
                type="text"
                placeholder="example.com, 192.168.1.0/24"
                value={scopeTarget}
                onChange={(e) => setScopeTarget(e.target.value)}
                className="flex-1 rounded-xl border border-line bg-bg px-3 py-2 text-[12px] text-text transition-colors duration-500 ease-spring placeholder:text-faint/70 focus:border-accent/60 focus:outline-none"
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
                  <span key={entry} className="mono-cell rounded-md border border-line px-2 py-0.5 text-[10px] text-accent">
                    {entry}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Scanner readiness / preflight preview */}
          <div className="panel space-y-3 p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-[12.5px] font-semibold text-text flex items-center gap-1.5">
                <Crosshair className="w-3.5 h-3.5" aria-hidden="true" />
                Scanner readiness
              </h2>
              <button
                type="button"
                onClick={reprobeTools}
                className="mono-cell cursor-pointer rounded-md border border-line px-2 py-0.5 text-[10px] text-faint transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
              >
                {toolStatusLoading ? 'probing…' : 're-probe'}
              </button>
            </div>
            <p className="text-[10.5px] text-faint leading-relaxed">
              Preflight preview from real <code className="font-mono">shutil.which</code> probes. Selected tools that are
              missing here are recorded as <span className="text-medium">gaps</span> — never simulated.
            </p>

            {!toolStatusLoading && toolStatus && (
              <div className="flex items-center gap-4">
                <span className="mono-cell text-[10px] text-accent">
                  <CheckCircle2 className="w-3 h-3 inline mr-1" aria-hidden="true" />
                  {toolStatus.installed_count} installed
                </span>
                <span className="mono-cell text-[10px] text-medium">
                  <Ban className="w-3 h-3 inline mr-1" aria-hidden="true" />
                  {toolStatus.missing_count} missing
                </span>
              </div>
            )}

            {!toolStatusLoading && toolStatus && toolStatus.installed_count === 0 && (
              <p className="text-[10.5px] leading-relaxed text-medium">
                No scanner binaries found on PATH. Install them, then <span className="text-text">re-probe</span>, or add
                their folder to <code className="font-mono">TOOL_PATH</code> in{' '}
                <code className="font-mono">backend/.env</code>.
              </p>
            )}

            {!toolStatusLoading && toolStatus && (
              (() => {
                const installedSet = new Set(toolStatus.installed.map((t) => t.tool));
                const selectedMissing = TOOLS.filter((t) => selectedTools[t.id] && !installedSet.has(t.id));
                return selectedMissing.length > 0 ? (
                  <div className="rounded-xl border border-warn/30 bg-warn/[0.06] px-3 py-2.5">
                    <p className="eyebrow mb-1">Selected but not installed — will record gaps</p>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedMissing.map((t) => (
                        <span key={t.id} className="mono-cell text-[10px] text-medium">{t.id}</span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="flex items-center gap-1.5 text-[11px] text-accent">
                    <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                    All selected scanners are callable on this host.
                  </p>
                );
              })()
            )}
          </div>
        </div>

        {/* Live pipeline */}
        <div className="xl:col-span-8 panel flex min-h-0 flex-col p-5" style={{ maxHeight: 720 }}>
          <div className="flex items-center justify-between pb-3 border-b border-line mb-3">
            <h2 className="text-[12.5px] font-semibold text-text flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
              Live pipeline events
            </h2>
            <span className="mono-cell text-[10px] text-faint">SSE</span>
          </div>

          {scanId && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pb-4">
              <Meta label="Assessment ID" value={`#${scanId}`} mono />
              <Meta label="Status" value={status} status />
              <Meta label="Stage" value={stage} mono />
              <Meta label="Coverage" value={coverage !== null ? `${coverage}%` : '—'} mono />
            </div>
          )}

          <div className="flex-1 min-h-[220px] grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Tool status */}
            <div className="overflow-y-auto rounded-xl border border-line bg-bg p-3">
              <div className="flex items-center gap-1.5 pb-2">
                <BriefcaseBusiness className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <span className="block text-[10px] text-faint uppercase tracking-[0.12em] font-mono">Tool progress</span>
                <span className="mono-cell text-[9px] text-faint ml-auto">{toolLogs.length}</span>
              </div>
              {toolLogs.length === 0 ? (
                <p className="text-[10px] text-faint mt-2">
                  {scanId
                    ? isRunning
                      ? 'Assessment running — awaiting first tool completion…'
                      : 'No tool completions were recorded for this assessment.'
                    : 'No assessment running — launch one to stream tool completions.'}
                </p>
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
              className="overflow-y-auto whitespace-pre-wrap rounded-xl border border-line bg-bg p-3 font-mono text-[11px] leading-relaxed text-accent/90 md:col-span-2"
              role="log"
              aria-label="Pipeline event log"
            >
              {logs.length === 0 ? (
                <span className="text-faint">// Ready. Configure an authorized assessment and launch it…</span>
              ) : (
                logs.join('')
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-line mt-3">
            {scanId && (
              <button
                type="button"
                onClick={handleCancel}
                disabled={cancelling}
                className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-critical/35 px-3 py-1.5 text-[11.5px] text-critical transition-colors duration-500 ease-spring hover:bg-critical/[0.08] disabled:opacity-50"
              >
                <Circle className="w-3 h-3" aria-hidden="true" />
                {cancelling ? 'Requesting…' : 'Request cancellation'}
              </button>
            )}
            {(status === 'Completed' || status === 'Cancelled' || status === 'Failed') && (
              <Button size="sm" onClick={() => navigate('/findings')}>
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

const PathCard: React.FC<{
  icon: React.ReactNode;
  title: string;
  description: string;
  selected: boolean;
  onSelect: () => void;
}> = ({ icon, title, description, selected, onSelect }) => (
  <button
    type="button"
    onClick={onSelect}
    className={`flex w-full items-start gap-3 rounded-xl border p-3.5 text-left transition-colors duration-500 ease-spring ${
      selected ? 'border-accent/50 bg-accent/[0.06]' : 'border-line hover:bg-surface-2/60'
    }`}
    aria-pressed={selected}
  >
    <span className={`mt-0.5 ${selected ? 'text-accent' : 'text-faint'}`}>{icon}</span>
    <span className="leading-tight">
      <span className="block text-[12px] font-medium text-text">{title}</span>
      <span className="mt-1 block text-[10.5px] leading-relaxed text-faint">{description}</span>
    </span>
  </button>
);

const SummaryRow: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="flex items-center justify-between gap-3">
    <span className="eyebrow">{label}</span>
    <span className={`text-[11px] text-text ${mono ? 'font-mono' : ''}`}>{value}</span>
  </div>
);

const WizardNav: React.FC<{ onBack: () => void; onNext: () => void; nextDisabled?: boolean }> = ({ onBack, onNext, nextDisabled }) => (
  <div className="flex gap-2">
    <Button type="button" onClick={onBack} disabled={false}>
      <ChevronLeft className="w-3.5 h-3.5" aria-hidden="true" />
      Back
    </Button>
    <Button type="button" variant="primary" className="flex-1" onClick={onNext} disabled={nextDisabled}>
      Continue
      <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
    </Button>
  </div>
);

const ToolPicker: React.FC<{
  selectedTools: Record<string, boolean>;
  toggleTool: (id: string) => void;
  disabled: boolean;
  allowedToolsCount: number;
}> = ({ selectedTools, toggleTool, disabled, allowedToolsCount }) => (
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
            <div className="overflow-hidden rounded-xl border border-line divide-y divide-line/70">
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
                    disabled={disabled}
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
);

const OptionsRow: React.FC<{
  severity: string;
  setSeverity: (v: string) => void;
  profile: string;
  setProfile: (v: string) => void;
  activeTesting: boolean;
  setActiveTesting: (v: boolean) => void;
  disabled: boolean;
}> = ({ severity, setSeverity, profile, setProfile, activeTesting, setActiveTesting, disabled }) => (
  <div className="space-y-3">
    <div className="grid grid-cols-2 gap-3">
      <Select label="Severity floor" value={severity} onChange={(e) => setSeverity(e.target.value)} disabled={disabled}>
        <option value="">All severities</option>
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </Select>
      <Select label="Profile" value={profile} onChange={(e) => setProfile(e.target.value)} disabled={disabled}>
        {PROFILES.map((p) => (
          <option key={p.id} value={p.id}>{p.label}</option>
        ))}
      </Select>
    </div>
    <label className="flex cursor-pointer items-start gap-2 rounded-xl border border-line px-3 py-2.5 transition-colors duration-500 ease-spring hover:bg-surface-2/60">
      <input
        type="checkbox"
        checked={activeTesting}
        onChange={(e) => setActiveTesting(e.target.checked)}
        disabled={disabled}
        className="mt-0.5 accent-accent"
      />
      <span className="leading-tight">
        <span className="block text-[11px] font-medium text-text">Active (mutating) testing</span>
        <span className="block text-[10px] text-faint">
          Opt-in: sends crafted comparison requests against scope-guarded endpoints. Off by default.
        </span>
      </span>
    </label>
  </div>
);

const Meta: React.FC<{ label: string; value: string; mono?: boolean; status?: boolean }> = ({ label, value, mono, status }) => (
  <div className="rounded-xl border border-line px-2.5 py-2">
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
