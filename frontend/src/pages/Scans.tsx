import React, { useState, useEffect, useRef } from 'react';
import {
  Layers,
  Terminal,
  Scale,
  FileSearch,
  ShieldCheck,
  ChevronRight,
  RotateCw,
} from 'lucide-react';
import { apiFetch, authUrl } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDate, formatDateTime } from '../components/format';

const STAGES = [
  { id: 'queued', label: 'Queued' },
  { id: 'starting', label: 'Starting' },
  { id: 'recon', label: 'Recon' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'service_scan', label: 'Service Scan' },
  { id: 'http_scan', label: 'HTTP Scan' },
  { id: 'vulnerability_scan', label: 'Vulnerability Scan' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'reporting', label: 'Reporting' },
];

export const Scans: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<any | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [liveEvents, setLiveEvents] = useState<string[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);
  const liveRef = useRef<HTMLDivElement>(null);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/scans/list');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Error fetching scans list:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectScan = async (id: number) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setLiveEvents([]);
    setDetailsLoading(true);
    setDetailError('');
    try {
      const res = await apiFetch(`/scans/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
        setVulnerabilities(data.vulnerabilities || []);
        setTools(data.tools || []);
        setLogs(data.logs || '');
        startSSEStream(id);
      } else {
        const errData = await res.json().catch(() => null);
        setDetailError(errData?.detail || 'Failed to load scan details.');
      }
    } catch {
      setDetailError('Server connection failed.');
    } finally {
      setDetailsLoading(false);
    }
  };

  const startSSEStream = (id: number) => {
    const es = new EventSource(authUrl(`/scans/${id}/events`));
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'error') {
          setLiveEvents((prev) => [...prev, `[Error] ${data.error}`]);
          setDetailsLoading(false);
          return;
        }
        if (data.type === 'stage') {
          setSelectedScan((prev: any) => (prev ? { ...prev, stage: data.stage, status: data.status } : prev));
          setLiveEvents((prev) => [...prev, `[Stage] ${data.stage} (${data.status})`]);
        }
        if (data.type === 'tool') {
          const line = `[Tool] ${data.tool} -> ${data.status}`;
          setLiveEvents((prev) => [...prev, line]);
          setTools((prev) => [...prev, { name: data.tool, status: data.status }]);
        }
        if (data.type === 'finding') {
          setLiveEvents((prev) => [...prev, `[Finding] ${data.severity}: ${data.title}`]);
        }
        if (data.type === 'progress') {
          setSelectedScan((prev: any) =>
            prev ? { ...prev, coverage: data.coverage, security_score: data.security_score } : prev
          );
        }
        if (data.type === 'done') {
          setSelectedScan((prev: any) =>
            prev
              ? {
                  ...prev,
                  status: data.status,
                  stage: data.stage,
                  coverage: data.coverage,
                  security_score: data.security_score,
                }
              : prev
          );
          setLiveEvents((prev) => [...prev, `[Done] ${data.status} — coverage ${data.coverage ?? 0}%`]);
          es.close();
          eventSourceRef.current = null;
          setDetailsLoading(false);
        }
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };

    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
    };
  };

  useEffect(() => {
    fetchScans();
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (liveRef.current) liveRef.current.scrollTop = liveRef.current.scrollHeight;
  }, [liveEvents]);

  const handleCancel = async () => {
    if (!selectedScan) return;
    setCancelling(true);
    try {
      const res = await apiFetch(`/scans/${selectedScan.id}/cancel`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setLiveEvents((prev) => [...prev, `[System] Cancellation requested. ${data.message || ''}`]);
        setSelectedScan((prev: any) => (prev ? { ...prev, status: 'Cancelling…' } : prev));
      } else {
        const errData = await res.json().catch(() => null);
        setLiveEvents((prev) => [...prev, `[Error] Cancel failed: ${errData?.detail || 'unknown'}`]);
      }
    } catch {
      setLiveEvents((prev) => [...prev, '[Error] Cancel failed: server unreachable.']);
    } finally {
      setCancelling(false);
    }
  };

  const stageIdx = (s?: string) => STAGES.findIndex((st) => st.id === (s || '').toLowerCase());
  const currentStageIdx = selectedScan ? stageIdx(selectedScan.stage) : -1;
  const terminalStage = selectedScan
    ? ['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase())
    : false;
  const lastInclusive = terminalStage ? STAGES.length : currentStageIdx + 1;
  const isActive = (idx: number) => !terminalStage && idx === currentStageIdx;
  const isDone = (idx: number) => idx < lastInclusive;
  const notInstalledTools = tools.filter((t) => (t.status || '').toLowerCase() === 'not installed').length;
  const canCancel =
    selectedScan &&
    (selectedScan.status === 'Running' || selectedScan.status === 'Pending' || selectedScan.status === 'Cancelling…') &&
    !['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase());

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assessments"
        title="Scan history"
        description="Stage-packed lifetime of each scanning job, its evidence, and outcomes."
        actions={
          selectedScan && currentStageIdx >= 0 && !terminalStage ? (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="inline-flex items-center gap-1.5 text-[11px] text-critical border border-critical/40 rounded px-2.5 py-1.5 hover:bg-critical/10 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Scale className="w-3 h-3" aria-hidden="true" />
              {cancelling ? 'Requesting…' : 'Request cancellation'}
            </button>
          ) : (
            <button
              onClick={fetchScans}
              className="inline-flex items-center gap-1.5 text-[11px] border border-line rounded px-2.5 py-1.5 text-muted hover:text-text hover:bg-surface-2 transition-colors cursor-pointer"
            >
              <RotateCw className="w-3 h-3" aria-hidden="true" />
              Refresh
            </button>
          )
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Scan list */}
        <div className="lg:col-span-1">
          <div className="panel rounded-md overflow-hidden">
            <div className="px-4 pt-4 pb-2 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Triggered scans</h2>
              <span className="mono-cell text-[10px] text-faint">{scans.length}</span>
            </div>
            <div className="max-h-[70vh] overflow-y-auto p-2">
              {loading ? (
                <div className="px-2 space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="skeleton h-14 rounded" />
                  ))}
                </div>
              ) : scans.length === 0 ? (
                <EmptyState
                  title="No scan logs"
                  description="Queue an assessment from the New Assessment page."
                />
              ) : (
                <ul className="space-y-1">
                  {scans.map((scan) => {
                    const selected = selectedScan?.id === scan.id;
                    return (
                      <li key={scan.id}>
                        <button
                          onClick={() => handleSelectScan(scan.id)}
                          className={`w-full text-left rounded px-3 py-2.5 border-l-2 transition-colors cursor-pointer ${
                            selected
                              ? 'bg-surface-2 border-accent'
                              : 'border-transparent hover:bg-surface-2/60'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[12px] font-medium text-text truncate">{scan.target}</span>
                            <StatusBadge status={scan.status} />
                          </div>
                          <div className="flex items-center justify-between mt-1 text-[10px] text-faint">
                            <span>#{scan.id}</span>
                            <span>{formatDate(scan.created_at)}</span>
                          </div>
                          {scan.security_score !== null && (
                            <p className="mono-cell text-[10px] text-faint mt-0.5">score: {scan.security_score}/100</p>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Detail */}
        <div className="lg:col-span-3">
          <div className="space-y-4">
            {detailsLoading ? (
              <SkeletonPanel className="min-h-[360px]" />
            ) : detailError ? (
              <ErrorState message={detailError} onRetry={() => selectedScan && handleSelectScan(selectedScan.id)} />
            ) : !selectedScan ? (
              <EmptyState
                icon={<FileSearch className="w-4 h-4" aria-hidden="true" />}
                title="No assessment selected"
                description="Select a scan from the list to inspect its pipeline, evidence, and findings."
              />
            ) : (
              <>
                {/* Header summary */}
                <div className="panel rounded-md p-4">
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                    <div className="min-w-0">
                      <h2 className="text-base font-semibold text-text truncate">{selectedScan.target}</h2>
                      <p className="mono-cell text-[10.5px] text-faint mt-1">
                        #{selectedScan.id} · queued {formatDateTime(selectedScan.created_at)}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 mt-2">
                        <StatusBadge status={selectedScan.status} />
                        <span className="mono-cell text-[10px] text-faint">stage: {selectedScan.stage || 'queued'}</span>
                        <span className="mono-cell text-[10px] text-faint">
                          mode: {selectedScan.simulation ? 'simulation' : 'real'}
                        </span>
                      </div>
                    </div>
                    <div className="shrink-0 flex items-center gap-6">
                      <div className="text-right">
                        <p className="eyebrow">Coverage</p>
                        <p className="text-lg font-semibold text-text">{selectedScan.coverage ?? '—'}%</p>
                      </div>
                      <div className="text-right">
                        <p className="eyebrow">Security score</p>
                        <p className="text-lg font-semibold text-text">{selectedScan.security_score ?? '—'}/100</p>
                      </div>
                    </div>
                  </div>

                  {/* Lifecycle */}
                  {selectedScan.stage && (
                    <div className="mt-4 pt-4 border-t border-line">
                      <div className="flex items-center gap-1.5 mb-2.5">
                        <Layers className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Pipeline lifecycle</span>
                      </div>
                      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
                        {STAGES.map((st, idx) => {
                          const done = isDone(idx) || (terminalStage && isDone(idx));
                          const active = isActive(idx);
                          return (
                            <div key={st.id} className="flex items-center gap-1.5 shrink-0">
                              <span
                                className={`px-2 py-1 rounded border mono-cell text-[9px] uppercase tracking-wide ${
                                  active
                                    ? 'border-accent/60 text-accent bg-accent/10'
                                    : done
                                    ? 'border-line-strong text-muted bg-surface-2'
                                    : 'border-line text-faint'
                                }`}
                              >
                                {st.label}
                              </span>
                              {idx < STAGES.length - 1 && (
                                <span className={`w-2 h-px ${isDone(idx) ? 'bg-line-strong' : 'bg-line'}`} />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>

                {/* Phase 5 assessment coverage */}
                {selectedScan.assessment?.coverage && (
                  <div className="panel rounded-md p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Assessment coverage</h3>
                      <span className="eyebrow">
                        {selectedScan.assessment.coverage.findings_confirmed ?? 0} confirmed finding(s)
                      </span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                      <KV label="Coverage" value={`${selectedScan.assessment.coverage.coverage_percent ?? '—'}%`} mono />
                      <KV
                        label="Tests executed"
                        value={`${selectedScan.assessment.coverage.tests_executed ?? 0}/${selectedScan.assessment.coverage.tests_applicable ?? 0}`}
                        mono
                      />
                      <KV label="Not applicable" value={String(selectedScan.assessment.coverage.tests_not_applicable ?? 0)} mono />
                      <KV label="Observations" value={String(selectedScan.assessment.coverage.observations ?? 0)} mono />
                    </div>
                    {selectedScan.assessment.coverage.findings_confirmed === 0 && (
                      <p className="text-[10.5px] text-faint mb-2">
                        Zero confirmed findings is not the same as zero risk. Unevaluated areas are listed below.
                      </p>
                    )}
                    {selectedScan.assessment.tests?.length > 0 && (
                      <div className="space-y-1 max-h-52 overflow-y-auto">
                        {selectedScan.assessment.tests.map((t: any) => (
                          <div key={t.test_id} className="flex items-center gap-2 border border-line rounded px-2.5 py-1.5">
                            <span className="mono-cell text-[10px] text-muted w-44 truncate">{t.test_id}</span>
                            <span
                              className={`mono-cell text-[9.5px] uppercase shrink-0 ${
                                t.status === 'executed' ? 'text-accent' : t.status === 'failed' ? 'text-high' : 'text-faint'
                              }`}
                            >
                              {t.status}
                            </span>
                            <span className="flex-1 min-w-0 text-[10px] text-faint truncate" title={t.reason || ''}>
                              {t.reason || ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Tool pipeline */}
                <div className="panel rounded-md p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Tool pipeline ({tools.length})</h3>
                    {notInstalledTools > 0 && (
                      <span className="mono-cell text-[10px] text-medium">{notInstalledTools} not installed</span>
                    )}
                  </div>
                  {tools.length === 0 ? (
                    <p className="text-[11px] text-faint">No tool completions yet. Queued jobs launch asynchronously.</p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                      {tools.map((tr, i) => (
                        <div
                          key={`${tr.name}-${i}`}
                          className="flex items-center justify-between gap-2 border border-line rounded px-2.5 py-2"
                          title={tr.raw_output ? 'raw output available in observations' : undefined}
                        >
                          <span className="mono-cell text-[11px] text-text truncate">{tr.name}</span>
                          <StatusBadge status={tr.status} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Findings */}
                <div className="panel rounded-md p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                      Findings ({vulnerabilities.length})
                    </h3>
                    <span className="eyebrow">evidence-backed</span>
                  </div>

                  {vulnerabilities.length === 0 ? (
                    <div className="flex flex-col items-center text-center py-6">
                      <ShieldCheck className="w-8 h-8 text-faint" strokeWidth={1.5} aria-hidden="true" />
                      <p className="text-[12px] text-muted mt-2">No evidence-backed findings persisted for this scan.</p>
                      <p className="text-[10.5px] text-faint mt-1">Findings are only ever created from real tool observations.</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {vulnerabilities.map((vuln) => {
                        const isExpanded = expandedVuln === vuln.id;
                        return (
                          <div key={vuln.id} className="border border-line rounded overflow-hidden">
                            <button
                              onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                              className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-surface-2/60 transition-colors cursor-pointer"
                              aria-expanded={isExpanded}
                            >
                              <SeverityBadge severity={vuln.severity} />
                              <span className="flex-1 min-w-0 text-[12px] font-medium text-text truncate">{vuln.title}</span>
                              {vuln.cve && <span className="mono-cell text-[10px] text-faint shrink-0">{vuln.cve}</span>}
                              <ChevronRight
                                className={`w-3.5 h-3.5 text-faint shrink-0 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                                aria-hidden="true"
                              />
                            </button>

                            {isExpanded && <FindingDetail vuln={vuln} />}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Live events + logs */}
                {(liveEvents.length > 0 || logs) && (
                  <>
                    <div className="panel rounded-md p-4">
                      <div className="flex items-center gap-1.5 mb-2">
                        <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Live events</span>
                      </div>
                      <pre className="bg-bg border border-line rounded p-3 font-mono text-[10.5px] text-accent/90 leading-relaxed max-h-28 overflow-y-auto whitespace-pre-wrap">
                        {liveEvents.length === 0 ? '// waiting…' : liveEvents.join('\n')}
                      </pre>
                    </div>
                    <div className="panel rounded-md p-4">
                      <div className="flex items-center gap-1.5 mb-2">
                        <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Scan logs</span>
                      </div>
                      <pre className="bg-bg border border-line rounded p-3 font-mono text-[10.5px] text-muted leading-relaxed max-h-48 overflow-y-auto whitespace-pre-wrap">
                        {logs || '// No logs yet.'}
                      </pre>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const FindingDetail: React.FC<{ vuln: any }> = ({ vuln }) => (
  <div className="border-t border-line bg-bg p-4 text-[11.5px] space-y-4">
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <KV label="State" value={vuln.state || 'NEW'} mono />
      <KV label="OWASP" value={vuln.owasp || '—'} />
      <KV label="MITRE ATT&CK" value={vuln.mitre || '—'} />
      <KV label="CVSS" value={vuln.cvss != null ? String(vuln.cvss) : '—'} />
    </div>

    <div>
      <p className="eyebrow mb-1">Description</p>
      <p className="text-muted leading-relaxed">{vuln.description}</p>
    </div>

    {vuln.remediation && (
      <div>
        <p className="eyebrow mb-1">Recommended mitigation</p>
        <p className="text-accent leading-relaxed">{vuln.remediation}</p>
      </div>
    )}

    {vuln.rule_id && (
      <div className="flex items-center gap-2">
        <p className="eyebrow">Rule</p>
        <span className="mono-cell text-[10px] text-faint">{vuln.rule_id}</span>
        {vuln.cwe && <span className="mono-cell text-[10px] text-faint">CWE-{vuln.cwe}</span>}
      </div>
    )}

    {vuln.evidence_observation_ids?.length > 0 && (
      <div>
        <p className="eyebrow mb-1.5">Evidence provenance</p>
        <div className="flex flex-wrap gap-1.5">
          {vuln.evidence_observation_ids.map((oid: number) => (
            <span key={oid} className="mono-cell text-[10px] text-accent border border-line rounded px-2 py-0.5">
              observation #{oid}
            </span>
          ))}
        </div>
      </div>
    )}

    {(vuln.category || vuln.source_test) && (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KV label="Category" value={vuln.category || '—'} mono />
        <KV label="Source test" value={vuln.source_test || '—'} mono />
        <KV label="Endpoint" value={vuln.endpoint ? `${vuln.http_method || ''} ${vuln.endpoint}` : '—'} />
        <KV label="Security boundary" value={vuln.evidence_records?.[0]?.security_boundary || '—'} />
      </div>
    )}

    {vuln.impact && (
      <div>
        <p className="eyebrow mb-1">Impact</p>
        <p className="text-muted leading-relaxed">{vuln.impact}</p>
      </div>
    )}

    {vuln.validation_reason && (
      <div>
        <p className="eyebrow mb-1">Deterministic validation</p>
        <p className="text-muted leading-relaxed">{vuln.validation_reason}</p>
      </div>
    )}

    {vuln.evidence_records?.length > 0 && (
      <div>
        <p className="eyebrow mb-1.5">Structured evidence</p>
        <div className="space-y-1.5">
          {vuln.evidence_records.map((e: any) => (
            <div key={e.id} className="border border-line rounded p-2.5 text-[10.5px]">
              <div className="flex items-center gap-2 mb-1">
                <span className="mono-cell text-[10px] text-accent">{e.evidence_type}</span>
                {e.observation_id != null && (
                  <span className="mono-cell text-[10px] text-faint">observation #{e.observation_id}</span>
                )}
                <span className="mono-cell text-[10px] text-faint">{e.redaction_status}</span>
              </div>
              <p className="text-muted"><span className="text-faint">expected:</span> {e.expected || '—'}</p>
              <p className="text-muted"><span className="text-faint">actual:</span> {e.actual || '—'}</p>
            </div>
          ))}
        </div>
      </div>
    )}

    {vuln.proof_of_concept && (
      <div>
        <p className="eyebrow mb-1.5">Proof of concept</p>
        <pre className="bg-surface-2 border border-line rounded p-3 font-mono text-[10px] text-muted overflow-x-auto whitespace-pre-wrap">
          {vuln.proof_of_concept}
        </pre>
      </div>
    )}
  </div>
);

const KV: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div>
    <p className="eyebrow mb-0.5">{label}</p>
    <p className={`text-[11px] text-muted break-words ${mono ? 'font-mono' : ''}`}>{value}</p>
  </div>
);