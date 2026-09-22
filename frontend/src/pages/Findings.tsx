import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ShieldAlert, X, Filter, FlaskConical, GitCommitHorizontal, ExternalLink } from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { DataTable } from '../components/DataTable';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatDate, formatDateTime } from '../components/format';

const TRIAGE_ACTIONS = [
  { id: 'confirm', label: 'Confirm' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'duplicate', label: 'Duplicate' },
  { id: 'accepted_risk', label: 'Accepted risk' },
  { id: 'resolve', label: 'Resolve' },
];

const SIH_AREAS: { key: string; label: string }[] = [
  { key: 'authentication', label: 'Authentication & Session Management' },
  { key: 'authorization', label: 'Authorization & Access Control' },
  { key: 'input_validation', label: 'Input Validation & Data Handling' },
  { key: 'api_security', label: 'API Security' },
  { key: 'client_side', label: 'Client-Side Security' },
  { key: 'secure_communication', label: 'Secure Communication (TLS)' },
  { key: 'data_protection', label: 'Data Protection & Privacy' },
];

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const STATUSES = ['confirmed', 'validated', 'candidate', 'rejected', 'duplicate', 'accepted', 'remediated'];

interface Finding {
  id: number;
  scan_id: number;
  target: string | null;
  assessment_type: string | null;
  title: string;
  severity: string;
  status: string;
  state: string;
  category: string | null;
  sih_areas: string[];
  cwe: string | null;
  owasp: string | null;
  endpoint: string | null;
  http_method: string | null;
  parameter: string | null;
  affected_component: string | null;
  confidence: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

const AREA_LABEL: Record<string, string> = Object.fromEntries(SIH_AREAS.map((a) => [a.key, a.label]));

export const Findings: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<Finding[] | null>(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  const severity = params.get('severity') || '';
  const status = params.get('status') || '';
  const sihArea = params.get('sih_area') || '';

  const fetchFindings = useCallback(async () => {
    setRows(null);
    setError('');
    const qs = new URLSearchParams();
    if (severity) qs.set('severity', severity);
    if (status) qs.set('status', status);
    if (sihArea) qs.set('sih_area', sihArea);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    try {
      const res = await apiFetch(`/findings${suffix}`);
      if (res.ok) {
        const data = await res.json();
        setRows(Array.isArray(data.findings) ? data.findings : []);
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load findings.');
      }
    } catch {
      setError('Server connection failed.');
    }
  }, [severity, status, sihArea]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const handleTriageUpdated = useCallback(() => {
    fetchFindings();
  }, [fetchFindings]);

  const counts = useMemo(() => {
    const base: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (rows || []).forEach((r) => {
      if (base[r.severity] !== undefined) base[r.severity] += 1;
    });
    return base;
  }, [rows]);

  const activeFilters = [severity && `severity: ${severity}`, status && `status: ${status}`, sihArea && `area: ${AREA_LABEL[sihArea] || sihArea}`]
    .filter(Boolean)
    .length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Assessments / Findings"
        title="Findings"
        description="Every finding across your assessments, derived from persisted evidence. Filter by severity, lifecycle status, or SIH26163 security area. Nothing here is synthesized."
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setFilter('severity', severity === s ? '' : s)}
            className={`panel p-4 text-left transition-colors duration-500 ease-spring ${
              severity === s ? 'border-accent/40' : ''
            }`}
          >
            <p className="eyebrow mb-1.5">{s}</p>
            <p className="tnum text-[24px] font-semibold leading-none tracking-tight text-text">{counts[s]}</p>
          </button>
        ))}
      </div>

      <div className="panel flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-2 text-faint">
          <Filter className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
          <span className="eyebrow">Filters</span>
        </div>
        <select
          value={severity}
          onChange={(e) => setFilter('severity', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setFilter('status', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text capitalize"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={sihArea}
          onChange={(e) => setFilter('sih_area', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text"
        >
          <option value="">All security areas</option>
          {SIH_AREAS.map((a) => (
            <option key={a.key} value={a.key}>{a.label}</option>
          ))}
        </select>
        {activeFilters > 0 && (
          <button
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
            className="rounded-full border border-line px-3 py-1.5 text-[11px] text-muted transition-colors duration-500 ease-spring hover:text-text"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto mono-cell text-[10px] text-faint">
          {rows === null ? '…' : `${rows.length} shown`}
        </span>
      </div>

      <DataTable
        rows={rows}
        keyField={(r: Finding) => String(r.id)}
        error={error}
        onRetry={fetchFindings}
        onRowClick={(r: Finding) => setSelected(r)}
        empty={{
          title: 'No findings match',
          description: 'Adjust the filters, or run an assessment to produce evidence-backed findings.',
        }}
        columns={[
          {
            key: 'severity',
            label: 'Severity',
            render: (r: Finding) => <SeverityBadge severity={r.severity} />,
          },
          {
            key: 'title',
            label: 'Finding',
            render: (r: Finding) => (
              <div className="min-w-0">
                <p className="truncate text-[12px] text-text">{r.title}</p>
                <p className="mono-cell truncate text-[10px] text-faint">
                  {r.http_method ? `${r.http_method} ` : ''}{r.endpoint || r.affected_component || '—'}
                </p>
              </div>
            ),
          },
          {
            key: 'areas',
            label: 'Security area',
            render: (r: Finding) => (
              <div className="flex flex-wrap gap-1">
                {(r.sih_areas || []).length === 0 ? (
                  <span className="text-faint text-[10.5px]">—</span>
                ) : (
                  r.sih_areas.map((a) => (
                    <span key={a} className="chip !py-0.5 !text-[9.5px]">{AREA_LABEL[a] || a}</span>
                  ))
                )}
              </div>
            ),
          },
          {
            key: 'target',
            label: 'Assessment',
            render: (r: Finding) => (
              <div className="min-w-0">
                <p className="truncate font-mono text-[10.5px] text-muted">{r.target || '—'}</p>
                <p className="mono-cell text-[9.5px] text-faint">
                  {r.assessment_type ? r.assessment_type.replace('_', ' ') : 'assessment'} #{r.scan_id}
                </p>
              </div>
            ),
          },
          {
            key: 'status',
            label: 'Status',
            render: (r: Finding) => (
              <span className="mono-cell text-[10px] text-muted capitalize">{(r.status || '').replace('_', ' ')}</span>
            ),
          },
          {
            key: 'first_seen',
            label: 'First seen',
            render: (r: Finding) => (
              <span className="mono-cell text-[10px] text-faint">{formatDate(r.first_seen)}</span>
            ),
          },
        ]}
      />

      {selected && (
        <FindingDrawer finding={selected} onClose={() => setSelected(null)} onUpdated={handleTriageUpdated} />
      )}
    </div>
  );
};

const FindingDrawer: React.FC<{ finding: Finding; onClose: () => void; onUpdated?: (id: number) => void }> = ({ finding, onClose, onUpdated }) => {
  const [detail, setDetail] = useState<any | null>(null);
  const [error, setError] = useState('');
  const [triageAction, setTriageAction] = useState<string>('');
  const [triageReason, setTriageReason] = useState('');
  const [triageBusy, setTriageBusy] = useState(false);
  const [triageError, setTriageError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setError('');
    setTriageError('');
    apiFetch(`/findings/${finding.id}`)
      .then(async (res) => (res.ok ? res.json() : Promise.reject(await res.json().catch(() => null))))
      .then((data) => !cancelled && setDetail(data))
      .catch((err) => !cancelled && setError(err?.detail || 'Failed to load finding detail.'));
    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  const runTriage = async () => {
    if (!triageAction) return;
    setTriageBusy(true);
    setTriageError('');
    try {
      const res = await apiFetch(`/findings/${finding.id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: triageAction, reason: triageReason || null }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(typeof errData?.detail === 'string' ? errData.detail : 'Triage failed.');
      }
      const data = await res.json();
      setTriageAction('');
      setTriageReason('');
      setDetail((prev: any) => (prev ? { ...prev, status: data.status, state: data.state } : prev));
      onUpdated?.(finding.id);
    } catch (err: any) {
      setTriageError(err.message || 'Triage failed.');
    } finally {
      setTriageBusy(false);
    }
  };

  const openAssetTab = () => {
    onClose();
    navigate(`/scans?scan=${finding.scan_id}`);
  };

  const poc = detail?.proof_of_concept;
  const cvss = detail?.cvss || {};
  const history = Array.isArray(detail?.history) ? detail.history : [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label="Finding detail">
      <div className="flex-1 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div className="glass flex h-full w-[560px] max-w-[94vw] flex-col overflow-hidden border-l border-line">
        <div className="flex items-start justify-between gap-3 border-b border-line p-4">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="mono-cell text-[10px] text-faint capitalize">{finding.status}</span>
            </div>
            <h2 className="text-[14px] font-semibold text-text">{finding.title}</h2>
            <p className="mono-cell mt-1 truncate text-[10px] text-faint">
              assessment #{finding.scan_id} · {finding.target || '—'}
            </p>
            <button
              onClick={openAssetTab}
              className="mt-2 inline-flex cursor-pointer items-center gap-1 rounded-full border border-line px-2.5 py-1 text-[10px] text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-accent"
            >
              <ExternalLink className="h-3 w-3" aria-hidden="true" />
              Open affected assets
            </button>
          </div>
          <button
            onClick={onClose}
            className="rounded-full p-1.5 text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-text"
            aria-label="Close"
          >
            <X className="h-4 w-4" strokeWidth={1.5} />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4 text-[11.5px]">
          {error && <p className="text-critical">{error}</p>}
          {!detail && !error && <p className="text-faint">Loading…</p>}
          {detail && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <KV label="Category" value={detail.category || '—'} mono />
                <KV label="Component" value={detail.affected_component || '—'} mono />
                <KV label="Endpoint" value={detail.endpoint || '—'} mono />
                <KV label="Parameter" value={detail.parameter || '—'} mono />
                <KV label="OWASP" value={detail.owasp || '—'} />
                <KV label="CWE" value={detail.cwe ? `CWE-${detail.cwe}` : '—'} mono />
              </div>

              {(cvss.vector || cvss.score != null) && (
                <div>
                  <p className="eyebrow mb-1.5">CVSS</p>
                  <div className="grid grid-cols-2 gap-3">
                    <KV label="Score / version" value={cvss.score != null ? `${cvss.score}${cvss.version ? ` (v${cvss.version})` : ''}` : '—'} mono />
                    <KV label="Vector" value={cvss.vector || '—'} mono />
                  </div>
                </div>
              )}

              {detail.description && (
                <div>
                  <p className="eyebrow mb-1">Description</p>
                  <p className="leading-relaxed text-muted">{detail.description}</p>
                </div>
              )}

              {(detail.remediation || detail.remediation_details?.technical_fix) && (
                <div>
                  <p className="eyebrow mb-1">Recommended remediation</p>
                  <p className="leading-relaxed text-accent">{detail.remediation || detail.remediation_details?.technical_fix}</p>
                </div>
              )}

              {detail.validation_reason && (
                <div>
                  <p className="eyebrow mb-1">Deterministic validation</p>
                  <p className="leading-relaxed text-muted">{detail.validation_reason}</p>
                </div>
              )}

              {poc && poc.request && (
                <div>
                  <p className="eyebrow mb-1.5">Proof of concept</p>
                  <div className="space-y-1 rounded-xl border border-line p-3 text-[10.5px]">
                    <p className="mono-cell text-faint">
                      {poc.request.method} {poc.request.endpoint || ''}
                      {poc.request.parameter ? ` (param: ${poc.request.parameter})` : ''}
                    </p>
                    <p className="text-muted"><span className="text-faint">expected:</span> {poc.expected_behavior || '—'}</p>
                    <p className="text-muted"><span className="text-faint">observed:</span> {poc.observed_behavior || '—'}</p>
                  </div>
                  {poc.steps_to_reproduce && (
                    <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-xl border border-line bg-surface-2 p-3 font-mono text-[10px] text-muted">
                      {poc.steps_to_reproduce}
                    </pre>
                  )}
                </div>
              )}

              {Array.isArray(detail.evidence) && detail.evidence.length > 0 && (
                <div>
                  <p className="eyebrow mb-1.5">Evidence ({detail.evidence.length})</p>
                  <div className="space-y-1.5">
                    {detail.evidence.map((e: any) => (
                      <div key={e.id} className="rounded-xl border border-line p-3 text-[10.5px]">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <FlaskConical className="h-3 w-3 text-accent" strokeWidth={1.5} aria-hidden="true" />
                          <span className="mono-cell text-[10px] text-accent">{e.evidence_type}</span>
                          <span className="mono-cell text-[10px] text-faint">{e.redaction_status}</span>
                          <span className="mono-cell text-[10px] text-faint">{e.security_boundary}</span>
                        </div>
                        <p className="text-muted"><span className="text-faint">expected:</span> {e.expected || '—'}</p>
                        <p className="text-muted"><span className="text-faint">actual:</span> {e.actual || '—'}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {!poc?.request && (!detail.evidence || detail.evidence.length === 0) && (
                <div className="flex items-start gap-2 rounded-xl border border-line p-3 text-[10.5px] text-faint">
                  <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" strokeWidth={1.5} aria-hidden="true" />
                  <span>No structured evidence or proof of concept is attached to this finding.</span>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <KV label="First seen" value={detail.first_seen ? formatDateTime(detail.first_seen) : '—'} />
                <KV label="Last seen" value={detail.last_seen ? formatDateTime(detail.last_seen) : '—'} />
              </div>

              {/* Verdict history timeline */}
              {history.length > 0 && (
                <div>
                  <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-text">
                    <GitCommitHorizontal className="h-3.5 w-3.5 text-faint" aria-hidden="true" />
                    Verdict history
                  </p>
                  <div className="space-y-1.5">
                    {history.map((h: any) => (
                      <div
                        key={h.id}
                        className="flex items-start gap-2 rounded-xl border border-line px-3 py-2 text-[10.5px]"
                      >
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                        <div className="min-w-0 flex-1">
                          <p className="font-mono text-[10px] text-muted">
                            {h.from_status} <span className="text-faint">→</span> {h.to_status}
                            <span className="ml-2 text-faint">by {h.actor || 'system'}</span>
                          </p>
                          <p className="mt-0.5 text-faint">{h.reason || ''}</p>
                          <p className="mt-0.5 text-[9.5px] text-faint">{h.created_at ? formatDateTime(h.created_at) : '—'}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Operator triage */}
              <div className="rounded-xl border border-line p-3">
                <p className="eyebrow mb-2">Operator triage</p>
                <div className="flex flex-wrap gap-1.5">
                  {TRIAGE_ACTIONS.map((a) => (
                    <button
                      key={a.id}
                      onClick={() => setTriageAction(triageAction === a.id ? '' : a.id)}
                      className={`mono-cell cursor-pointer rounded-full border px-2.5 py-1 text-[10px] transition-colors duration-500 ease-spring ${
                        triageAction === a.id
                          ? 'border-accent/60 bg-accent/10 text-accent'
                          : 'border-line text-faint hover:text-muted'
                      }`}
                      disabled={triageBusy}
                    >
                      {a.label}
                    </button>
                  ))}
                </div>
                {triageAction && (
                  <div className="mt-2 space-y-2">
                    <input
                      type="text"
                      value={triageReason}
                      onChange={(e) => setTriageReason(e.target.value)}
                      placeholder="Reason (optional, recorded in history)"
                      className="w-full rounded-xl border border-line bg-bg px-3 py-2 text-[11px] text-text placeholder:text-faint/70 focus:border-accent/60 focus:outline-none"
                    />
                    {triageError && <p className="text-[10.5px] text-critical">{triageError}</p>}
                    <button
                      onClick={runTriage}
                      disabled={triageBusy}
                      className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-[10.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20 disabled:opacity-50"
                    >
                      {triageBusy ? 'Applying…' : `Apply: ${TRIAGE_ACTIONS.find((x) => x.id === triageAction)?.label}`}
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

const KV: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div>
    <p className="eyebrow mb-0.5">{label}</p>
    <p className={`break-words text-[11px] text-muted ${mono ? 'font-mono' : ''}`}>{value}</p>
  </div>
);

export default Findings;
