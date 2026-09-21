import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu,
  Layers,
  Terminal,
  AlertCircle,
  CheckCircle2,
  Ban,
  Activity,
  RotateCw,
  ChevronRight,
  Scale,
} from 'lucide-react';
import { apiFetch } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDateTime, humanDuration } from '../components/format';

interface Phase7ConsoleProps {
  scanId: number;
}

export const Phase7Console: React.FC<Phase7ConsoleProps> = ({ scanId }) => {
  const [state, setState] = useState<any | null>(null);
  const [readiness, setReadiness] = useState<any | null>(null);
  const [stages, setStages] = useState<any[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [eventCursor, setEventCursor] = useState(0);
  const [hasMoreEvents, setHasMoreEvents] = useState(false);
  const [ml, setMl] = useState<any | null>(null);
  const [allScans, setAllScans] = useState<any[]>([]);
  const [compareWith, setCompareWith] = useState<number | null>(null);
  const [compare, setCompare] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchAll = useCallback(
    async (cursor: number, replace: boolean) => {
      setError('');
      try {
        const [s, r, st, ex, ev, m, scans] = await Promise.all([
          apiFetch(`/scans/${scanId}/state`),
          apiFetch(`/scans/${scanId}/readiness`),
          apiFetch(`/scans/${scanId}/stages`),
          apiFetch(`/scans/${scanId}/executions`),
          apiFetch(`/scans/${scanId}/typed-events?cursor=${cursor}&limit=500`),
          apiFetch(`/scans/${scanId}/ml-advisory`),
          apiFetch('/scans/list'),
        ]);
        setState(s.ok ? await s.json() : null);
        setReadiness(r.ok ? await r.json() : null);
        setStages(st.ok ? await st.json() : []);
        setExecutions(ex.ok ? await ex.json() : []);
        if (ev.ok) {
          const payload = await ev.json();
          const items = payload.events || [];
          setEvents((prev) => (replace ? items : [...prev, ...items]));
          setEventCursor(payload.cursor ?? cursor);
          setHasMoreEvents(Boolean(payload.has_more));
        }
        setMl(m.ok ? await m.json() : null);
        setAllScans(scans.ok ? (await scans.json()) || [] : []);
      } catch (err) {
        setError('Server connection failed while loading the execution console.');
        console.error('phase7 console load error:', err);
      } finally {
        setLoading(false);
      }
    },
    [scanId]
  );

  useEffect(() => {
    setLoading(true);
    setEvents([]);
    setEventCursor(0);
    setHasMoreEvents(false);
    setCompare(null);
    setCompareWith(null);
    fetchAll(0, true);
  }, [scanId, fetchAll]);

  const refresh = () => {
    setLoading(true);
    fetchAll(0, true);
  };

  const loadMoreEvents = () => fetchAll(eventCursor, false);

  const runCompare = async () => {
    if (compareWith === null) return;
    try {
      const res = await apiFetch(`/scans/${scanId}/compare?with_scan_id=${compareWith}`);
      if (res.ok) {
        setCompare(await res.json());
      } else {
        const errData = await res.json().catch(() => null);
        setCompare({ error: errData?.detail || 'Compare failed.' });
      }
    } catch {
      setCompare({ error: 'Compare failed: server unreachable.' });
    }
  };

  if (loading && !state) {
    return (
      <div className="panel rounded-md p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Phase 7 execution platform</span>
        </div>
        <SkeletonPanel className="min-h-[200px]" />
      </div>
    );
  }

  const pre = readiness?.preflight || {};
  const toolReadiness = readiness?.tools || [];

  return (
    <div className="space-y-4">
      <div className="panel rounded-md p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted">
              Phase 7 execution platform
            </h3>
          </div>
          <button
            onClick={refresh}
            className="inline-flex items-center gap-1.5 text-[11px] border border-line rounded px-2.5 py-1.5 text-muted hover:text-text hover:bg-surface-2 transition-colors cursor-pointer"
          >
            <RotateCw className="w-3 h-3" aria-hidden="true" />
            Refresh
          </button>
        </div>

        {error && (
          <div className="mb-3 flex gap-2 border border-critical/40 bg-critical/10 rounded px-3 py-2.5 text-[11px] text-critical">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        {/* State machine */}
        {state && (
          <div className="border border-line rounded p-3 mb-3">
            <div className="flex flex-wrap items-center gap-3">
              <KV label="State" value={state.state || '—'} mono />
              <KV label="Coarse completion" value={state.coarse_completion || '—'} mono />
              <KV label="Stage" value={state.stage || '—'} mono />
              <span className="eyebrow">
                terminal:{' '}
                <span className={state.terminal ? 'text-critical' : 'text-accent'}>{String(Boolean(state.terminal))}</span>
              </span>
              {state.queue_waited_ms !== null && state.queue_waited_ms !== undefined && (
                <KV label="Queue wait" value={humanDuration(state.queue_waited_ms)} />
              )}
            </div>
            {(state.transitions || []).length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 mt-2 pt-2 border-t border-line">
                <span className="eyebrow">Transitions</span>
                {(state.transitions as string[]).map((t) => (
                  <span key={t} className="mono-cell text-[10px] text-faint border border-line rounded px-2 py-0.5">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Preflight / readiness */}
        {readiness && (
          <div className="border border-line rounded p-3 mb-3">
            <div className="flex flex-wrap items-center gap-3 mb-2">
              <span className="eyebrow">Preflight readiness</span>
              <span className={`mono-cell text-[10px] ${pre.runnable ? 'text-accent' : 'text-critical'}`}>
                runnable: {String(Boolean(pre.runnable))}
              </span>
              {(pre.blocked_reasons || []).map((reason: string, i: number) => (
                <span key={i} className="mono-cell text-[10px] text-critical">
                  {reason}
                </span>
              ))}
              <span className="mono-cell text-[10px] text-faint ml-auto">
                msg: {toolReadiness.filter((t: any) => t.status === 'missing').length} missing ·{' '}
                {toolReadiness.filter((t: any) => t.status === 'disabled').length} disabled
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {toolReadiness.map((t: any) => (
                <div key={t.tool} className="flex items-center justify-between gap-2 border border-line rounded px-2.5 py-1.5">
                  <div className="min-w-0">
                    <p className="mono-cell text-[10.5px] text-text truncate">{t.tool}</p>
                    <p className="text-[9.5px] text-faint truncate">{t.reason || (t.adapter ? `${t.adapter} adapter` : t.category)}</p>
                  </div>
                  <ReadinessBadge status={t.status} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Stage ledger */}
        <div className="border border-line rounded p-3 mb-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Layers className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Stage ledger ({stages.length})</span>
          </div>
          {stages.length === 0 ? (
            <p className="text-[11px] text-faint">No stage rows persisted yet.</p>
          ) : (
            <div className="space-y-1 max-h-72 overflow-y-auto">
              {stages.map((s) => (
                <div key={s.id ?? `${s.name}-${s.order}`} className="flex items-center gap-2 border border-line rounded px-2.5 py-1.5">
                  <span className="mono-cell text-[10px] text-muted w-24 shrink-0">
                    {s.order}. {s.name}
                  </span>
                  <StatusBadge status={s.status} />
                  <span className="flex-1 min-w-0 text-[10px] text-faint truncate" title={s.reason || ''}>
                    {s.reason || ''}
                  </span>
                  <span className="mono-cell text-[9.5px] text-faint shrink-0">
                    tools {s.tools?.length ?? 0} · obs {s.observations ?? 0} · cand {s.candidates ?? 0} · conf{' '}
                    {s.confirmed_findings ?? 0}
                  </span>
                  {s.duration_ms != null && (
                    <span className="mono-cell text-[9.5px] text-faint shrink-0 hidden sm:inline">
                      {humanDuration(s.duration_ms)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Execution ledger */}
        <div className="border border-line rounded p-3 mb-3">
          <div className="flex items-center gap-1.5 mb-2">
            <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">
              Execution ledger ({executions.length})
            </span>
          </div>
          {executions.length === 0 ? (
            <p className="text-[11px] text-faint">No tool executions recorded yet.</p>
          ) : (
            <div className="space-y-1 max-h-72 overflow-y-auto">
              {executions.map((ex) => (
                <div key={ex.id} className="flex items-center gap-2 border border-line rounded px-2.5 py-1.5">
                  <span className="mono-cell text-[10px] text-muted w-20 truncate shrink-0" title={ex.stage}>
                    {ex.stage}
                  </span>
                  <span className="mono-cell text-[11px] text-text w-28 truncate shrink-0" title={ex.tool}>
                    {ex.tool}
                  </span>
                  <span className="mono-cell text-[9.5px] text-faint shrink-0">{ex.adapter || '—'}</span>
                  <ExecutionBadge status={ex.status} />
                  {ex.exit_code !== null && ex.exit_code !== undefined && (
                    <span className="mono-cell text-[9.5px] text-faint shrink-0">exit {ex.exit_code}</span>
                  )}
                  {ex.duration_ms != null && (
                    <span className="mono-cell text-[9.5px] text-faint shrink-0 hidden md:inline">{humanDuration(ex.duration_ms)}</span>
                  )}
                  <span className="mono-cell text-[9.5px] text-faint shrink-0 hidden md:inline">
                    obs {ex.parsed_observations ?? 0}
                  </span>
                  {ex.cancellation_state && (
                    <span className="mono-cell text-[9.5px] text-medium shrink-0">cancelled:{ex.cancellation_state}</span>
                  )}
                  {ex.termination_reason && (
                    <span className="flex-1 min-w-0 text-[10px] text-faint truncate" title={ex.termination_reason}>
                      {ex.termination_reason}
                    </span>
                  )}
                  {ex.command_redacted && (
                    <ChevronRight className="w-3 h-3 text-faint shrink-0" aria-hidden="true" />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Typed events replay */}
        <div className="border border-line rounded p-3 mb-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Typed events</span>
            </div>
            {hasMoreEvents && (
              <button
                onClick={loadMoreEvents}
                className="mono-cell text-[10px] border border-line rounded px-2 py-0.5 text-muted hover:text-text hover:bg-surface-2 transition-colors cursor-pointer"
              >
                Load more (cursor {eventCursor})
              </button>
            )}
          </div>
          <pre className="bg-bg border border-line rounded p-3 font-mono text-[10.5px] text-accent/90 leading-relaxed max-h-64 overflow-y-auto whitespace-pre-wrap">
            {events.length === 0
              ? '// No typed events persisted.'
              : events
                  .map((e) => {
                    const d = e.data || {};
                    let line = `[${e.type}] `;
                    if (e.type === 'state') line += `state=${d.state ?? ''}`;
                    else if (e.type === 'stage') line += `stage=${d.stage ?? ''} status=${d.status ?? ''}`;
                    else if (e.type === 'tool') line += `${d.tool ?? ''} -> ${d.status ?? ''}`;
                    else if (e.type === 'preflight') line += `runnable=${d.runnable ?? ''} missing=${(d.missing || []).join(',')}`;
                    else if (e.type === 'progress') line += `percent=${d.percent ?? ''}`;
                    else if (e.type === 'coverage') line += `coverage=${d.coverage ?? ''}`;
                    else if (e.type === 'finding') line += `${d.severity ?? ''}: ${d.title ?? ''}`;
                    else if (e.type === 'done') line += `state=${d.state ?? d.status ?? ''}`;
                    else line += JSON.stringify(d);
                    return `#${e.seq} ${line}`;
                  })
                  .join('\n')}
          </pre>
        </div>

        {/* ML advisory */}
        {ml && (
          <div className="border border-line rounded p-3 mb-3">
            <div className="flex flex-wrap items-center gap-3 mb-2">
              <span className="eyebrow">Advisory record</span>
              <StatusBadge status={ml.status || 'advisory_only'} />
              <span className="mono-cell text-[10px] text-faint">model: {ml.model_name || 'none (deterministic advisory)'}</span>
              <span className="mono-cell text-[10px] text-faint">schema: {ml.feature_schema_version || '—'}</span>
              <span className="mono-cell text-[10px] text-faint">
                {ml.generated_at ? formatDateTime(ml.generated_at) : '—'}
              </span>
            </div>
            {ml.advisory && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10.5px]">
                <div className="border border-line rounded p-2.5">
                  <p className="eyebrow mb-1">Coverage advisory</p>
                  <p className="text-muted leading-relaxed">{ml.advisory.summary || ml.advisory.advisory || '—'}</p>
                </div>
                {(ml.advisory.tool_gaps as string[] | undefined)?.length ? (
                  <div className="border border-line rounded p-2.5">
                    <p className="eyebrow mb-1">Tool gaps</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(ml.advisory.tool_gaps as string[]).map((g) => (
                        <span key={g} className="mono-cell text-[10px] text-medium border border-warn/30 rounded px-2 py-0.5">
                          {g}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        )}

        {/* Cross-scan compare */}
        <div className="border border-line rounded p-3">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <Scale className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">Cross-scan findings diff</span>
            <select
              value={compareWith === null ? '' : String(compareWith)}
              onChange={(e) => setCompareWith(e.target.value ? Number(e.target.value) : null)}
              className="bg-bg border border-line rounded px-2 py-1 text-[11px] text-muted focus:outline-none focus:border-accent/60"
            >
              <option value="">Select a scan to compare…</option>
              {allScans
                .filter((s) => s.id !== scanId)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} {s.target}
                  </option>
                ))}
            </select>
            <button
              onClick={runCompare}
              disabled={compareWith === null}
              className="inline-flex items-center gap-1.5 text-[11px] border border-line rounded px-2.5 py-1 text-muted hover:text-text hover:bg-surface-2 transition-colors disabled:opacity-50 cursor-pointer"
            >
              Compare
            </button>
          </div>
          {compare && (
            <div className="flex flex-wrap items-center gap-2">
              {compare.error ? (
                <span className="text-[11px] text-critical">{compare.error}</span>
              ) : (
                <>
                  {compare.same_target === false && (
                    <span className="mono-cell text-[10px] text-faint w-full">{compare.note || ''}</span>
                  )}
                  <CompareChip label="added" count={compare.added?.length ?? 0} tone="danger" />
                  <CompareChip label="removed" count={compare.removed?.length ?? 0} tone="ok" />
                  <CompareChip label="retained" count={compare.retained?.length ?? 0} tone="active" />
                  <CompareChip label="reintroduced" count={compare.reintroduced?.length ?? 0} tone="warn" />
                  {(compare.added || [])
                    .slice(0, 6)
                    .map((item: any) => (
                      <span key={item.title} className="mono-cell text-[10px] text-faint border border-line rounded px-2 py-0.5">
                        + {item.title}
                      </span>
                    ))}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const KV: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div>
    <p className="eyebrow mb-0.5">{label}</p>
    <p className={`text-[11px] text-muted break-words ${mono ? 'font-mono' : ''}`}>{value}</p>
  </div>
);

const ReadinessBadge: React.FC<{ status: string }> = ({ status }) => {
  const s = (status || '').toLowerCase();
  if (s === 'installed') return <OkBadge label="installed" />;
  if (s === 'disabled') return <DisBadge label="disabled" />;
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-medium shrink-0">
      <Ban className="w-3 h-3" aria-hidden="true" />
      missing
    </span>
  );
};

const ExecutionBadge: React.FC<{ status: string }> = ({ status }) => {
  const s = (status || '').toLowerCase();
  if (s === 'completed' || s === 'success') return <OkBadge label="completed" />;
  if (s === 'skipped') return <DisBadge label="skipped" />;
  if (s === 'not_installed') {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[10px] text-medium shrink-0">
        <Ban className="w-3 h-3" aria-hidden="true" />
        not_installed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-critical shrink-0">
      <AlertCircle className="w-3 h-3" aria-hidden="true" />
      {s}
    </span>
  );
};

const OkBadge: React.FC<{ label: string }> = ({ label }) => (
  <span className="inline-flex items-center gap-1 font-mono text-[10px] text-accent shrink-0">
    <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
    {label}
  </span>
);

const DisBadge: React.FC<{ label: string }> = ({ label }) => (
  <span className="inline-flex items-center gap-1 font-mono text-[10px] text-faint shrink-0">
    <Activity className="w-3 h-3" aria-hidden="true" />
    {label}
  </span>
);

const CompareChip: React.FC<{ label: string; count: number; tone: 'danger' | 'ok' | 'warn' | 'active' }> = ({
  label,
  count,
  tone,
}) => {
  const tones: Record<string, string> = {
    danger: 'text-critical border-critical/40',
    ok: 'text-accent border-accent/40',
    warn: 'text-medium border-warn/40',
    active: 'text-accent border-accent/40',
  };
  return (
    <span className={`mono-cell text-[10px] border rounded px-2 py-0.5 ${tones[tone]}`}>
      {label}: {count}
    </span>
  );
};