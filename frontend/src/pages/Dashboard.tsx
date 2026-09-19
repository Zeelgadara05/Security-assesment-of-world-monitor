import React, { useState, useEffect, useCallback } from 'react';
import { Radar, AlertTriangle, Target } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityText } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { Skeleton, SkeletonTable } from '../components/Skeleton';
import { DataTable } from '../components/DataTable';
import { relativeTime } from '../components/format';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [scanRes, summaryRes] = await Promise.all([
        apiFetch('/scans/list'),
        apiFetch('/scans/summary'),
      ]);
      if (scanRes.ok) {
        setScans(await scanRes.json());
        setError('');
      } else if (!summaryRes.ok) {
        const errData = await summaryRes.json().catch(() => null);
        setError(errData?.detail || 'Failed to load assessment data.');
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const latestScans = (raw: any[], count = 6) =>
    [...raw].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, count);

  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Overview"
        title="Assessment overview"
        description="Live status of scan operations, latest assessments, and open findings."
        actions={
          <Link to="/scan/new" className="no-underline">
            <span className="inline-flex items-center gap-1.5 bg-accent text-[#062b20] border border-accent rounded px-3 py-1.5 text-[11.5px] font-medium hover:bg-accent/85 transition-colors">
              <Radar className="w-3.5 h-3.5" />
              New Assessment
            </span>
          </Link>
        }
      />

      {/* Stat tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <StatTile
          label="Assessments Run"
          icon={<Target className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
          loading={loading}
          iconTone="text-accent"
        >
          {scans.length}
          <span className="text-[10px] text-faint">total</span>
        </StatTile>
        <StatTile
          label="Open Findings"
          icon={<AlertTriangle className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
          loading={loading}
          iconTone="text-critical"
        >
          {summary?.open_findings ?? 0}
        </StatTile>
        <StatTile
          label="Avg Security Score"
          icon={<Target className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
          loading={loading}
          iconTone="text-accent"
        >
          {avgScore(summary?.score_history)}
          <span className="text-[10px] text-faint">/100</span>
        </StatTile>
        <StatTile
          label="Open Ports"
          icon={<Target className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
          loading={loading}
          iconTone="text-low"
        >
          {summary?.open_ports_total ?? 0}
        </StatTile>
      </div>

      {/* Summary + severity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="panel rounded-md p-4 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Security Score Trend</h2>
            <span className="eyebrow">Last assessments</span>
          </div>
          {loading ? (
            <Skeleton className="h-32 w-full" />
          ) : (summary?.score_history ?? []).length === 0 ? (
            <EmptyState
              title="No score history yet"
              description="Run your first assessment to plot the security score trend."
              action={
                <Link to="/scan/new">
                  <span className="inline-flex items-center gap-1.5 border border-line rounded px-2.5 py-1.5 text-[11px] text-muted hover:text-text hover:bg-surface-2 transition-colors">
                    Start assessment
                  </span>
                </Link>
              }
            />
          ) : (
            <ScoreBars history={summary.score_history} />
          )}
        </div>

        <div className="panel rounded-md p-4">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted mb-3">Severity Distribution</h2>
          {loading ? (
            <Skeleton className="h-32 w-full" />
          ) : (
            <SeverityBreakdown dist={summary?.severity_distribution ?? {}} />
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="panel rounded-md overflow-hidden">
        <div className="flex items-center justify-between px-4 pt-4 pb-2">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Recent Assessments</h2>
          <Link to="/scans" className="text-[11px] text-accent hover:text-accent/80 no-underline font-medium">
            View all
          </Link>
        </div>
        {error ? (
          <div className="px-4 pb-4">
            <ErrorState message={error} onRetry={fetchData} />
          </div>
        ) : loading ? (
          <div className="px-4 pb-4"><SkeletonTable rows={4} /></div>
        ) : scans.length === 0 ? (
          <div className="px-4 pb-4">
            <EmptyState
              title="No assessments yet"
              description="Queue your first scan pipeline to start collecting evidence-backed findings."
              action={
                <Link to="/scan/new">
                  <span className="inline-flex items-center gap-1.5 border border-line rounded px-2.5 py-1.5 text-[11px] text-muted hover:text-text hover:bg-surface-2 transition-colors">
                    Queue scan
                  </span>
                </Link>
              }
            />
          </div>
        ) : (
          <DataTable
            columns={[
              { key: 'target', label: 'Target', render: (s: any) => <span className="font-medium text-text">{s.target}</span> },
              {
                key: 'status',
                label: 'Status',
                render: (s: any) => <StatusBadge status={s.status} />,
              },
              {
                key: 'score',
                label: 'Score',
                render: (s: any) => (
                  <span className="mono-cell text-muted">{s.security_score !== null ? `${s.security_score}/100` : '—'}</span>
                ),
              },
              {
                key: 'coverage',
                label: 'Coverage',
                render: (s: any) => (
                  <span className="mono-cell text-muted">{s.coverage !== null ? `${s.coverage}%` : '—'}</span>
                ),
              },
              {
                key: 'created',
                label: 'Triggered',
                render: (s: any) => <span className="text-[11px] text-faint">{relativeTime(s.created_at)}</span>,
              },
            ]}
            rows={latestScans(scans)}
            keyField={(s: any) => String(s.id)}
            loading={loading}
            onRowClick={() => navigate('/scans')}
          />
        )}
      </div>
    </div>
  );
};

const StatTile: React.FC<{
  label: string;
  icon: React.ReactNode;
  loading?: boolean;
  iconTone?: string;
  children: React.ReactNode;
}> = ({ label, icon, loading, iconTone = 'text-accent', children }) => (
  <div className="panel rounded-md p-4 flex items-center gap-3">
    <span className={`w-9 h-9 rounded-md border border-line bg-surface-2 flex items-center justify-center ${iconTone}`}>
      {icon}
    </span>
    <div className="min-w-0">
      <p className="eyebrow mb-0.5">{label}</p>
      <div className="flex items-baseline gap-1">
        {loading ? (
          <Skeleton className="h-6 w-12" />
        ) : (
          <span className="text-xl font-semibold text-text leading-none">{children}</span>
        )}
      </div>
    </div>
  </div>
);

function avgScore(history: any[] | undefined): string {
  if (!history || history.length === 0) return '—';
  const total = history.reduce((acc, h) => acc + (Number(h.score) || 0), 0);
  return String(Math.round(total / history.length));
}

const ScoreBars: React.FC<{ history: any[] }> = ({ history }) => (
  <div className="flex items-end gap-1.5 h-32">
    {history.map((h, i) => {
      const score = h.score ?? 0;
      const height = Math.max(4, score); // pct of container
      return (
        <div key={i} className="flex flex-col items-center gap-1 flex-1 min-w-0">
          <span className="mono-cell text-[9px] text-faint">{score}</span>
          <div className="w-full rounded-sm bg-surface-2" style={{ height: '6rem' }}>
            <div
              className="w-full rounded-sm bg-accent/70"
              style={{ height: `${height}%`, transition: 'height 0.6s ease' }}
            />
          </div>
          <span className="mono-cell text-[8px] text-faint truncate w-full text-center">{h.target?.split('.').slice(0, 1)[0] ?? ''}</span>
        </div>
      );
    })}
  </div>
);

const SeverityBreakdown: React.FC<{ dist: Record<string, number> }> = ({ dist }) => {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...Object.values(dist));
  if (total === 0) {
    return (
      <EmptyState
        title="No open findings"
        description="Findings appear here once evidence-backed records are persisted for a scan."
      />
    );
  }
  return (
    <div className="space-y-2.5">
      {order.map((sev) => {
        const count = dist[sev] ?? 0;
        if (count === 0) return null;
        return (
          <div key={sev} className="flex items-center gap-2">
            <span className="w-14 shrink-0"><SeverityText severity={sev} /></span>
            <div className="flex-1 h-1.5 rounded-full bg-surface-2 overflow-hidden">
              <div
                className={`h-full rounded-full ${sevColorClass(sev)}`}
                style={{ width: `${(count / max) * 100}%` }}
              />
            </div>
            <span className="mono-cell text-faint w-6 text-right">{count}</span>
          </div>
        );
      })}
    </div>
  );
};

function sevColorClass(sev: string): string {
  switch (sev) {
    case 'Critical': return 'bg-critical';
    case 'High': return 'bg-high';
    case 'Medium': return 'bg-medium';
    case 'Low': return 'bg-low';
    default: return 'bg-faint';
  }
}