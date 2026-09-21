import React from 'react';

export type StatusTone = 'active' | 'ok' | 'warn' | 'danger' | 'neutral';

const dotClasses: Record<StatusTone, string> = {
  active: 'dot dot-active',
  ok: 'dot dot-ok',
  warn: 'dot dot-warn',
  danger: 'dot dot-danger',
  neutral: 'dot dot-neutral',
};

const chipClasses: Record<StatusTone, string> = {
  active: 'border-accent/30 text-accent bg-accent/[0.07]',
  ok: 'border-accent/30 text-accent bg-accent/[0.07]',
  warn: 'border-medium/30 text-medium bg-medium/[0.07]',
  danger: 'border-critical/30 text-critical bg-critical/[0.07]',
  neutral: 'border-line text-faint bg-white/[0.02]',
};

export function statusTone(status: string): StatusTone {
  const s = (status || '').toLowerCase();
  if (['completed', 'partial'].some((x) => s.startsWith(x)) && s.includes('fail')) return 'warn';
  if (s === 'completed') return 'ok';
  if (s === 'partial') return 'warn';
  if (s === 'failed') return 'danger';
  if (s === 'cancelled') return 'neutral';
  if (['running', 'queued', 'pending', 'cancelling', 'initializing', 'tools_loading', 'stage_'].some((x) => s.startsWith(x)))
    return 'active';
  return 'neutral';
}

export function statusLabel(status: string): string {
  const s = (status || '')
    .replaceAll('_', ' ')
    .replace(/^stage\s+/, '')
    .toLowerCase();
  return s.length ? s.charAt(0).toUpperCase() + s.slice(1) : '—';
}

interface StatusBadgeProps {
  status: string;
  label?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, label }) => {
  const tone = statusTone(status);
  return (
    <span
      className={`inline-flex min-w-fit items-center gap-2 rounded-full border px-2.5 py-1 font-mono text-[10.5px] tracking-wide ${chipClasses[tone]}`}
    >
      <span className={dotClasses[tone]} aria-hidden="true" />
      {label ?? statusLabel(status)}
    </span>
  );
};
