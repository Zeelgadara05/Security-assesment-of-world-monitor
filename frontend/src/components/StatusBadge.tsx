import React from 'react';

export type StatusTone = 'active' | 'ok' | 'warn' | 'danger' | 'neutral';

const toneClasses: Record<StatusTone, string> = {
  active: 'dot dot-active',
  ok: 'dot dot-ok',
  warn: 'dot dot-warn',
  danger: 'dot dot-danger',
  neutral: 'dot dot-neutral',
};

const textClasses: Record<StatusTone, string> = {
  active: 'text-accent',
  ok: 'text-accent',
  warn: 'text-medium',
  danger: 'text-critical',
  neutral: 'text-faint',
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
    <span className={`inline-flex items-center gap-1.5 font-mono text-[11px] ${textClasses[tone]} min-w-fit`}>
      <span className={toneClasses[tone]} aria-hidden="true" />
      {label ?? statusLabel(status)}
    </span>
  );
};