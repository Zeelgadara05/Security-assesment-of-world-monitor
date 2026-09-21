import React from 'react';
import { ShieldAlert, ShieldX, AlertTriangle, Info } from 'lucide-react';

const severityStyles: Record<string, { text: string; chip: string; icon: React.ReactNode }> = {
  Critical: {
    text: 'text-critical',
    chip: 'border-critical/35 text-critical bg-critical/[0.09]',
    icon: <ShieldX className="w-3 h-3" strokeWidth={1.5} aria-hidden="true" />,
  },
  High: {
    text: 'text-high',
    chip: 'border-high/35 text-high bg-high/[0.09]',
    icon: <ShieldAlert className="w-3 h-3" strokeWidth={1.5} aria-hidden="true" />,
  },
  Medium: {
    text: 'text-medium',
    chip: 'border-medium/35 text-medium bg-medium/[0.09]',
    icon: <AlertTriangle className="w-3 h-3" strokeWidth={1.5} aria-hidden="true" />,
  },
  Low: {
    text: 'text-low',
    chip: 'border-low/35 text-low bg-low/[0.09]',
    icon: <Info className="w-3 h-3" strokeWidth={1.5} aria-hidden="true" />,
  },
  Info: {
    text: 'text-neutral',
    chip: 'border-line-strong text-neutral bg-white/[0.03]',
    icon: <Info className="w-3 h-3" strokeWidth={1.5} aria-hidden="true" />,
  },
};

export const SeverityBadge: React.FC<{ severity: string; withIcon?: boolean }> = ({
  severity,
  withIcon = true,
}) => {
  const style = severityStyles[severity] ?? severityStyles.Info;
  return (
    <span
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-2 py-1 text-[10.5px] font-semibold tracking-wide ${style.chip}`}
    >
      {withIcon && style.icon}
      {severity}
    </span>
  );
};

export const SeverityText: React.FC<{ severity: string }> = ({ severity }) => {
  const style = severityStyles[severity] ?? severityStyles.Info;
  return <span className={`font-mono text-[11px] font-medium ${style.text}`}>{severity}</span>;
};
