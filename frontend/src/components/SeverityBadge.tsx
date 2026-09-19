import React from 'react';
import { ShieldAlert, ShieldX, AlertTriangle, Info } from 'lucide-react';

const severityStyles: Record<string, { text: string; chip: string; icon: React.ReactNode }> = {
  Critical: {
    text: 'text-critical',
    chip: 'border-critical/40 text-critical bg-critical/10',
    icon: <ShieldX className="w-3 h-3" aria-hidden="true" />,
  },
  High: {
    text: 'text-high',
    chip: 'border-high/40 text-high bg-high/10',
    icon: <ShieldAlert className="w-3 h-3" aria-hidden="true" />,
  },
  Medium: {
    text: 'text-medium',
    chip: 'border-medium/40 text-medium bg-medium/10',
    icon: <AlertTriangle className="w-3 h-3" aria-hidden="true" />,
  },
  Low: {
    text: 'text-low',
    chip: 'border-low/40 text-low bg-low/10',
    icon: <Info className="w-3 h-3" aria-hidden="true" />,
  },
  Info: {
    text: 'text-neutral',
    chip: 'border-line-strong text-neutral bg-surface-2',
    icon: <Info className="w-3 h-3" aria-hidden="true" />,
  },
};

export const SeverityBadge: React.FC<{ severity: string; withIcon?: boolean }> = ({
  severity,
  withIcon = true,
}) => {
  const style = severityStyles[severity] ?? severityStyles.Info;
  return (
    <span className={`inline-flex items-center gap-1 border justify-center px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${style.chip}`}>
      {withIcon && style.icon}
      {severity}
    </span>
  );
};

export const SeverityText: React.FC<{ severity: string }> = ({ severity }) => {
  const style = severityStyles[severity] ?? severityStyles.Info;
  return <span className={`font-mono text-[11px] font-medium ${style.text}`}>{severity}</span>;
};