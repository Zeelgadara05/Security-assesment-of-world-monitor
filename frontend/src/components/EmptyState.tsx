import React from 'react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => (
  <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-line-strong/70 px-6 py-14 text-center">
    {icon && (
      <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl border border-line bg-surface-2 text-faint shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
        {icon}
      </div>
    )}
    <h3 className="display text-[15px] font-semibold text-text">{title}</h3>
    {description && (
      <p className="mt-2 max-w-[46ch] text-[12.5px] leading-relaxed text-muted">{description}</p>
    )}
    {action && <div className="mt-6">{action}</div>}
  </div>
);
