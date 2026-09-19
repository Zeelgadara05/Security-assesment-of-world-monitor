import React from 'react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => (
  <div className="flex flex-col items-center justify-center text-center px-6 py-14 border border-dashed border-line-strong rounded-md">
    {icon && (
      <div className="w-10 h-10 rounded-md border border-line bg-surface-2 flex items-center justify-center text-faint mb-4">
        {icon}
      </div>
    )}
    <h3 className="text-sm font-semibold text-text">{title}</h3>
    {description && <p className="text-[12px] text-muted mt-1.5 max-w-sm leading-relaxed">{description}</p>}
    {action && <div className="mt-5">{action}</div>}
  </div>
);