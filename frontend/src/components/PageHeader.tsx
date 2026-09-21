import React from 'react';

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
  meta?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ eyebrow, title, description, actions, meta }) => (
  <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
    <div className="min-w-0">
      {eyebrow && <span className="chip mb-3">{eyebrow}</span>}
      <h1 className="display text-[26px] font-semibold text-text sm:text-[30px]">{title}</h1>
      {description && (
        <p className="mt-2.5 max-w-[64ch] text-[13px] leading-relaxed text-muted">{description}</p>
      )}
      {meta && <div className="mt-3">{meta}</div>}
    </div>
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
