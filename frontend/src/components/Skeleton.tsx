import React from 'react';

export const Skeleton: React.FC<{ className?: string }> = ({ className = 'h-4 w-full' }) => (
  <div className={`skeleton ${className}`} aria-hidden="true" />
);

export const SkeletonText: React.FC<{ lines?: number; className?: string }> = ({ lines = 3, className }) => (
  <div className="space-y-2.5">
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} className={`${i === lines - 1 ? 'w-2/3' : 'w-full'} ${className ?? 'h-3'}`} />
    ))}
  </div>
);

export const SkeletonTable: React.FC<{ rows?: number; cols?: number }> = ({ rows = 5, cols = 4 }) => (
  <div className="overflow-hidden rounded-2xl border border-line">
    <div
      className="grid gap-4 border-b border-line bg-white/[0.015] px-4 py-3.5"
      style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}
    >
      {Array.from({ length: cols }).map((_, i) => (
        <Skeleton key={i} className="h-3" />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, r) => (
      <div
        key={r}
        className="grid gap-4 border-b border-line/60 px-4 py-3.5 last:border-b-0"
        style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}
      >
        {Array.from({ length: cols }).map((_, c) => (
          <Skeleton key={c} className="h-3" />
        ))}
      </div>
    ))}
  </div>
);

export const SkeletonPanel: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`rounded-2xl border border-line p-5 ${className}`}>
    <Skeleton className="mb-5 h-4 w-40" />
    <div className="space-y-3">
      <Skeleton className="h-3 w-full" />
      <Skeleton className="h-3 w-5/6" />
      <Skeleton className="h-3 w-4/6" />
    </div>
  </div>
);
