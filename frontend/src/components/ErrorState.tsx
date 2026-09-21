import React from 'react';
import { RotateCcw, AlertCircle } from 'lucide-react';
import { Button } from './Button';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ title = 'Could not load data', message, onRetry }) => (
  <div className="flex flex-col items-center justify-center rounded-2xl border border-critical/25 bg-critical/[0.05] px-6 py-12 text-center">
    <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl border border-critical/30 bg-surface-2 text-critical shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
      <AlertCircle className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
    </div>
    <h3 className="display text-[15px] font-semibold text-text">{title}</h3>
    <p className="mt-2 max-w-[46ch] break-words text-[12.5px] leading-relaxed text-muted">{message}</p>
    {onRetry && (
      <Button variant="outline" size="sm" onClick={onRetry} className="mt-6" trailing={<RotateCcw className="h-3 w-3" strokeWidth={1.5} />}>
        Retry
      </Button>
    )}
  </div>
);
