import React from 'react';
import { RotateCcw, Loader2 } from 'lucide-react';
import { Button } from './Button';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ title = 'Could not load data', message, onRetry }) => (
  <div className="flex flex-col items-center justify-center text-center px-6 py-12 border border-critical/30 rounded-md bg-critical/5">
    <div className="w-10 h-10 rounded-md border border-critical/30 bg-surface-2 flex items-center justify-center text-critical mb-4">
      <AlertIcon />
    </div>
    <h3 className="text-sm font-semibold text-text">{title}</h3>
    <p className="text-[12px] text-muted mt-1.5 max-w-sm leading-relaxed break-words">{message}</p>
    {onRetry && (
      <Button variant="outline" size="sm" onClick={onRetry} className="mt-5">
        <RotateCcw className="w-3 h-3" />
        Retry
      </Button>
    )}
  </div>
);

function AlertIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

export const LoaderBlock: React.FC<{ label?: string }> = ({ label = 'Loading…' }) => (
  <div className="flex flex-col items-center justify-center py-12 text-faint gap-2">
    <Loader2 className="w-4 h-4 animate-spin" />
    <span className="text-[11px]">{label}</span>
  </div>
);