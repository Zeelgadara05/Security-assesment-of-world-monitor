import React from 'react';
import { RotateCcw, AlertCircle } from 'lucide-react';
import { Button } from './Button';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ title = 'Could not load data', message, onRetry }) => (
  <div className="flex flex-col items-center justify-center text-center px-6 py-12 border border-critical/30 rounded-md bg-critical/5">
    <div className="w-10 h-10 rounded-md border border-critical/30 bg-surface-2 flex items-center justify-center text-critical mb-4">
      <AlertCircle className="w-4 h-4" aria-hidden="true" />
    </div>
    <h3 className="text-sm font-semibold text-text">{title}</h3>
    <p className="text-[12px] text-muted mt-1.5 max-w-sm leading-relaxed break-words">{message}</p>
    {onRetry && (
      <Button variant="outline" size="sm" onClick={onRetry} className="mt-5">
        <RotateCcw className="w-3 h-3" aria-hidden="true" />
        Retry
      </Button>
    )}
  </div>
);