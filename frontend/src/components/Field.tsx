import React from 'react';

interface FieldProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
}

export const Input: React.FC<FieldProps> = ({ label, hint, className = '', ...rest }) => (
  <div className="space-y-1.5">
    <label className="block text-[11.5px] font-medium text-muted">{label}</label>
    <input
      className={`w-full bg-bg border border-line rounded px-3 py-2 text-[12.5px] text-text placeholder:text-faint/70 focus:outline-none focus:border-accent/60 focus:ring-1 focus:ring-accent/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      {...rest}
    />
    {hint && <p className="text-[10.5px] text-faint">{hint}</p>}
  </div>
);

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  children: React.ReactNode;
}

export const Select: React.FC<SelectProps> = ({ label, children, className = '', ...rest }) => (
  <div className="space-y-1.5">
    <label className="block text-[11.5px] font-medium text-muted">{label}</label>
    <select
      className={`w-full bg-bg border border-line rounded px-2.5 py-2 text-[12.5px] text-text focus:outline-none focus:border-accent/60 focus:ring-1 focus:ring-accent/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      {...rest}
    >
      {children}
    </select>
  </div>
);