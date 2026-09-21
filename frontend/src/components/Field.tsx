import React from 'react';

const fieldShell =
  'w-full rounded-xl border border-line bg-bg/60 px-3.5 py-2.5 text-[12.5px] text-text placeholder:text-faint/70 ' +
  'shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] transition-[border-color,box-shadow] duration-500 ease-spring ' +
  'focus:outline-none focus:border-accent/60 focus:ring-4 focus:ring-accent/10 disabled:opacity-50 disabled:cursor-not-allowed';

interface FieldProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
}

export const Input: React.FC<FieldProps> = ({ label, hint, className = '', ...rest }) => (
  <div className="space-y-2">
    {label && <label className="block text-[11px] font-medium tracking-wide text-muted">{label}</label>}
    <input className={`${fieldShell} ${className}`} {...rest} />
    {hint && <p className="text-[10.5px] text-faint">{hint}</p>}
  </div>
);

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  children: React.ReactNode;
}

export const Select: React.FC<SelectProps> = ({ label, children, className = '', ...rest }) => (
  <div className="space-y-2">
    {label && <label className="block text-[11px] font-medium tracking-wide text-muted">{label}</label>}
    <select className={`${fieldShell} cursor-pointer ${className}`} {...rest}>
      {children}
    </select>
  </div>
);

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
}

export const Textarea: React.FC<TextareaProps> = ({ label, hint, className = '', ...rest }) => (
  <div className="space-y-2">
    {label && <label className="block text-[11px] font-medium tracking-wide text-muted">{label}</label>}
    <textarea className={`${fieldShell} resize-y leading-relaxed ${className}`} {...rest} />
    {hint && <p className="text-[10.5px] text-faint">{hint}</p>}
  </div>
);
