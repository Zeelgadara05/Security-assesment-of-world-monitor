import React from 'react';

type Variant = 'primary' | 'outline' | 'ghost' | 'danger';
type Size = 'sm' | 'md';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const base =
  'inline-flex items-center justify-center gap-1.5 font-medium select-none cursor-pointer transition-colors disabled:opacity-45 disabled:cursor-not-allowed active:translate-y-px';

const variants: Record<Variant, string> = {
  primary: 'bg-accent text-[#062b20] hover:bg-accent/85 border border-accent',
  outline: 'bg-transparent text-muted hover:text-text hover:bg-surface-2 border border-line hover:border-line-strong',
  ghost: 'bg-transparent text-muted hover:text-text hover:bg-surface-2 border border-transparent',
  danger: 'bg-transparent text-critical hover:bg-critical/10 border border-critical/40',
};

const sizes: Record<Size, string> = {
  sm: 'text-[11.5px] px-2.5 py-1.5 rounded gap-1',
  md: 'text-xs px-3.5 py-2 rounded-md gap-1.5',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'outline',
  size = 'md',
  className = '',
  type = 'button',
  ...rest
}) => (
  <button type={type} className={`${base} ${variants[variant]} ${sizes[size]} ${className}`} {...rest} />
);

export const IconButton: React.FC<ButtonProps> = ({ variant = 'ghost', size = 'md', className = '', ...rest }) => (
  <button
    type="button"
    className={`inline-flex items-center justify-center cursor-pointer transition-colors disabled:opacity-45 disabled:cursor-not-allowed ${variants[variant]} ${size === 'sm' ? 'p-1.5 rounded' : 'p-2 rounded-md'} ${className}`}
    {...rest}
  />
);