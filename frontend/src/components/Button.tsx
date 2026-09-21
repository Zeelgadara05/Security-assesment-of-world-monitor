import React from 'react';

type Variant = 'primary' | 'outline' | 'ghost' | 'danger';
type Size = 'sm' | 'md';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  /** Optional trailing icon rendered inside a nested circular well. */
  trailing?: React.ReactNode;
}

const base =
  'group relative inline-flex items-center justify-center font-medium select-none cursor-pointer rounded-full border ' +
  'transition-[background-color,border-color,color,box-shadow,transform] duration-500 ease-spring ' +
  'active:scale-[0.98] focus-visible:outline-none disabled:opacity-45 disabled:cursor-not-allowed disabled:active:scale-100';

const variants: Record<Variant, string> = {
  primary:
    'bg-accent text-[#04140e] border-accent/60 shadow-[0_12px_32px_-16px_rgba(24,185,138,0.8)] hover:bg-accent-bright hover:shadow-[0_18px_44px_-16px_rgba(24,185,138,0.95)]',
  outline:
    'bg-white/[0.015] text-muted border-line hover:text-text hover:border-line-strong hover:bg-white/[0.05]',
  ghost: 'bg-transparent text-muted border-transparent hover:text-text hover:bg-white/[0.055]',
  danger: 'bg-transparent text-critical border-critical/35 hover:bg-critical/10 hover:border-critical/60',
};

const sizes: Record<Size, string> = {
  sm: 'text-[11.5px] px-3.5 py-1.5 gap-1.5',
  md: 'text-[12.5px] px-5 py-2.5 gap-2',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'outline',
  size = 'md',
  className = '',
  type = 'button',
  trailing,
  children,
  ...rest
}) => (
  <button type={type} className={`${base} ${variants[variant]} ${sizes[size]} ${className}`} {...rest}>
    {children}
    {trailing && (
      <span className="-mr-2 ml-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-black/15 transition-transform duration-500 ease-spring group-hover:translate-x-0.5 group-hover:-translate-y-px">
        {trailing}
      </span>
    )}
  </button>
);

export const IconButton: React.FC<ButtonProps> = ({
  variant = 'ghost',
  size = 'md',
  className = '',
  children,
  ...rest
}) => (
  <button
    type="button"
    className={`inline-flex items-center justify-center rounded-full border cursor-pointer transition-[background-color,border-color,color,transform] duration-500 ease-spring active:scale-95 focus-visible:outline-none disabled:opacity-45 disabled:cursor-not-allowed ${variants[variant]} ${
      size === 'sm' ? 'p-1.5' : 'p-2'
    } ${className}`}
    {...rest}
  >
    {children}
  </button>
);
