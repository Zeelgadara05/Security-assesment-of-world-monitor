import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Compass } from 'lucide-react';

export const NotFound: React.FC = () => (
  <div className="flex min-h-[70dvh] flex-col items-center justify-center px-4 text-center">
    <span className="chip mb-6">Error 404</span>
    <p className="display font-mono text-[76px] font-semibold leading-none text-text sm:text-[112px]">
      4<span className="text-accent">0</span>4
    </p>
    <h1 className="display mt-2 text-[20px] font-semibold text-text">This route isn't in scope</h1>
    <p className="mt-2.5 max-w-[52ch] text-[13px] leading-relaxed text-muted">
      The page you're looking for doesn't exist or was moved. Head back to the overview to keep working.
    </p>
    <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
      <Link
        to="/"
        className="group inline-flex items-center gap-2 rounded-full border border-accent/60 bg-accent px-5 py-2.5 text-[12.5px] font-medium text-[#04140e] shadow-[0_12px_32px_-16px_rgba(24,185,138,0.8)] transition-[background-color,box-shadow,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
      >
        <ArrowLeft className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
        Back to overview
      </Link>
      <Link
        to="/scan/new"
        className="group inline-flex items-center gap-2 rounded-full border border-line bg-white/[0.015] px-5 py-2.5 text-[12.5px] text-muted transition-[background-color,border-color,color] duration-500 ease-spring hover:border-line-strong hover:text-text"
      >
        <Compass className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
        Queue a new assessment
      </Link>
    </div>
  </div>
);
