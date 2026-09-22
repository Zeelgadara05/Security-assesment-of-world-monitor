import React from 'react';
import { LandingNav, LandingFooter } from '../components/LandingChrome';

export const LandingLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="min-h-dvh bg-bg text-text">
    <LandingNav />
    <main id="landing-main" className="pt-[92px]">
      {children}
    </main>
    <LandingFooter />
  </div>
);

export default LandingLayout;
