import React, { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  LayoutDashboard,
  Radar,
  ShieldCheck,
  Server,
  FileText,
  MessageSquareText,
  Cpu,
  BookOpen,
  Settings,
  LogOut,
  Menu,
  X,
  Crosshair,
} from 'lucide-react';
import { apiFetch } from '../api';

interface ShellProps {
  children: React.ReactNode;
  onLogout: () => void;
}

interface UserInfo {
  email?: string;
  role?: string;
}

interface ScopeInfo {
  count: number;
  sample: string[];
}

const NAV_GROUPS = [
  {
    label: 'Operations',
    items: [
      { name: 'Overview', path: '/', icon: LayoutDashboard },
      { name: 'New Assessment', path: '/scan/new', icon: Radar },
      { name: 'Assessments', path: '/scans', icon: ShieldCheck },
      { name: 'Assets', path: '/assets', icon: Server },
      { name: 'Reports', path: '/reports', icon: FileText },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { name: 'Assessment Assistant', path: '/chat', icon: MessageSquareText },
      { name: 'Tool Health', path: '/tools', icon: Cpu },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { name: 'Knowledge Base', path: '/knowledge', icon: BookOpen },
      { name: 'Settings', path: '/settings', icon: Settings },
    ],
  },
];

export const DashboardLayout: React.FC<ShellProps> = ({ children, onLogout }) => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [scope, setScope] = useState<ScopeInfo | null>(null);
  const [env, setEnv] = useState<{ simulation_mode: boolean } | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    apiFetch('/auth/me')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setUser({ email: data.email, role: data.role || 'user' }))
      .catch(() => {});
  }, []);

  useEffect(() => {
    apiFetch('/scans/scope')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        const list: string[] = Array.isArray(data?.scope) ? data.scope : [];
        setScope({ count: list.length, sample: list.slice(-3) });
      })
      .catch(() => {});
  }, []);

  const fetchEnv = () => {
    apiFetch('/tools/inventory')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setEnv({ simulation_mode: !!data.simulation_mode }))
      .catch(() => {});
  };

  useEffect(() => {
    fetchEnv();
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const initials = (user?.email || '?').split('@')[0].slice(0, 2).toUpperCase();

  const sidebar = (
    <nav aria-label="Primary" className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
      <ul className="space-y-5">
        {NAV_GROUPS.map((group) => (
          <li key={group.label}>
            <p className="eyebrow px-2 pb-2">{group.label}</p>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.path}>
                    <NavLink
                      to={item.path}
                      end={item.path === '/'}
                      className={({ isActive }) =>
                        `group flex items-center gap-2.5 rounded px-2.5 py-[7px] text-[12.5px] border-l-2 transition-colors ${
                          isActive
                            ? 'bg-surface-2 border-accent text-text font-medium'
                            : 'border-transparent text-muted hover:bg-surface-2/60 hover:text-text'
                        }`
                      }
                    >
                      <Icon className="w-4 h-4 shrink-0 text-faint group-hover:text-text" strokeWidth={1.75} aria-hidden="true" />
                      <span className="flex-1 min-w-0 truncate">{item.name}</span>
                      {item.path === '/scan/new' && (
                        <span className="hidden lg:inline-flex items-center gap-1 font-mono text-[9px] text-accent uppercase tracking-wider">
                          scan
                        </span>
                      )}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
      </ul>

      {/* Scope context */}
      <div className="border border-line rounded-md bg-surface px-3 py-3">
        <div className="flex items-center gap-1.5 mb-2">
          <Crosshair className="w-3.5 h-3.5 text-accent" strokeWidth={1.75} aria-hidden="true" />
          <span className="eyebrow">Authorized Scope</span>
        </div>
        {scope && scope.count > 0 ? (
          <>
            <p className="text-[11px] text-muted mb-1">
              {scope.count} declared target{scope.count === 1 ? '' : 's'}
            </p>
            <div className="space-y-0.5">
              {scope.sample.slice(-3).map((entry) => (
                <p key={entry} className="mono-cell text-[10px] text-faint truncate">{entry}</p>
              ))}
              {scope.count > scope.sample.length && (
                <p className="mono-cell text-[10px] text-faint">+{scope.count - scope.sample.length} more</p>
              )}
            </div>
          </>
        ) : (
          <p className="text-[11px] text-faint leading-relaxed">
            No scope declared. Out-of-scope targets are rejected with 403.
          </p>
        )}
      </div>
    </nav>
  );

  const pageTransition = reduceMotion ? <div>{children}</div> : (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -4 }}
        transition={{ duration: 0.22, ease: 'easeOut' }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );

  return (
    <div className="flex h-[100dvh] w-screen flex-col overflow-hidden bg-bg text-text font-sans">
      {/* Top operational bar */}
      <header className="flex items-center gap-3 border-b border-line bg-surface px-4 shrink-0" style={{ height: 52 }}>
        <button
          onClick={() => setMobileOpen((v) => !v)}
          className="lg:hidden p-2 -ml-1 text-muted hover:text-text cursor-pointer"
          aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>

        {/* Brand */}
        <NavLink to="/" className="flex items-center gap-2.5 min-w-0 hover:opacity-90 transition-opacity">
          <span className="w-7 h-7 rounded overflow-hidden border border-line flex items-center justify-center shrink-0">
            <img src="/logo.png" alt="" className="w-full h-full object-cover" />
          </span>
          <span className="hidden sm:flex flex-col leading-none">
            <span className="text-[15px] font-semibold tracking-tight">CyberAgent</span>
            <span className="text-[9px] text-faint font-mono uppercase tracking-[0.18em] mt-0.5">Scan Platform</span>
          </span>
        </NavLink>

        <div className="flex-1" />

        {/* Execution mode chip */}
        <div className="hidden md:flex items-center gap-1.5 border border-line rounded px-2 py-1" title="Backend execution mode">
          <span className={env ? 'dot dot-ok' : 'dot dot-neutral'} />
          <span className="mono-cell text-[10px] text-muted uppercase tracking-wider">
            {env === null ? '…' : env.simulation_mode ? 'Simulation' : 'Live'}
          </span>
        </div>

        {/* User session */}
        <div className="flex items-center gap-2 pl-1">
          <div className="w-8 h-8 rounded-full bg-surface-2 border border-line flex items-center justify-center text-[11px] font-semibold text-accent" aria-hidden="true">
            {initials}
          </div>
          <div className="hidden sm:flex-col leading-tight min-w-0 max-w-[180px]">
            <p className="text-[11px] font-medium truncate">{user?.email?.split('@')[0] || '…'}</p>
            <p className="mono-cell text-[9px] text-faint uppercase tracking-wider">{user?.role || '…'}</p>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="p-2 text-faint hover:text-critical hover:bg-critical/10 rounded cursor-pointer transition-colors"
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="w-4 h-4" strokeWidth={1.75} />
        </button>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Desktop sidebar */}
        <aside className="hidden lg:flex w-[220px] shrink-0 flex-col border-r border-line bg-surface overflow-y-auto" aria-label="Sidebar">
          {sidebar}
        </aside>

        {/* Mobile drawer */}
        {mobileOpen && (
          <div className="lg:hidden fixed inset-0 z-40 flex">
            <div className="flex-1 bg-black/60" onClick={() => setMobileOpen(false)} aria-hidden="true" />
            <aside className="w-[260px] bg-surface border-l border-line flex flex-col overflow-y-auto" aria-label="Sidebar">
              <div className="flex items-center justify-between px-4 border-b border-line" style={{ height: 52 }}>
                <span className="text-[13px] font-semibold">Navigation</span>
              </div>
              {sidebar}
            </aside>
          </div>
        )}

        {/* Main viewport */}
        <main className="flex-1 min-w-0 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1400px] px-4 sm:px-6 lg:px-8 py-6 lg:py-8">{pageTransition}</div>
        </main>
      </div>
    </div>
  );
};