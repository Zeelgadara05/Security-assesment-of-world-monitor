import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Radio, FileText, Server, BookOpen, MessageSquare, Settings, ShieldAlert, Cpu, LogOut } from 'lucide-react';
import { apiFetch } from '../api';

interface SidebarProps {
  children: React.ReactNode;
  onLogout: () => void;
}

export const DashboardLayout: React.FC<SidebarProps> = ({ children, onLogout }) => {
  const [user, setUser] = useState<{ email: string; role: string } | null>(null);

  useEffect(() => {
    apiFetch('/auth/me')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setUser({ email: data.email, role: data.role || 'user' }))
      .catch(() => {});
  }, []);

  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'New Scan', path: '/scan/new', icon: Radio },
    { name: 'Scans History', path: '/scans', icon: ShieldAlert },
    { name: 'Assets', path: '/assets', icon: Server },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Assessment Assistant', path: '/chat', icon: MessageSquare },
    { name: 'Knowledge Base', path: '/knowledge', icon: BookOpen },
    { name: 'Tool Health', path: '/tools', icon: Cpu },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const initials = (user?.email || '?')
    .split('@')[0]
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-slate-100 font-sans">
      {/* Sidebar Nav */}
      <aside className="w-64 border-r border-slate-800/80 bg-slate-950/80 backdrop-blur-md flex flex-col justify-between p-4 flex-shrink-0">
        <div>
          {/* Brand Logo */}
          <div className="flex items-center gap-3 px-2 py-3 mb-6">
            <div className="w-8 h-8 rounded-lg overflow-hidden flex items-center justify-center shadow-lg shadow-slate-900/50 border border-slate-800 flex-shrink-0">
              <img src="/logo.png" alt="CyberAgent Logo" className="w-full h-full object-cover" />
            </div>
            <div>
              <h1 className="font-bold tracking-wider text-base text-white">CyberAgent</h1>
              <p className="text-[10px] text-emerald-500 uppercase tracking-widest font-semibold">Scan Platform</p>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="space-y-1">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.name}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 cursor-pointer ${
                      isActive
                        ? 'bg-slate-800 text-white border-l-2 border-emerald-500 pl-2.5'
                        : 'text-slate-400 hover:bg-slate-900/60 hover:text-slate-200'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* User Card Profile */}
        <div className="border-t border-slate-800/80 pt-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 rounded-full bg-slate-800 flex items-center justify-center font-bold text-emerald-500 border border-slate-700">
              {initials}
            </div>
            <div>
              <p className="text-xs font-semibold text-slate-200">{user?.email ? user.email.split('@')[0] : 'Loading...'}</p>
              <p className="text-[10px] text-slate-500 capitalize">{user?.email || '...'}</p>
              {user?.role && (
                <p className="text-[9px] text-emerald-500 uppercase tracking-widest font-semibold">{user.role}</p>
              )}
            </div>
          </div>
          <button
            onClick={onLogout}
            className="text-slate-500 hover:text-red-400 transition-colors p-1.5 rounded-lg hover:bg-slate-900 cursor-pointer"
            aria-label="Log out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Main Panel Viewport */}
      <main className="flex-1 overflow-y-auto bg-background p-8 relative">
        <div className="max-w-7xl mx-auto space-y-6">
          {children}
        </div>
      </main>
    </div>
  );
};