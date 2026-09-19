import React, { useState, useEffect } from 'react';
import { ShieldAlert, Play, ArrowRight, ShieldCheck, Activity, Award, CheckCircle, RefreshCw } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { apiFetch } from '../api';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [scanRes, summaryRes] = await Promise.all([
        apiFetch('/scans/list'),
        apiFetch('/scans/summary'),
      ]);
      if (scanRes.ok) {
        setScans(await scanRes.json());
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Compute metrics based on scans
  const activeScans = scans.filter((s) => s.status === 'Running').length;
  const completedScans = scans.filter((s) => s.status === 'Completed').length;
  const averageScore = (summary?.score_history?.length ?? 0) > 0
    ? Math.round(summary.score_history.reduce((acc: number, s: any) => acc + (s.score ?? 100), 0) / summary.score_history.length)
    : null;
  const openFindings = summary?.open_findings ?? 0;

  // Real analytical data, derived from persisted findings/assets
  const trendData = (summary?.score_history ?? []).map((s: any) => ({
    name: s.target,
    score: s.score ?? 100,
  }));

  const severityColors: Record<string, string> = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#3b82f6',
    Info: '#64748b',
  };
  const severityPieData = (Object.entries(summary?.severity_distribution ?? {}) as [string, number][])
    .filter(([, count]) => count > 0)
    .map(([name, count]) => ({ name, value: count, color: severityColors[name] ?? '#64748b' }));

  const portsData = (summary?.open_ports ?? []).map((p: string) => ({ name: p, count: 1 }));

  return (
    <div className="space-y-6">
      {/* Header banner */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Dashboard Overview</h2>
          <p className="text-slate-400 text-sm">Security posture and active scan operations monitor.</p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors text-slate-300"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Data</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-card p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Security Score</span>
            <Award className="w-5 h-5 text-emerald-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white">{averageScore ?? '--'}</span>
            <span className="text-xs text-slate-500">/100 avg</span>
          </div>
        </div>

        <div className="glass-card p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Active Scans</span>
            <Activity className="w-5 h-5 text-amber-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white">{activeScans}</span>
            <span className="text-xs text-slate-500">running currently</span>
          </div>
        </div>

        <div className="glass-card p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Scans Completed</span>
            <CheckCircle className="w-5 h-5 text-emerald-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white">{completedScans}</span>
            <span className="text-xs text-slate-500">total historical</span>
          </div>
        </div>

        <div className="glass-card p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-start">
            <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Open Findings</span>
            <ShieldAlert className="w-5 h-5 text-red-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-white">{openFindings}</span>
            <span className="text-xs text-red-400 font-medium">evidence-backed</span>
          </div>
        </div>
      </div>

      {/* Visualizations Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Score Trend Chart */}
        <div className="glass-card p-5 lg:col-span-2 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-300">Security Score History</h3>
            <p className="text-slate-500 text-xs">Timeline of security rating across scans.</p>
          </div>
          <div className="h-64 w-full">
            {trendData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">No scan history yet.</div>
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="score" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" />
              </AreaChart>
            </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Distribution Pie */}
        <div className="glass-card p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-300">Vulnerabilities Severity</h3>
            <p className="text-slate-500 text-xs">Active vulnerability findings breakdown.</p>
          </div>
          <div className="h-48 flex justify-center items-center">
            {severityPieData.length === 0 ? (
              <div className="text-slate-500 text-sm">No open findings.</div>
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityPieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b' }} />
              </PieChart>
            </ResponsiveContainer>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {severityPieData.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400 font-medium">{item.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Grid: Open Ports & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Open Ports Bar Chart */}
        <div className="glass-card p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-300">Discovered Open Ports</h3>
            <p className="text-slate-500 text-xs">Frequency of network ports found listening.</p>
          </div>
          <div className="h-64 w-full">
            {portsData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">No open ports discovered.</div>
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portsData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Recent Scans table */}
        <div className="glass-card p-5 lg:col-span-2 space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-sm font-semibold text-slate-300">Recent Scanning Tasks</h3>
              <p className="text-slate-500 text-xs">Recent security checks triggered.</p>
            </div>
            <a href="/scans" className="text-emerald-500 hover:text-emerald-400 text-xs font-semibold flex items-center gap-1 cursor-pointer">
              <span>View All</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </a>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 font-semibold">Target Domain / IP</th>
                  <th className="py-2.5 font-semibold">Status</th>
                  <th className="py-2.5 font-semibold">Score</th>
                  <th className="py-2.5 font-semibold">Triggered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {loading ? (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-slate-500">Loading scans...</td>
                  </tr>
                ) : scans.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-slate-500">No scans triggered yet. Go to "New Scan" to start.</td>
                  </tr>
                ) : (
                  scans.slice(0, 5).map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-900/40">
                      <td className="py-3 font-semibold text-white">{scan.target}</td>
                      <td className="py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                          scan.status === 'Completed' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' :
                          scan.status === 'Running' ? 'bg-amber-500/10 border-amber-500/20 text-amber-500 animate-pulse' :
                          scan.status === 'Failed' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                          'bg-slate-500/10 border-slate-500/20 text-slate-400'
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3">
                        <span className={`font-semibold ${
                          scan.security_score >= 80 ? 'text-emerald-500' :
                          scan.security_score >= 50 ? 'text-warning' : 'text-danger'
                        }`}>
                          {scan.security_score ?? 'Pending'}
                        </span>
                      </td>
                      <td className="py-3 text-slate-500">{new Date(scan.created_at).toLocaleTimeString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
