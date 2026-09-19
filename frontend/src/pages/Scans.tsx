import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Info, ShieldCheck, ChevronDown, ChevronUp, FileText, MessageSquare, Terminal } from 'lucide-react';
import { apiFetch } from '../api';

export const Scans: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<any | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  const fetchScans = async () => {
    try {
      const res = await apiFetch('/scans/list');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
        // Select first scan automatically
        if (data.length > 0 && !selectedScan) {
          handleSelectScan(data[0].id);
        }
      }
    } catch (err) {
      console.error('Error fetching scans list:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectScan = async (id: number) => {
    setDetailsLoading(true);
    try {
      const res = await apiFetch(`/scans/${id}/details`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
        setVulnerabilities(data.vulnerabilities || []);
        setLogs(data.logs || '');
      }
    } catch (err) {
      console.error('Error fetching scan details:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/10 border-red-500/20 text-red-500';
      case 'high':
        return 'bg-orange-500/10 border-orange-500/20 text-orange-500';
      case 'medium':
        return 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500';
      case 'low':
        return 'bg-blue-500/10 border-blue-500/20 text-blue-500';
      default:
        return 'bg-slate-500/10 border-slate-500/20 text-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Scans History</h2>
        <p className="text-slate-400 text-sm">Historical review of security findings, reports, and AI planner outputs.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Side: Scan list */}
        <div className="glass-card p-4 space-y-3 h-[600px] overflow-y-auto">
          <h3 className="text-sm font-semibold text-slate-300 px-1">Triggered Scans</h3>
          
          {loading ? (
            <div className="text-slate-500 text-xs text-center py-8">Loading history...</div>
          ) : scans.length === 0 ? (
            <div className="text-slate-500 text-xs text-center py-8">No scan logs found.</div>
          ) : (
            <div className="space-y-2">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => handleSelectScan(scan.id)}
                  className={`p-3.5 rounded-lg border transition-all duration-200 cursor-pointer ${
                    selectedScan?.id === scan.id
                      ? 'bg-slate-900 border-emerald-500/40'
                      : 'bg-slate-955 border-slate-900 hover:bg-slate-900/40 hover:border-slate-800'
                  }`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-semibold text-xs text-white truncate max-w-[140px]">{scan.target}</span>
                    <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold border ${
                      scan.status === 'Completed' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' :
                      scan.status === 'Running' ? 'bg-amber-500/10 border-amber-500/20 text-amber-500 animate-pulse' :
                      'bg-red-500/10 border-red-500/20 text-red-500'
                    }`}>{scan.status}</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>Score: <strong className={scan.security_score >= 80 ? 'text-emerald-500' : scan.security_score >= 50 ? 'text-yellow-500' : 'text-red-500'}>{scan.security_score ?? 'Pending'}</strong></span>
                    <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Side: Scan Details / Vulnerabilities */}
        <div className="glass-card p-6 lg:col-span-2 space-y-6 h-[600px] overflow-y-auto">
          {detailsLoading ? (
            <div className="text-slate-500 text-xs text-center py-24">Loading scan details...</div>
          ) : !selectedScan ? (
            <div className="text-slate-500 text-xs text-center py-24">Select a scan history card to inspect vulnerabilities.</div>
          ) : (
            <div className="space-y-6">
              {/* Target info card */}
              <div className="flex justify-between items-start border-b border-slate-850 pb-4">
                <div>
                  <h3 className="font-bold text-lg text-white">{selectedScan.target}</h3>
                  <p className="text-xs text-slate-500">Scan ID: #{selectedScan.id} • Triggered at {new Date(selectedScan.created_at).toLocaleString()}</p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 block uppercase tracking-widest font-semibold">Security Rating</span>
                  <span className={`text-3xl font-extrabold ${
                    selectedScan.security_score >= 80 ? 'text-emerald-500' :
                    selectedScan.security_score >= 50 ? 'text-warning' : 'text-danger'
                  }`}>{selectedScan.security_score}/100</span>
                </div>
              </div>

              {/* Scan Findings Lists */}
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-slate-300">Vulnerabilities Identified ({vulnerabilities.length})</h4>

                {vulnerabilities.length === 0 ? (
                  <div className="bg-slate-950 border border-slate-900 rounded-lg p-6 text-center">
                    <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                    <p className="text-xs text-slate-400">Zero active vulnerabilities detected by scanning agents.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {vulnerabilities.map((vuln) => {
                      const isExpanded = expandedVuln === vuln.id;
                      return (
                        <div key={vuln.id} className="border border-slate-850/80 rounded-lg overflow-hidden bg-slate-950/20">
                          {/* Header toggle row */}
                          <div
                            onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                            className="flex items-center justify-between p-4 cursor-pointer hover:bg-slate-900/30 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                              <span className="text-xs font-semibold text-slate-200">{vuln.title}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              {vuln.cve && <span className="text-[10px] font-mono bg-slate-850 px-2 py-0.5 rounded text-slate-400">{vuln.cve}</span>}
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                            </div>
                          </div>

                          {/* Expanded Details panel */}
                          {isExpanded && (
                            <div className="p-4 border-t border-slate-850 bg-slate-950/50 space-y-4 text-xs">
                              <div className="grid grid-cols-2 gap-4 text-slate-400 border-b border-slate-900 pb-3">
                                <div>
                                  <span className="text-[10px] text-slate-500 block">OWASP Alignment</span>
                                  <span className="font-semibold text-slate-300">{vuln.owasp || 'N/A'}</span>
                                </div>
                                <div>
                                  <span className="text-[10px] text-slate-500 block">MITRE ATT&CK Mapping</span>
                                  <span className="font-semibold text-slate-300">{vuln.mitre || 'N/A'}</span>
                                </div>
                                <div>
                                  <span className="text-[10px] text-slate-500 block">CVSS Rating</span>
                                  <span className="font-semibold text-slate-300">{vuln.cvss || 'N/A'}</span>
                                </div>
                                <div>
                                  <span className="text-[10px] text-slate-500 block">Identified Endpoint</span>
                                  <span className="font-mono text-emerald-400 truncate block">{vuln.target || selectedScan.target}</span>
                                </div>
                              </div>

                              <div className="space-y-1">
                                <span className="text-[10px] text-slate-500 block">Vulnerability Summary</span>
                                <p className="text-slate-300 leading-relaxed">{vuln.description}</p>
                              </div>

                              <div className="space-y-1">
                                <span className="text-[10px] text-slate-500 block">AI Recommended Mitigation</span>
                                <p className="text-emerald-400 leading-relaxed bg-emerald-950/10 border border-emerald-900/20 p-3 rounded-lg">{vuln.remediation}</p>
                              </div>

                              {vuln.proof_of_concept && (
                                <div className="space-y-1">
                                  <span className="text-[10px] text-slate-500 block">Proof of Concept Evidence</span>
                                  <pre className="bg-slate-950 border border-slate-900 rounded p-3 text-[10px] font-mono text-cyan-400 overflow-x-auto whitespace-pre-wrap">{vuln.proof_of_concept}</pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Terminal Logs view */}
              <div className="space-y-2 border-t border-slate-850 pt-4">
                <div className="flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-500" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Agent Scan Logs</h4>
                </div>
                <pre className="bg-slate-950 border border-slate-900 rounded-lg p-4 font-mono text-[10px] text-emerald-400 leading-relaxed max-h-48 overflow-y-auto whitespace-pre-wrap">{logs}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
