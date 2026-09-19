import React, { useState, useEffect, useRef } from 'react';
import { ShieldAlert, AlertTriangle, Info, ShieldCheck, ChevronDown, ChevronUp, Terminal, XCircle, RefreshCw, Cpu, Layers } from 'lucide-react';
import { apiFetch, authUrl } from '../api';

const STAGE_LABELS = [
  { id: 'queued', label: 'Queued' },
  { id: 'starting', label: 'Starting' },
  { id: 'recon', label: 'Recon' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'service_scan', label: 'Service Scan' },
  { id: 'http_scan', label: 'HTTP Scan' },
  { id: 'vulnerability_scan', label: 'Vulnerability Scan' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'reporting', label: 'Reporting' },
];

export const Scans: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<any | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [liveEvents, setLiveEvents] = useState<string[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);
  const liveRef = useRef<HTMLDivElement>(null);

  const fetchScans = async () => {
    try {
      const res = await apiFetch('/scans/list');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
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
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setLiveEvents([]);
    setDetailsLoading(true);
    try {
      const res = await apiFetch(`/scans/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
        setVulnerabilities(data.vulnerabilities || []);
        setTools(data.tools || []);
        setLogs(data.logs || '');
        startSSEStream(id);
      }
    } catch (err) {
      console.error('Error fetching scan details:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  const startSSEStream = (id: number) => {
    const es = new EventSource(authUrl(`/scans/${id}/events`));
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'error') {
          setLiveEvents((prev) => [...prev, `[Error] ${data.error}`]);
          setDetailsLoading(false);
          return;
        }
        if (data.type === 'stage') {
          setSelectedScan((prev: any) => (prev ? { ...prev, stage: data.stage, status: data.status } : prev));
          setLiveEvents((prev) => [...prev, `[Stage] ${data.stage} (${data.status})`]);
        }
        if (data.type === 'tool') {
          const line = `[Tool] ${data.tool} -> ${data.status}`;
          setLiveEvents((prev) => [...prev, line]);
          setTools((prev) => [...prev, { name: data.tool, status: data.status }]);
        }
        if (data.type === 'finding') {
          setLiveEvents((prev) => [...prev, `[Finding] ${data.severity}: ${data.title}`]);
        }
        if (data.type === 'progress') {
          setSelectedScan((prev: any) => (prev ? { ...prev, coverage: data.coverage, security_score: data.security_score } : prev));
        }
        if (data.type === 'done') {
          setSelectedScan((prev: any) => (prev ? { ...prev, status: data.status, stage: data.stage, coverage: data.coverage, security_score: data.security_score } : prev));
          setLiveEvents((prev) => [...prev, `[Done] ${data.status} — coverage ${data.coverage ?? 0}%`]);
          es.close();
          eventSourceRef.current = null;
          setDetailsLoading(false);
        }
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };

    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
    };
  };

  useEffect(() => {
    fetchScans();
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  useEffect(() => {
    if (liveRef.current) {
      liveRef.current.scrollTop = liveRef.current.scrollHeight;
    }
  }, [liveEvents]);

  const handleCancel = async () => {
    if (!selectedScan) return;
    setCancelling(true);
    try {
      const res = await apiFetch(`/scans/${selectedScan.id}/cancel`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setLiveEvents((prev) => [...prev, `[System] Cancellation requested. ${data.message || ''}`]);
        setSelectedScan((prev: any) => (prev ? { ...prev, status: 'Cancelling...' } : prev));
      } else {
        const errData = await res.json().catch(() => null);
        setLiveEvents((prev) => [...prev, `[Error] Cancel failed: ${errData?.detail || 'unknown'}`]);
      }
    } catch {
      setLiveEvents((prev) => [...prev, '[Error] Cancel failed: server unreachable.']);
    } finally {
      setCancelling(false);
    }
  };

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

  const stageIndex = (s: string | undefined) => STAGE_LABELS.findIndex((st) => st.id === (s || '').toLowerCase());
  const currentStageIdx = selectedScan ? stageIndex(selectedScan.stage) : -1;
  const terminalStage = selectedScan ? ['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase()) : false;
  const lastInclusive = terminalStage ? STAGE_LABELS.length : currentStageIdx + 1;

  const isActive = (idx: number) => !terminalStage && idx === currentStageIdx;
  const isDone = (idx: number) => idx < lastInclusive;
  const totalTools = tools.length;
  const notInstalledTools = tools.filter((t) => (t.status || '').toLowerCase() === 'not installed').length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Scans History</h2>
        <p className="text-slate-400 text-sm">Stage-packed lifetime of each scanning job, its evidence, and outcomes.</p>
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
                      scan.status === 'Cancelled' ? 'bg-slate-500/10 border-slate-500/20 text-slate-400' :
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

        {/* Right Side: Scan Details */}
        <div className="glass-card p-6 lg:col-span-2 space-y-6 h-[600px] overflow-y-auto">
          {detailsLoading ? (
            <div className="text-slate-500 text-xs text-center py-24">Loading scan details...</div>
          ) : !selectedScan ? (
            <div className="text-slate-500 text-xs text-center py-24">Select a scan history card to inspect the pipeline output.</div>
          ) : (
            <div className="space-y-6">
              {/* Target info card */}
              <div className="flex justify-between items-start border-b border-slate-850 pb-4">
                <div>
                  <h3 className="font-bold text-lg text-white">{selectedScan.target}</h3>
                  <p className="text-xs text-slate-500">Scan ID: #{selectedScan.id} • Queued at {new Date(selectedScan.created_at).toLocaleString()}</p>
                  <div className="flex gap-2 mt-2 text-[10px]">
                    <span className="bg-slate-900 border border-slate-800 text-slate-300 px-2 py-0.5 rounded-full font-mono">stage: {selectedScan.stage || 'queued'}</span>
                    <span className="bg-slate-900 border border-slate-800 text-slate-300 px-2 py-0.5 rounded-full font-mono">mode: {selectedScan.simulation ? 'simulation' : 'real'}</span>
                  </div>
                </div>
                <div className="text-right space-y-1">
                  <span className="text-[10px] text-slate-500 block uppercase tracking-widest font-semibold">Security Rating</span>
                  <span className={`text-3xl font-extrabold ${
                    selectedScan.security_score >= 80 ? 'text-emerald-500' :
                    selectedScan.security_score >= 50 ? 'text-warning' : 'text-danger'
                  }`}>{selectedScan.security_score ?? '--'}/100</span>
                  <span className="block text-[10px] text-slate-500">Coverage: {selectedScan.coverage ?? '--'}%</span>
                </div>
              </div>

              {/* Lifecycle timeline */}
              {selectedScan.stage && (
                <div className="space-y-3">
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-emerald-500" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Pipeline Lifecycle</h4>
                  </div>
                  <div className="flex items-center gap-1 overflow-x-auto pb-1">
                    {STAGE_LABELS.map((stage, idx) => {
                      const done = isDone(idx);
                      const active = isActive(idx);
                      return (
                        <div key={stage.id} className="flex items-center gap-1 flex-shrink-0">
                          <div
                            className={`px-2.5 py-1 rounded-full border text-[9px] font-bold uppercase tracking-wide flex-shrink-0 ${
                              done && !active && !terminalStage ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                              : done && terminalStage ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                              : active ? 'bg-amber-500/10 border-amber-500/40 text-amber-400 animate-pulse'
                              : 'bg-slate-950 border-slate-800 text-slate-600'
                            }`}
                          >
                            {stage.label}
                          </div>
                          {idx < STAGE_LABELS.length - 1 && (
                            <div className={`w-2 h-px ${done ? 'bg-emerald-500/40' : 'bg-slate-800'}`} />
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Tool results */}
              <div className="space-y-2 border-t border-slate-850 pt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Cpu className="w-4 h-4 text-emerald-500" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Tool Pipeline ({totalTools})</h4>
                  </div>
                  {notInstalledTools > 0 && (
                    <span className="text-[9px] text-amber-400/80 font-mono">{notInstalledTools} not installed — honestly reported</span>
                  )}
                </div>
                {totalTools === 0 ? (
                  <div className="bg-slate-950 border border-slate-900 rounded-lg p-4 text-[10px] text-slate-500 text-center">
                    No tools have completed yet. Queued jobs launch asynchronously.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {tools.map((tr, i) => {
                      const st = (tr.status || '').toLowerCase();
                      return (
                        <span
                          key={`${tr.name}-${i}`}
                          className={`text-[9px] font-mono px-2 py-1 rounded border ${
                            st === 'completed' || st === 'success'
                              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                              : st === 'not installed'
                                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                                : st === 'failed'
                                  ? 'bg-red-500/10 border-red-500/30 text-red-400'
                                  : 'bg-slate-900 border-slate-800 text-slate-400'
                          }`}
                          title={tr.raw_output ? `raw output available in /observations` : undefined}
                        >
                          {tr.name} <span className="opacity-80">· {tr.status}</span>
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Scan Findings */}
              <div className="space-y-4">
                <h4 className="text-sm font-semibold text-slate-300">Vulnerabilities Identified ({vulnerabilities.length})</h4>

                {vulnerabilities.length === 0 ? (
                  <div className="bg-slate-950 border border-slate-900 rounded-lg p-6 text-center">
                    <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                    <p className="text-xs text-slate-400">No evidence-backed findings were persisted for this scan.</p>
                    <p className="text-[10px] text-slate-600 mt-1">Findings are only ever created from real tool observations.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {vulnerabilities.map((vuln) => {
                      const isExpanded = expandedVuln === vuln.id;
                      return (
                        <div key={vuln.id} className="border border-slate-850/80 rounded-lg overflow-hidden bg-slate-950/20">
                          <div
                            onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                            className="flex items-center justify-between p-4 cursor-pointer hover:bg-slate-900/30 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                              <span className="text-xs font-semibold text-slate-200">{vuln.title}</span>
                              <span className="text-[9px] text-slate-500 font-mono">[{vuln.state || 'NEW'}]</span>
                            </div>
                            <div className="flex items-center gap-2">
                              {vuln.cve && <span className="text-[10px] font-mono bg-slate-850 px-2 py-0.5 rounded text-slate-400">{vuln.cve}</span>}
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                            </div>
                          </div>

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
                                  <span className="text-[10px] text-slate-500 block">Rule / CWE</span>
                                  <span className="font-mono text-slate-300">{vuln.rule_id || 'legacy'}{vuln.cwe ? ` · ${vuln.cwe}` : ''}</span>
                                </div>
                              </div>

                              <div className="space-y-1">
                                <span className="text-[10px] text-slate-500 block">Description</span>
                                <p className="text-slate-300 leading-relaxed">{vuln.description}</p>
                              </div>

                              <div className="space-y-1">
                                <span className="text-[10px] text-slate-500 block">Recommended Mitigation</span>
                                <p className="text-emerald-400 leading-relaxed bg-emerald-950/10 border border-emerald-900/20 p-3 rounded-lg">{vuln.remediation}</p>
                              </div>

                              {(vuln.evidence_observation_ids?.length > 0) && (
                                <div className="space-y-1">
                                  <span className="text-[10px] text-slate-500 block">Evidence Provenance</span>
                                  <div className="flex flex-wrap gap-1.5">
                                    {vuln.evidence_observation_ids.map((oid: number) => (
                                      <span key={oid} className="text-[9px] font-mono bg-slate-900 border border-slate-800 text-emerald-400 px-2 py-0.5 rounded">
                                        observation #{oid}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

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

              {/* Cancel + live events */}
              <div className="flex items-center gap-2 border-t border-slate-850 pt-4">
                {(selectedScan.status === 'Running' || selectedScan.status === 'Pending' || selectedScan.status === 'Cancelling...') && !['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase()) ? (
                  <button
                    onClick={handleCancel}
                    disabled={cancelling}
                    className="bg-red-950/30 border border-red-800/40 text-red-400 hover:bg-red-950/50 disabled:opacity-50 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    <span>{cancelling ? 'Requesting...' : 'Request Cancellation'}</span>
                  </button>
                ) : (
                  <button
                    onClick={fetchScans}
                    className="bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Refresh</span>
                  </button>
                )}
                <div
                  ref={liveRef}
                  className="flex-1 h-24 bg-slate-950/60 border border-slate-900 rounded-lg p-2.5 font-mono text-[9px] text-emerald-400/80 overflow-y-auto whitespace-pre-wrap"
                >
                  {liveEvents.length === 0
                    ? <span className="text-slate-600">// Waiting for live pipeline events...</span>
                    : liveEvents.join('\n')}
                </div>
              </div>

              {/* Terminal Logs */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-500" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Scan Logs</h4>
                </div>
                <pre className="bg-slate-950 border border-slate-900 rounded-lg p-4 font-mono text-[10px] text-emerald-400 leading-relaxed max-h-48 overflow-y-auto whitespace-pre-wrap">{logs || '// No logs yet.'}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};