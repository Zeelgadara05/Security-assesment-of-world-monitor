import React, { useState, useEffect } from 'react';
import { FileText, Download, Eye, Sparkles } from 'lucide-react';
import MonacoEditor from '@monaco-editor/react';
import { apiFetch, authUrl } from '../api';

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [selectedReport, setSelectedReport] = useState<any | null>(null);
  const [content, setContent] = useState('');
  const [format, setFormat] = useState<'markdown' | 'json' | 'html'>('markdown');
  const [loading, setLoading] = useState(true);

  const fetchReports = async () => {
    try {
      const res = await apiFetch('/reports/list');
      if (res.ok) {
        const data = await res.json();
        setReports(data);
        if (data.length > 0) {
          handleSelectReport(data[0].scan_id, 'markdown');
        }
      }
    } catch (err) {
      console.error('Error fetching reports list:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectReport = async (scanId: number, reqFormat: 'markdown' | 'json' | 'html') => {
    setFormat(reqFormat);
    try {
      const res = await apiFetch(`/reports/${scanId}/${reqFormat}`);
      if (res.ok) {
        const selected = reports.find(r => r.scan_id === scanId);
        setSelectedReport(selected || { scan_id: scanId, title: `Report for Scan #${scanId}` });

        if (reqFormat === 'json') {
          const jsonVal = await res.json();
          setContent(JSON.stringify(jsonVal, null, 2));
        } else {
          const textVal = await res.text();
          setContent(textVal);
        }
      }
    } catch (err) {
      console.error('Error fetching report details:', err);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Security Reports</h2>
        <p className="text-slate-400 text-sm">Download and preview auto-generated compliance and vulnerability details reports.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left: Report list panel */}
        <div className="glass-card p-4 space-y-3 h-[550px] overflow-y-auto">
          <h3 className="text-sm font-semibold text-slate-300">Generated Reports</h3>

          {loading ? (
            <div className="text-slate-500 text-xs text-center py-10">Fetching reports...</div>
          ) : reports.length === 0 ? (
            <div className="text-slate-500 text-xs text-center py-10">No reports generated yet. Run a scan pipeline.</div>
          ) : (
            <div className="space-y-2">
              {reports.map((rep) => (
                <div
                  key={rep.id}
                  onClick={() => handleSelectReport(rep.scan_id, 'markdown')}
                  className={`p-3 rounded-lg border transition-all duration-200 cursor-pointer ${
                    selectedReport?.scan_id === rep.scan_id
                      ? 'bg-slate-900 border-emerald-500/40'
                      : 'bg-slate-955 border-slate-900 hover:bg-slate-900/40 hover:border-slate-800'
                  }`}
                >
                  <div className="flex gap-2 items-start mb-1">
                    <FileText className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                    <span className="font-semibold text-xs text-white leading-tight">{rep.title}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 block text-right mt-1">
                    {new Date(rep.created_at).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Monaco Editor preview details */}
        <div className="glass-card p-5 lg:col-span-3 h-[550px] flex flex-col space-y-4">
          <div className="flex justify-between items-center flex-shrink-0">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-emerald-500" />
              <h3 className="text-sm font-semibold text-slate-300">Report Artifact Preview</h3>
            </div>
            
            {selectedReport && (
              <div className="flex gap-1.5 bg-slate-950 border border-slate-900 p-1 rounded-lg">
                <button
                  onClick={() => handleSelectReport(selectedReport.scan_id, 'markdown')}
                  className={`text-[10px] font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    format === 'markdown' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  Markdown
                </button>
                <button
                  onClick={() => handleSelectReport(selectedReport.scan_id, 'json')}
                  className={`text-[10px] font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    format === 'json' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  JSON
                </button>
                <button
                  onClick={() => handleSelectReport(selectedReport.scan_id, 'html')}
                  className={`text-[10px] font-semibold px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    format === 'html' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  HTML
                </button>
              </div>
            )}
          </div>

          {/* Monaco preview panel */}
          <div className="flex-1 border border-slate-900 rounded-lg overflow-hidden relative">
            {!selectedReport ? (
              <div className="absolute inset-0 flex items-center justify-center text-slate-600 text-xs">
                // Select a report from the list to preview content
              </div>
            ) : (
              <MonacoEditor
                height="100%"
                language={format === 'json' ? 'json' : format === 'html' ? 'html' : 'markdown'}
                theme="vs-dark"
                value={content}
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  fontSize: 11,
                  fontFamily: 'Fira Code',
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  padding: { top: 12, bottom: 12 }
                }}
              />
            )}
          </div>

          {/* Action download links */}
          {selectedReport && (
            <div className="flex justify-end gap-2 flex-shrink-0">
              <a
                href={authUrl(`/reports/${selectedReport.scan_id}/pdf`)}
                className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs px-4 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export PDF</span>
              </a>
              <a
                href={authUrl(`/reports/${selectedReport.scan_id}/markdown`)}
                download={`cyberagent_report_${selectedReport.scan_id}.md`}
                className="bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 font-semibold text-xs px-4 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Markdown</span>
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
