import React, { useState, useEffect, useCallback } from 'react';
import { FileText, Eye, Download, FileDown } from 'lucide-react';
import MonacoEditor from '@monaco-editor/react';
import { apiFetch, authUrl } from '../api';
import { PageHeader } from '../components/PageHeader';
import { Select } from '../components/Field';
import { EmptyState } from '../components/EmptyState';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDate } from '../components/format';

type Format = 'markdown' | 'json' | 'html';

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [content, setContent] = useState('');
  const [format, setFormat] = useState<Format>('markdown');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [contentLoading, setContentLoading] = useState(false);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/reports/list');
      if (res.ok) {
        const data = await res.json();
        setReports(data);
        if (data.length > 0 && selectedScanId === null) {
          const first = data[0].scan_id;
          setSelectedScanId(first);
          await loadContent(first, 'markdown');
        }
        setError('');
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load reports.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, [selectedScanId]);

  const loadContent = async (scanId: number, reqFormat: Format) => {
    setContentLoading(true);
    try {
      const res = await apiFetch(`/reports/${scanId}/${reqFormat}`);
      if (res.ok) {
        setSelectedScanId(scanId);
        setFormat(reqFormat);
        if (reqFormat === 'json') {
          const jsonVal = await res.json();
          setContent(JSON.stringify(jsonVal, null, 2));
        } else {
          setContent(await res.text());
        }
      }
    } catch {
      setContent('// Could not load report content.');
    } finally {
      setContentLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selected = reports.find((r) => r.scan_id === selectedScanId) || null;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Reports"
        title="Security reports"
        description="Download and preview auto-generated assessment reports. Formats are produced by the backend."
      />

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* List */}
        <div className="xl:col-span-4">
          <div className="panel rounded-md overflow-hidden">
            <div className="px-4 pt-4 pb-2 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Generated reports</h2>
              <span className="mono-cell text-[10px] text-faint">{reports.length}</span>
            </div>
            <div className="max-h-[70vh] overflow-y-auto p-2">
              {loading ? (
                <div className="space-y-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="skeleton h-14 rounded" />
                  ))}
                </div>
              ) : reports.length === 0 ? (
                <EmptyState
                  icon={<FileText className="w-4 h-4" aria-hidden="true" />}
                  title="No reports generated"
                  description="Run an assessment to produce report artifacts."
                />
              ) : (
                <ul className="space-y-1">
                  {reports.map((rep) => {
                    const active = selectedScanId === rep.scan_id;
                    return (
                      <li key={rep.id}>
                        <button
                          onClick={() => loadContent(rep.scan_id, 'markdown')}
                          className={`w-full text-left rounded px-3 py-2.5 border-l-2 transition-colors cursor-pointer ${
                            active ? 'bg-surface-2 border-accent' : 'border-transparent hover:bg-surface-2/60'
                          }`}
                        >
                          <span className="block text-[11.5px] font-medium text-text leading-snug line-clamp-2">{rep.title}</span>
                          <span className="mono-cell text-[10px] text-faint mt-1 block">scan #{rep.scan_id}</span>
                          <span className="mono-cell text-[9px] text-faint block">{formatDate(rep.created_at)}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Preview */}
        <div className="xl:col-span-8">
          <div className="panel rounded-md flex flex-col min-h-0" style={{ height: 640 }}>
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3 pb-2 border-b border-line">
              <div className="flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-accent" aria-hidden="true" />
                <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Report preview</h2>
              </div>
              {selected && (
                <div className="flex items-center gap-2">
                  <Select label="" value={format} onChange={(e) => selectedScanId && loadContent(selectedScanId, e.target.value as Format)} className="!py-1.5 !text-[11px]">
                    <option value="markdown">Markdown</option>
                    <option value="json">JSON</option>
                    <option value="html">HTML</option>
                  </Select>
                </div>
              )}
            </div>

            <div className="flex-1 min-h-0 m-3 border border-line rounded overflow-hidden relative">
              {contentLoading ? (
                <div className="absolute inset-0 p-4">
                  <SkeletonPanel className="!border-0 h-full" />
                </div>
              ) : !selected ? (
                <div className="absolute inset-0 flex items-center justify-center">
                  <EmptyState
                    title="No report selected"
                    description="Select a report from the list to preview its content."
                  />
                </div>
              ) : (
                <MonacoEditor
                  height="100%"
                  language={format === 'json' ? 'json' : format === 'html' ? 'html' : 'markdown'}
                  theme="vs-dark"
                  value={content}
                  loading={
                    <div className="flex items-center justify-center h-full text-faint text-[11px]">Loading preview…</div>
                  }
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    fontSize: 11.5,
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    padding: { top: 12, bottom: 12 },
                    wordWrap: 'on',
                  }}
                />
              )}
            </div>

            {/* Actions */}
            {selected && (
              <div className="flex flex-wrap items-center justify-end gap-2 px-4 pb-3">
                <a
                  href={authUrl(`/reports/${selectedScanId}/markdown`)}
                  download={`cyberagent_report_${selectedScanId}.md`}
                  className="inline-flex items-center gap-1.5 text-[11px] border border-line rounded px-2.5 py-1.5 text-muted hover:text-text hover:bg-surface-2 transition-colors"
                >
                  <Download className="w-3 h-3" aria-hidden="true" />
                  Markdown
                </a>
                <a
                  href={authUrl(`/reports/${selectedScanId}/json`)}
                  download={`cyberagent_report_${selectedScanId}.json`}
                  className="inline-flex items-center gap-1.5 text-[11px] border border-line rounded px-2.5 py-1.5 text-muted hover:text-text hover:bg-surface-2 transition-colors"
                >
                  <Download className="w-3 h-3" aria-hidden="true" />
                  JSON
                </a>
                <a
                  href={authUrl(`/reports/${selectedScanId}/pdf`)}
                  className="inline-flex items-center gap-1.5 text-[11px] bg-accent text-[#062b20] border border-accent rounded px-2.5 py-1.5 font-medium hover:bg-accent/85 transition-colors"
                >
                  <FileDown className="w-3 h-3" aria-hidden="true" />
                  Export PDF
                </a>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};