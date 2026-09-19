import React, { useState, useEffect, useRef } from 'react';
import { Send, UserRound, MessageSquareText, Sparkles, Bot } from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { LoaderBlock } from '../components/ErrorState';

interface Message {
  role: string;
  message: string;
  created_at?: string;
}

export const AIChat: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(true);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const fetchScans = async () => {
    try {
      const res = await apiFetch('/scans/list');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
        if (data.length > 0 && !selectedScanId) {
          setSelectedScanId(data[0].id);
          fetchChatHistory(data[0].id);
        }
      }
    } catch (err) {
      console.error('Error listing scans for chat context:', err);
    } finally {
      setListLoading(false);
    }
  };

  const fetchChatHistory = async (scanId: number) => {
    try {
      const res = await apiFetch(`/chat/history/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        setMessages(data);
      }
    } catch (err) {
      console.error('Error fetching chat history:', err);
    }
  };

  const handleSelectScan = (scanId: number) => {
    setSelectedScanId(scanId);
    setMessages([]);
    fetchChatHistory(scanId);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !selectedScanId) return;
    const userMsg = input.trim();
    setInput('');
    await sendMessage(userMsg);
  };

  const sendMessage = async (rawMsg: string) => {
    if (!selectedScanId) return;
    setMessages((prev) => [...prev, { role: 'user', message: rawMsg, created_at: new Date().toISOString() }]);
    setLoading(true);

    try {
      const res = await apiFetch('/chat/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: selectedScanId, message: rawMsg }),
      });

      if (res.ok) {
        const data = await res.json();
        setMessages((prev) => [...prev, { role: 'assistant', message: data.message, created_at: data.created_at }]);
      } else {
        const errData = await res.json().catch(() => null);
        setMessages((prev) => [
          ...prev,
          { role: 'assistant', message: errData?.detail || 'The request failed. Check the server and retry.', created_at: new Date().toISOString() },
        ]);
      }
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', message: 'Could not reach the assessment backend. Ensure the server is active.', created_at: new Date().toISOString() },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Autoscroll chat window
  useEffect(() => {
    if (chatScrollRef.current) chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
  }, [messages, loading]);

  useEffect(() => {
    fetchScans();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sampleQuestions = [
    'What is SQL Injection?',
    'How do I fix a missing CSP?',
    'Which issue should I fix first?',
    'Summarize the findings for this scan',
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Intelligence / Assistant"
        title="Assessment Assistant"
        description="Deterministic, evidence-driven Q&A over persisted scan findings. No fabricated answers."
      />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Session selector */}
        <div className="lg:col-span-1">
          <div className="panel rounded-md overflow-hidden">
            <div className="px-4 pt-4 pb-2 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Scan sessions</h2>
              <span className="mono-cell text-[10px] text-faint">{scans.length}</span>
            </div>
            <div className="max-h-[70vh] overflow-y-auto p-2">
              {listLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="skeleton h-12 rounded" />
                  ))}
                </div>
              ) : scans.length === 0 ? (
                <p className="text-[11px] text-faint px-2 py-4">No sessions available. Run a scan.</p>
              ) : (
                <ul className="space-y-1">
                  {scans.map((scan) => {
                    const active = selectedScanId === scan.id;
                    return (
                      <li key={scan.id}>
                        <button
                          onClick={() => handleSelectScan(scan.id)}
                          className={`w-full text-left rounded px-3 py-2.5 border-l-2 transition-colors cursor-pointer ${
                            active ? 'bg-surface-2 border-accent' : 'border-transparent hover:bg-surface-2/60'
                          }`}
                        >
                          <span className="block text-[12px] font-medium text-text truncate">{scan.target}</span>
                          <div className="flex items-center justify-between text-[10px] text-faint mt-0.5">
                            <span>scan #{scan.id}</span>
                            <span>score: {scan.security_score ?? '—'}</span>
                          </div>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Chat window */}
        <div className="lg:col-span-3 panel rounded-md flex flex-col min-h-0" style={{ height: 640 }}>
          <div className="flex items-center gap-2 px-4 pt-3 pb-2 border-b border-line">
            <MessageSquareText className="w-3.5 h-3.5 text-accent" aria-hidden="true" />
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Conversation</h2>
            {selectedScanId && (
              <span className="mono-cell text-[10px] text-faint ml-2">scan #{selectedScanId}</span>
            )}
          </div>

          <div ref={chatScrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
            {messages.length === 0 && !loading ? (
              <div className="h-full flex flex-col justify-center items-center text-center space-y-4 max-w-md mx-auto">
                <div className="w-12 h-12 rounded-md border border-line bg-surface-2 flex items-center justify-center text-accent">
                  <Sparkles className="w-5 h-5" strokeWidth={1.75} aria-hidden="true" />
                </div>
                <div>
                  <h4 className="text-[13px] font-semibold text-text">Ask about persisted vulnerabilities</h4>
                  <p className="text-[11.5px] text-muted mt-1">
                    Replies are generated only from evidence-backed findings recorded for the selected scan.
                  </p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full pt-1">
                  {sampleQuestions.map((q) => (
                    <button
                      key={q}
                      type="button"
                      onClick={() => {
                        if (selectedScanId) {
                          sendMessage(q);
                        } else {
                          setInput(q);
                        }
                      }}
                      className="text-left text-[11px] text-muted bg-surface-2 hover:bg-line border border-line p-2.5 rounded transition-colors cursor-pointer"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, idx) => (
                <div key={idx} className={`flex gap-3 max-w-[85%] ${m.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}>
                  <div
                    className={`w-7 h-7 rounded shrink-0 border flex items-center justify-center ${
                      m.role === 'user' ? 'bg-surface-2 border-line text-accent' : 'bg-surface-2 border-line text-muted'
                    }`}
                  >
                    {m.role === 'user' ? (
                      <UserRound className="w-3.5 h-3.5" aria-hidden="true" />
                    ) : (
                      <Bot className="w-3.5 h-3.5" aria-hidden="true" />
                    )}
                  </div>
                  <div
                    className={`rounded px-3.5 py-2.5 text-[12px] leading-relaxed whitespace-pre-wrap ${
                      m.role === 'user' ? 'bg-surface-2 text-text border border-line' : 'bg-bg text-muted border border-line'
                    }`}
                  >
                    {m.message}
                  </div>
                </div>
              ))
            )}

            {loading && (
              <div className="flex gap-3">
                <div className="w-7 h-7 rounded shrink-0 border border-line bg-surface-2 text-muted flex items-center justify-center">
                  <Bot className="w-3.5 h-3.5" aria-hidden="true" />
                </div>
                <div className="bg-bg border border-line rounded px-3.5 py-2.5 text-[12px] text-faint">
                  Compiling context from persisted findings…
                </div>
              </div>
            )}
          </div>

          <form onSubmit={handleSend} className="flex gap-2 px-4 pt-3 pb-4 border-t border-line">
            <input
              type="text"
              placeholder={
                selectedScanId ? "Ask the assistant — 'Explain this vulnerability'…" : 'Select a scan session to start'
              }
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={!selectedScanId || loading}
              className="flex-1 bg-bg border border-line rounded px-3 py-2 text-[12.5px] text-text placeholder:text-faint/70 focus:outline-none focus:border-accent/60 transition-colors disabled:opacity-50"
              aria-label="Ask a question"
            />
            <button
              type="submit"
              disabled={!selectedScanId || loading || !input.trim()}
              className="inline-flex items-center justify-center gap-1 p-2 rounded bg-accent text-[#062b20] hover:bg-accent/85 disabled:opacity-45 transition-colors cursor-pointer"
              aria-label="Send"
            >
              <Send className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

