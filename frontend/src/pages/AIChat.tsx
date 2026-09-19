import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, Send, Bot, User, Terminal, HelpCircle } from 'lucide-react';
import { API_URL } from '../api';

export const AIChat: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(true);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_URL}/scans/list`);
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
      const res = await fetch(`${API_URL}/chat/history/${scanId}`);
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
    // Optimistic user insert
    setMessages((prev) => [...prev, { role: 'user', message: userMsg, created_at: new Date() }]);
    setLoading(true);

    try {
      const res = await fetch(`${API_URL}/chat/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: selectedScanId, message: userMsg })
      });

      if (res.ok) {
        const data = await res.json();
        setMessages((prev) => [...prev, { role: 'assistant', message: data.message, created_at: data.created_at }]);
      }
    } catch (err) {
      console.error('Error in chat request:', err);
      setMessages((prev) => [...prev, { role: 'assistant', message: 'Could not connect to AI Copilot. Ensure backend server is active.', created_at: new Date() }]);
    } finally {
      setLoading(false);
    }
  };

  // Autoscroll chat window
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    fetchScans();
  }, []);

  const sampleQuestions = [
    "What is SQL Injection?",
    "How do I fix missing CSP?",
    "Which issue should I fix first?",
    "Summarize today's findings"
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">AI Security Copilot</h2>
        <p className="text-slate-400 text-sm">Ask question about scan findings, explain vulnerabilities or ask for code fixes.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left: Scan session selector */}
        <div className="glass-card p-4 space-y-3 h-[550px] overflow-y-auto">
          <h3 className="text-sm font-semibold text-slate-300">Scan Session Context</h3>
          
          {listLoading ? (
            <div className="text-slate-500 text-xs text-center py-10">Listing sessions...</div>
          ) : scans.length === 0 ? (
            <div className="text-slate-500 text-xs text-center py-10">No sessions available. Run a scan.</div>
          ) : (
            <div className="space-y-2">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => handleSelectScan(scan.id)}
                  className={`p-3 rounded-lg border transition-all duration-200 cursor-pointer ${
                    selectedScanId === scan.id
                      ? 'bg-slate-900 border-emerald-500/40'
                      : 'bg-slate-955 border-slate-900 hover:bg-slate-900/40 hover:border-slate-800'
                  }`}
                >
                  <span className="font-semibold text-xs text-white block truncate">{scan.target}</span>
                  <div className="flex justify-between items-center text-[10px] text-slate-500 mt-1">
                    <span>Scan #{scan.id}</span>
                    <span>Score: {scan.security_score ?? 'Pending'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Message Window */}
        <div className="glass-card p-5 lg:col-span-3 h-[550px] flex flex-col justify-between">
          {/* Messages lists scroll */}
          <div ref={chatScrollRef} className="flex-1 overflow-y-auto space-y-4 pr-2 mb-4 scroll-smooth">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col justify-center items-center text-center space-y-4 max-w-md mx-auto">
                <Bot className="w-12 h-12 text-emerald-500 bg-slate-900 border border-slate-850 p-2 rounded-xl" />
                <div>
                  <h4 className="text-sm font-bold text-white">Ask anything about vulnerabilities</h4>
                  <p className="text-slate-500 text-xs mt-1">CyberAgent AI Security copilot understands scan findings, vulnerabilities, and recommends clean fixes.</p>
                </div>
                
                {/* Seed prompt options */}
                <div className="grid grid-cols-2 gap-2 w-full pt-2">
                  {sampleQuestions.map((q) => (
                    <button
                      key={q}
                      onClick={() => setInput(q)}
                      className="text-left text-[10px] text-slate-400 bg-slate-900 hover:bg-slate-850 border border-slate-800/80 p-2.5 rounded-lg transition-colors cursor-pointer"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, idx) => (
                <div key={idx} className={`flex gap-3 max-w-[85%] ${m.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}>
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 border ${
                    m.role === 'user' ? 'bg-slate-800 border-slate-700 text-emerald-400' : 'bg-emerald-950/20 border-emerald-900/30 text-emerald-500'
                  }`}>
                    {m.role === 'user' ? <User className="w-4.5 h-4.5" /> : <Bot className="w-4.5 h-4.5" />}
                  </div>
                  
                  <div className={`p-4 rounded-xl text-xs leading-relaxed space-y-2 ${
                    m.role === 'user' ? 'bg-slate-900 text-white' : 'bg-slate-950/40 border border-slate-900 text-slate-200'
                  }`}>
                    <div className="whitespace-pre-line">{m.message}</div>
                  </div>
                </div>
              ))
            )}
            
            {loading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-emerald-500 flex items-center justify-center flex-shrink-0 animate-pulse">
                  <Bot className="w-4.5 h-4.5" />
                </div>
                <div className="bg-slate-950/40 border border-slate-900 p-4 rounded-xl text-xs text-slate-500 animate-pulse">
                  CyberAgent AI is compiling vulnerability logs and remediation instructions...
                </div>
              </div>
            )}
          </div>

          {/* Form input messaging controller */}
          <form onSubmit={handleSend} className="flex gap-2 flex-shrink-0 border-t border-slate-900 pt-3">
            <input
              type="text"
              placeholder={selectedScanId ? "Ask Copilot: 'Explain this vulnerability'..." : "Select scan session on the left to start chat"}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={!selectedScanId || loading}
              className="flex-1 bg-slate-950 border border-slate-900 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500/80 transition-colors"
            />
            <button
              type="submit"
              disabled={!selectedScanId || loading || !input.trim()}
              className="bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-slate-955 font-semibold text-xs px-4 py-2.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
