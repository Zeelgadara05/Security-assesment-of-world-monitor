import React from 'react';
import { Book, ShieldCheck, Cpu, Code, BookOpen } from 'lucide-react';

export const KnowledgeBase: React.FC = () => {
  const articles = [
    {
      title: "Understanding SQL Injection (SQLi)",
      category: "OWASP A03:2021",
      desc: "SQL Injection occurs when untrusted user input is directly concatenated into SQL database queries, allowing attackers to manipulate queries and bypass security logic.",
      remediation: "Always use Parameterized Queries (Prepared Statements) or Object Relational Mappers (ORMs). Never format or concatenate raw strings directly into query methods."
    },
    {
      title: "Content Security Policy (CSP) Headers Setup",
      category: "OWASP A05:2021",
      desc: "A missing or weak Content Security Policy leaves web applications vulnerable to Cross-Site Scripting (XSS) and code injection by failing to declare valid source scripts domain list.",
      remediation: "Return custom HTTP header: Content-Security-Policy: default-src 'self' script-src 'self' https://trusted-cdn.com."
    },
    {
      title: "MITRE ATT&CK: Exploit Public-Facing Application (T1190)",
      category: "MITRE ATT&CK",
      desc: "Attackers look for weaknesses in websites, ports, and public tools to get initial access to networks. Standard scanners like Nuclei check for matching signatures.",
      remediation: "Apply patches immediately. Keep web servers and internal library configurations updated, and minimize target exposure."
    },
    {
      title: "Managing Outdated & Vulnerable Components",
      category: "OWASP A06:2021",
      desc: "Software systems containing outdated dependencies (like old jQuery, Express or Django versions) often harbor known public CVE vulnerabilities.",
      remediation: "Integrate Software Composition Analysis (SCA) scanners in your CI/CD pipelines and configure automated dependency upgrade bots."
    }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Security Knowledge Base</h2>
        <p className="text-slate-400 text-sm">Remediation guides, vulnerability concepts, OWASP Top 10 guidelines and MITRE tactics.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {articles.map((article, idx) => (
          <div key={idx} className="glass-card p-6 space-y-4">
            <div className="flex justify-between items-start">
              <span className="text-[10px] bg-slate-800 text-emerald-400 border border-slate-700 font-bold px-2 py-0.5 rounded">
                {article.category}
              </span>
              <Book className="w-4 h-4 text-slate-500" />
            </div>

            <div className="space-y-1">
              <h3 className="font-bold text-sm text-white">{article.title}</h3>
              <p className="text-slate-400 text-xs leading-relaxed">{article.desc}</p>
            </div>

            <div className="bg-slate-950/60 border border-slate-900/60 p-4 rounded-lg space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold">
                <Code className="w-3.5 h-3.5" />
                <span>Standard Mitigation Plan</span>
              </div>
              <p className="text-slate-400 text-xs leading-relaxed">{article.remediation}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
