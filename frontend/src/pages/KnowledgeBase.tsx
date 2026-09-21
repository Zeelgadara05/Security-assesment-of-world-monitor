import React from 'react';
import { Shield, BookMarked, Wrench } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';

const articles = [
  {
    id: 1,
    title: 'Understanding SQL Injection (SQLi)',
    category: 'OWASP A03:2021',
    plan: 'SQL Injection occurs when untrusted user input is directly concatenated into SQL database queries, allowing attackers to manipulate queries and bypass security logic.',
    remediation:
      'Always use parameterized queries (prepared statements) or object relational mappers (ORMs). Never format or concatenate raw strings directly into query methods.',
    tags: ['input validation', 'OWASP'],
    ref: 'sql-injection',
  },
  {
    id: 2,
    title: 'Content Security Policy (CSP) Headers',
    category: 'OWASP A05:2021',
    plan: 'A missing or weak Content Security Policy leaves web applications vulnerable to Cross-Site Scripting (XSS) and code injection by failing to declare valid script sources.',
    remediation:
      "Return a custom HTTP header: Content-Security-Policy: default-src 'self' script-src 'self' https://trusted-cdn.com.",
    tags: ['headers', 'XSS'],
    ref: 'csp-headers',
  },
  {
    id: 3,
    title: 'MITRE ATT&CK: Exploit Public-Facing Application (T1190)',
    category: 'MITRE ATT&CK',
    plan: 'Attackers probe weaknesses in publicly reachable services for initial access. Standard scanners like Nuclei match published signatures to detect exposure.',
    remediation:
      'Apply patches immediately. Keep web servers and internal library configurations updated, and minimize target exposure.',
    tags: ['T1190', 'initial access'],
    ref: 'mitre-t1190',
  },
  {
    id: 4,
    title: 'Managing Outdated & Vulnerable Components',
    category: 'OWASP A06:2021',
    plan: 'Systems with outdated dependencies (old jQuery, Express, Django versions, …) often harbor known public CVEs that can be matched by signature scanners.',
    remediation:
      'Integrate Software Composition Analysis (SCA) in CI/CD pipelines and configure automated dependency upgrade bots.',
    tags: ['SCA', 'supply chain'],
    ref: 'outdated-components',
  },
];

export const KnowledgeBase: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace / Reference"
        title="Security knowledge base"
        description="Reference guides for the vulnerability classes this platform reports. Static editorial content — not assessment results."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {articles.map((a) => (
          <article key={a.id} className="panel flex flex-col p-6">
            <div className="flex items-center justify-between mb-3">
              <span className="mono-cell text-[10px] text-accent border border-accent/40 bg-accent/10 rounded-full px-2 py-0.5">
                {a.category}
              </span>
              <BookMarked className="h-4 w-4 text-faint" strokeWidth={1.5} aria-hidden="true" />
            </div>

            <h2 className="text-[13.5px] font-semibold text-text leading-snug">{a.title}</h2>
            <p className="text-[11.5px] text-muted leading-relaxed mt-2 flex-1">{a.plan}</p>

            <div className="mt-4 space-y-1.5 rounded-xl border border-line bg-bg p-3.5">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-accent">
                <Wrench className="w-3 h-3" aria-hidden="true" />
                <span>Standard mitigation plan</span>
              </div>
              <p className="text-[11.5px] text-muted leading-relaxed">{a.remediation}</p>
            </div>

            <div className="flex flex-wrap items-center gap-1.5 mt-3">
              <span className="mono-cell text-[9px] text-faint">#{a.ref}</span>
              {a.tags.map((t) => (
                <span key={t} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint">
                  {t}
                </span>
              ))}
            </div>
          </article>
        ))}
      </div>

      <div className="panel flex items-center gap-2.5 p-4 text-[11.5px] text-muted">
        <Shield className="w-3.5 h-3.5 text-accent" aria-hidden="true" />
        <span>
          Articles align with OWASP Top 10 (2021) and the MITRE ATT&amp;CK framework. Findings link to these concepts by
          rule identifier.
        </span>
      </div>
    </div>
  );
};