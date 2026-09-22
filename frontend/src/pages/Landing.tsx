import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Radar,
  Globe,
  ArrowUpRight,
  ArrowRight,
  ScanLine,
  ShieldCheck,
  FileText,
  Target,
  Layers,
  Network,
  Boxes,
  Eye,
  Crosshair,
} from 'lucide-react';
import { Button } from '../components/Button';
import { Reveal } from '../components/Reveal';

/* ============================================================================
   CyberAgent — public landing (unauthenticated root).
   Editorial acid/lime identity. Every section either states a real product
   capability or is an explicitly-conceptual editorial pipeline visualization.
   NO fabricated findings · NO fake telemetry · NO invented assessments.
   ========================================================================= */

const SECTIONS = [
  { id: 'flow', label: 'Product flow' },
  { id: 'surface', label: 'Attack surface' },
  { id: 'monitor', label: 'World Monitor' },
  { id: 'evidence', label: 'Evidence chain' },
];

const PIPELINE = [
  { label: 'Source', copy: 'Authorized scope — World Monitor deployments or declared custom targets.', icon: Crosshair },
  { label: 'Discovery', copy: 'Enumerate hosts, domains, subdomains and IPs in declared scope.', icon: Radar },
  { label: 'Enumeration', copy: 'Resolve services, ports and product metadata from live responses.', icon: Network },
  { label: 'DNS / HTTP', copy: 'Trace resolution paths and protocol behavior at the boundary.', icon: Globe },
  { label: 'Observations', copy: 'Every tool output persisted as a timestamped observation.', icon: ScanLine },
  { label: 'Evidence', copy: 'Selected observations become long-lived evidence records.', icon: Boxes },
  { label: 'Validation', copy: 'Evidence is validated against scope and tool output before any claim.', icon: Eye },
  { label: 'Finding', copy: 'Only validated, evidence-backed results surface as findings.', icon: ShieldCheck },
  { label: 'Report', copy: 'Traceable from source to evidence to finding to report.', icon: FileText },
];

const SURFACE = [
  { title: 'Domains & subdomains', copy: 'Scope declares what may be enumerated. Nothing is assessed without authorization.', tags: ['DNS', 'WHOIS', 'subdomains'] },
  { title: 'IPs, ports & services', copy: 'Discovery results are split by tool so coverage stays attributable.', tags: ['ports', 'services', 'banner'] },
  { title: 'URLs & endpoints', copy: 'HTTP enumeration feeds observations that become evidence.', tags: ['HTTP', 'paths', 'methods'] },
];

const WORLD_MONITOR = [
  { label: 'Register', copy: 'Add observed deployments as authorized World Monitor targets.' },
  { label: 'Reachability', copy: 'Check live connectivity of each registered deployment.' },
  { label: 'Inventory', copy: 'Discovery produces real, enumerated inventory entries.' },
  { label: 'Drive assessments', copy: 'Use World Monitor inventory as a first-class assessment source.' },
];

const EVIDENCE_CHAIN = [
  { label: 'Observation', copy: 'What a tool actually returned to CyberAgent.\nNo interpretation yet.' },
  { label: 'Evidence', copy: 'A persisted, immutable record with source, scope and tool identity.' },
  { label: 'Validation', copy: 'Deterministic rules confirm the record is in scope and well-formed.' },
  { label: 'Verified finding', copy: 'A finding is only published when evidence validates.' },
  { label: 'Report', copy: 'Traceable from assessment through evidence to the published report.' },
];

const REPORT_TRACE = [
  'Assessment → observations',
  'Observations → evidence',
  'Evidence → validated findings',
  'Findings → report',
];

// Editorial pipeline — conceptual, not live telemetry.
const CYBER_HEAD = [
  ['world monitor', 'source'],
  ['discovery', 'hosts / domains'],
  ['enumeration', 'services / ports'],
  ['dns / http', 'resolution / protocol'],
  ['observations', 'tool output'],
  ['evidence', 'persisted records'],
  ['validation', 'scope + output rules'],
  ['verified finding', 'evidence-backed'],
  ['report', 'traceable'],
];

const Landing: React.FC = () => {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(falseIv);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <div className="min-h-dvh bg-bg text-text">
      {/* ==================== PUBLIC NAV ==================== */}
      <a href="#landing-main" className="skip-link">Skip to content</a>
      <header
        className={`fixed inset-x-0 top-0 z-50 transition-[background-color,border-color,box-shadow] duration-500 ease-spring ${
          scrolled ? 'glass border-b border-line' : 'border-b border-transparent bg-transparent'
        }`}
      >
        <nav className="mx-auto flex h-16 max-w-[1440px] items-center justify-between gap-5 px-5 md:px-8" aria-label="Primary">
          <Link to="/" className="flex items-center gap-2 no-underline" aria-label="CyberAgent home">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-surface">
              <Radar className="h-4 w-4 text-accent" strokeWidth={1.5} aria-hidden="true" />
            </span>
            <span className="text-[13px] font-semibold tracking-tight text-text">CyberAgent</span>
          </Link>

          <div className="hidden items-center gap-1 md:flex">
            {SECTIONS.map((s) => (
              <a key={s.id} href={`#${s.id}`} className="rounded-lg px-3 py-2 text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:text-text">
                {s.label}
              </a>
            ))}
          </div>

          <div className="flex items-center gap-2.5">
            <Link to="/auth" className="rounded-lg px-3 py-2 text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:text-text">
              Sign in
            </Link>
            <Link
              to="/auth?mode=signup"
              className="rounded-full border border-accent/50 bg-accent px-4 py-2 text-[12px] font-semibold text-[#0a0a08] transition-[background-color,border-color,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
            >
              Get started
            </Link>
          </div>
        </nav>
      </header>

      <main id="landing-main" className="pt-16">
        {/* ==================== HERO ==================== */}
        <section className="relative overflow-hidden border-b border-line">
          <div className="pointer-events-none absolute inset-0" aria-hidden="true">
            <div className="absolute -top-24 right-[8%] h-[460px] w-[460px] rounded-full bg-accent/[0.06] blur-[120px]" />
            <div className="absolute bottom-0 left-[14%] h-[320px] w-[320px] rounded-full bg-accent/[0.03] blur-[120px]" />
          </div>

          <div className="relative mx-auto max-w-[1440px] px-5 pt-28 pb-20 md:px-8 md:pt-36 md:pb-28">
            <Reveal>
              <p className="eyebrow mb-5">Authorized security assessment</p>
            </Reveal>
            <Reveal delay={0.06}>
              <h1 className="max-w-[18ch] text-[clamp(2.4rem,7vw,5.6rem)] font-semibold leading-[1.02] tracking-[-0.035em] text-text">
                Security assessment
                <span className="block text-accent">without blind spots.</span>
              </h1>
            </Reveal>
            <Reveal delay={0.12}>
              <p className="mt-6 max-w-[52ch] text-[clamp(0.9rem,1.6vw,1.05rem)] leading-relaxed text-muted">
                Assess what you expose. Trace what you observe. Report what you can prove.
                CyberAgent runs authorized, scope-gated assessments and turns real
                observations into evidence-backed findings — never invented intelligence.
              </p>
            </Reveal>
            <Reveal delay={0.18}>
              <div className="mt-9 flex flex-wrap gap-3">
                <Button variant="primary" onClick={() => navigate('/auth?mode=signup')}>
                  Get started
                  <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                </Button>
                <Link to="/#flow" className="no-underline">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-4 py-2 text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text">
                    See how it works
                    <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                  </span>
                </Link>
              </div>
            </Reveal>

            {/* Backstage conceptual pipeline — editorial, not live data */}
            <Reveal delay={0.24} className="mt-14">
              <div className="panel-2 max-w-[860px] overflow-hidden">
                <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                  <span className="mono-cell text-[10px] uppercase tracking-[0.14em] text-faint">assessment pipeline</span>
                  <span className="flex items-center gap-1.5 text-[10px] text-faint">
                    <span className="dot dot-ok" aria-hidden="true" /> conceptual
                  </span>
                </div>
                <div className="flex flex-wrap items-stretch gap-y-1 px-1.5 py-3">
                  {CYBER_HEAD.map(([label, sub], i) => (
                    <React.Fragment key={label}>
                      <div className="flex min-w-[88px] flex-1 flex-col gap-1 rounded-xl px-2.5 py-2 transition-colors duration-500 ease-spring hover:bg-surface-2">
                        <span className="text-[10.5px] font-semibold text-text">{label}</span>
                        <span className="mono-cell text-[8.5px] uppercase tracking-[0.12em] text-faint">{sub}</span>
                      </div>
                      {i < CYBER_HEAD.length - 1 && (
                        <ArrowRight className="my-auto h-3 w-3 shrink-0 text-accent/60" strokeWidth={1.5} aria-hidden="true" />
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ==================== PRODUCT FLOW / BENTO ==================== */}
        <section id="flow" className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
          <Reveal>
            <p className="eyebrow mb-4">Product flow</p>
            <h2 className="mb-10 max-w-[24ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
              One authorized surface. One traceable pipeline. Zero blind spots.
            </h2>
          </Reveal>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {PIPELINE.map((s, i) => (
              <Reveal key={s.label} delay={0.05 * i} className="h-full">
                <div className="group flex h-full flex-col rounded-2xl border border-line bg-surface p-5 transition-[border-color,background-color,transform] duration-500 ease-spring hover:border-accent/40 hover:bg-surface-2">
                  <s.icon className="h-5 w-5 text-accent" strokeWidth={1.5} aria-hidden="true" />
                  <span className="mono-cell mt-4 text-[9px] uppercase tracking-[0.14em] text-faint">0{i + 1}</span>
                  <h3 className="mt-1 text-[14px] font-semibold text-text">{s.label}</h3>
                  <p className="mt-1.5 text-[11.5px] leading-relaxed text-muted">{s.copy}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ==================== ATTACK SURFACE ==================== */}
        <section id="surface" className="border-y border-line bg-bg-2">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4">Attack surface</p>
              <h2 className="mb-4 max-w-[26ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                Inventory everything you expose.
              </h2>
              <p className="mb-10 max-w-[56ch] text-[12.5px] leading-relaxed text-muted">
                CyberAgent inventories authorized scope from real tool output. If a service
                is listening, it becomes observable. If it is observed, it can become evidence.
              </p>
            </Reveal>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {SURFACE.map((card, i) => (
                <Reveal key={card.title} delay={0.05 * i}>
                  <div className="flex h-full flex-col rounded-2xl border border-line bg-surface-2 p-5">
                    <h3 className="text-[13.5px] font-semibold text-text">{card.title}</h3>
                    <p className="mt-1.5 flex-1 text-[11.5px] leading-relaxed text-muted">{card.copy}</p>
                    <div className="mt-4 flex flex-wrap gap-1.5">
                      {card.tags.map((t) => (
                        <span key={t} className="mono-cell rounded-full border border-line px-2.5 py-1 text-[9px] uppercase tracking-[0.1em] text-faint">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* ==================== WORLD MONITOR ==================== */}
        <section id="monitor" className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
          <Reveal>
            <p className="eyebrow mb-4 flex items-center gap-2">
              <Globe className="h-3.5 w-3.5 text-accent" strokeWidth={1.5} aria-hidden="true" />
              World Monitor
            </p>
            <h2 className="mb-12 max-w-[24ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
              The operational picture is also an assessment source.
            </h2>
          </Reveal>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
            {WORLD_MONITOR.map((w, i) => (
              <Reveal key={w.label} delay={0.05 * i}>
                <div className="h-full rounded-2xl border border-line bg-surface p-5">
                  <span className="mono-cell text-[9px] uppercase tracking-[0.14em] text-accent">{w.label}</span>
                  <p className="mt-2 text-[11.5px] leading-relaxed text-muted">{w.copy}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ==================== EVIDENCE CHAIN ==================== */}
        <section id="evidence" className="border-t border-line bg-bg-2">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4">Evidence chain</p>
              <h2 className="mb-12 max-w-[26ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                Observation before evidence. Evidence before findings.
              </h2>
            </Reveal>
            <div className="space-y-4">
              {EVIDENCE_CHAIN.map((n, i) => (
                <Reveal key={n.label} delay={0.04 * i}>
                  <div className="flex items-start gap-4 rounded-2xl border border-line bg-surface p-5">
                    <span className="mono-cell mt-0.5 text-[10px] text-accent">0{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <h3 className="text-[13.5px] font-semibold text-text">{n.label}</h3>
                      <p className="mt-0.5 whitespace-pre-line text-[11.5px] leading-relaxed text-muted">{n.copy}</p>
                    </div>
                    {i < EVIDENCE_CHAIN.length - 1 && (
                      <ArrowRight className="mt-1 h-4 w-4 shrink-0 text-accent/50" strokeWidth={1.5} aria-hidden="true" />
                    )}
                  </div>
                </Reveal>
              ))}
            </div>
            <Reveal delay={0.1}>
              <div className="mt-8 rounded-2xl border border-line bg-surface-2 p-5">
                <p className="eyebrow mb-3">Report traceability</p>
                <div className="flex flex-col gap-2">
                  {REPORT_TRACE.map((r) => (
                    <span key={r} className="mono-cell text-[11px] text-muted">{r}</span>
                  ))}
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ==================== CTA ==================== */}
        <section className="border-t border-line">
          <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-6 px-5 py-16 md:flex-row md:items-center md:px-8 md:py-24">
            <Reveal>
              <h2 className="max-w-[20ch] text-[clamp(1.7rem,3.6vw,2.8rem)] font-semibold tracking-[-0.03em]">
                Start assessing what you expose.
              </h2>
            </Reveal>
            <Reveal delay={0.08}>
              <div className="flex flex-wrap gap-3">
                <Button variant="primary" onClick={() => navigate('/auth?mode=signup')}>
                  Get started
                  <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                </Button>
                <Button variant="outline" onClick={() => navigate('/auth')}>
                  Sign in
                </Button>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      {/* ==================== FOOTER ==================== */}
      <footer className="border-t border-line px-5 py-10 md:px-8">
        <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2.5">
            <Radar className="h-4 w-4 text-accent" strokeWidth={1.5} aria-hidden="true" />
            <span className="text-[12px] font-semibold text-text">CyberAgent</span>
            <span className="eyebrow">&middot; authorized assessment</span>
          </div>
          <p className="text-[11px] text-faint">
            Assess what you expose. Trace what you observe. Report what you can prove.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
