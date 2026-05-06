'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { ENTITY, COMPLIANCE_ROADMAP } from '@/lib/site-config';

export default function SecurityPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const STATUS_COLOR = {
    shipped: color.green,
    planned: color.gold,
    intent: color.t3,
  };

  return (
    <div style={styles.page}>
      <SiteNav activePage="Trust" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge">Trust &amp; Security</div>
        <h1 className="ep-hero-text" style={styles.h1}>Security posture, transparently</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Procurement teams cannot evaluate a vendor without a real picture of where the security and compliance work stands today and where it is sequenced next. This page lists what is shipped, what is funded and in progress, and what is intent. We update it as commitments change. We never publish target dates we cannot hit.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Shipped</h2>
        <p className="ep-reveal" style={styles.body}>
          Each item below is verifiable today — independently reproducible from the public repo or directly inspectable on this site.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {COMPLIANCE_ROADMAP.current.map((c, i) => (
            <div key={i} style={{
              border: `1px solid ${color.border}`,
              borderLeft: `3px solid ${STATUS_COLOR.shipped}`,
              borderRadius: radius.base,
              padding: '14px 18px',
              background: '#FAFAF9',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 16,
              flexWrap: 'wrap',
            }}>
              <div style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1, flex: '1 1 auto' }}>
                {c.item}
              </div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>
                {c.evidence.startsWith('http') || c.evidence.startsWith('/') ? (
                  <a href={c.evidence.startsWith('http') ? c.evidence : c.evidence} target={c.evidence.startsWith('http') ? '_blank' : undefined} rel="noopener noreferrer" style={{ color: color.blue, textDecoration: 'none' }}>{c.evidence}</a>
                ) : c.evidence}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>In progress</h2>
        <p className="ep-reveal" style={styles.body}>
          Funded or actively being scoped. Each item shows the target window and named partner where committed; items without a named auditor or sponsor are flagged as such — we believe a missed target is more damaging than no target.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {COMPLIANCE_ROADMAP.inProgress.map((c, i) => (
            <div key={i} style={{
              border: `1px solid ${color.border}`,
              borderLeft: `3px solid ${STATUS_COLOR.planned}`,
              borderRadius: radius.base,
              padding: '14px 18px',
              background: '#FAFAF9',
            }}>
              <div style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1, marginBottom: 4 }}>
                {c.item}
              </div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>
                Target: {c.target}{c.auditor ? ` · ${c.auditor}` : ''}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Intent</h2>
        <p className="ep-reveal" style={styles.body}>
          Targeted certifications and frameworks sequenced against named pilot or sponsor engagement. We treat these as commitments to pursue when the corresponding buyer relationship is real, not as marketing claims.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {COMPLIANCE_ROADMAP.intent.map((c, i) => (
            <div key={i} style={{
              border: `1px solid ${color.border}`,
              borderLeft: `3px solid ${STATUS_COLOR.intent}`,
              borderRadius: radius.base,
              padding: '14px 18px',
              background: '#FAFAF9',
            }}>
              <div style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1, marginBottom: 4 }}>
                {c.item}
              </div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>{c.note}</div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Formal verification</h2>
        <p className="ep-reveal" style={styles.body}>
          The protocol is mathematically modeled in TLA+ and Alloy. The TLA+ specification declares 26 theorems covering safety and liveness — handshake binding integrity, replay resistance, signoff accountability, receipt integrity, federation consistency. The Alloy model declares 35 facts and 15 assertions covering structural invariants the TLA+ time-domain doesn't reach.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Both run on every push in CI. A counterexample fails the build. The model is part of the codebase, not a paper attached to it.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the spec</a>
          <a href="/blog/how-formal-verification-works-for-protocols" className="ep-cta-ghost" style={cta.ghost}>How verification works →</a>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Responsible disclosure</h2>
        <p className="ep-reveal" style={styles.body}>
          Security findings on the protocol, the reference runtime, the SDKs (<code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>@emilia-protocol/sdk</code>, <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>@emilia-protocol/verify</code>), the MCP server, or any *.emiliaprotocol.ai surface should be reported privately first.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Email: <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue, textDecoration: 'none' }}>{ENTITY.securityEmail}</a></li>
          <li>Encryption: PGP key fingerprint published at <a href="/.well-known/security.txt" style={{ color: color.blue, textDecoration: 'none' }}>/.well-known/security.txt</a></li>
          <li>Acknowledgement: within 48 hours.</li>
          <li>Coordination: minimum 90-day embargo on disclosure for any finding requiring a coordinated patch; we publish the advisory + credit on resolution.</li>
          <li>Safe harbor: we will not pursue legal action against good-faith research that follows this disclosure process and avoids privacy violations, data destruction, or service degradation.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          A formal bug-bounty program (HackerOne or Immunefi) is in roadmap. Until launched, the address above is monitored and triaged.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Operational practices</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li>Source control: GitHub with required code review + signed commits on the reference runtime.</li>
          <li>CI gating: lint, type-check, unit tests, integration tests against Postgres, semgrep, CodeQL, npm audit, secret scanning, formal-verification suite, and conformance suite — all required for merge.</li>
          <li>Dependencies: Dependabot enabled with auto-merge for vetted minor + patch upgrades.</li>
          <li>Cryptography: Ed25519 for signoff signatures, BLAKE3 for action-context hashing, Merkle batching for trust-receipt anchoring. No custom crypto primitives.</li>
          <li>Secrets handling: no production secrets in source; secrets stored in Vercel + Supabase secret managers with least-privilege scoped roles.</li>
          <li>Data minimization: trust receipts contain only the bound action context and signatures; no PII unless an integrator's policy explicitly includes it (and that integrator's DPA governs that data).</li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Procurement &amp; assurance documents</h2>
        <p className="ep-reveal" style={styles.body}>
          Requestable under NDA for active procurement engagements:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Filled Shared Assessments SIG Lite questionnaire</li>
          <li>Sub-processor list (also public at <a href="/legal/sub-processors" style={{ color: color.blue, textDecoration: 'none' }}>/legal/sub-processors</a>)</li>
          <li>DPA template (also public at <a href="/legal/privacy" style={{ color: color.blue, textDecoration: 'none' }}>/legal/privacy</a> as the working version)</li>
          <li>Incident-response playbook</li>
          <li>Business-continuity / disaster-recovery summary</li>
          <li>Penetration-test summary letter (once external review is complete)</li>
          <li>NIST 800-53 Rev. 5 control mapping</li>
          <li>FFIEC IT Examination Handbook alignment notes (FinGuard) and OMB Circular A-123 alignment notes (GovGuard)</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          Request via <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue, textDecoration: 'none' }}>{ENTITY.securityEmail}</a>.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Talk to us</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href={`mailto:${ENTITY.securityEmail}`} className="ep-cta" style={cta.primary}>Email security</a>
          <a href="/legal/privacy" className="ep-cta-secondary" style={cta.secondary}>Privacy policy</a>
          <a href="/legal/sub-processors" className="ep-cta-ghost" style={cta.ghost}>Sub-processors →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
