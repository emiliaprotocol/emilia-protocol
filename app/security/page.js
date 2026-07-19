'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { ENTITY, COMPLIANCE_ROADMAP, isPlaceholder } from '@/lib/site-config';
import proofStats from '@/lib/proof-stats.json';

const TEST_CASES = Number(proofStats.tests.total).toLocaleString('en-US');
const TEST_FILES = Number(proofStats.tests.files).toLocaleString('en-US');
const SECURITY_CLAIMS = proofStats.securityCase.claims;
const SECURITY_EVIDENCE_FILES = proofStats.securityCase.evidenceFiles;
const TAMARIN_OBLIGATIONS = proofStats.tamarin.verifiedObligations;
const TAMARIN_ATTACK_TRACES = proofStats.tamarin.deliberatelyUnsafeCounterexamples;
const CONFORMANCE_VECTORS = proofStats.conformance.vectors;
const CONFORMANCE_SUITES = proofStats.conformance.suites;
const HOSTILITY_CASES = proofStats.externalImplementation.hostilityCases;

const ENGINEERING_EVIDENCE = [
  { value: TAMARIN_OBLIGATIONS, label: 'Composed Tamarin obligations', detail: `${TAMARIN_ATTACK_TRACES} deliberately unsafe variants yield traces` },
  { value: SECURITY_CLAIMS, label: 'Executable security claims', detail: `${SECURITY_EVIDENCE_FILES} hashed evidence files` },
  { value: CONFORMANCE_VECTORS, label: 'Current conformance vectors', detail: `${CONFORMANCE_SUITES} suites; same-team JS, Python, Go ports` },
  { value: HOSTILITY_CASES, label: 'External hostility cases', detail: 'Pinned externally authored Rust implementation' },
  { value: TEST_CASES, label: 'Automated test cases', detail: `${TEST_FILES} files; applicable cases pass` },
];

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
        <h1 className="ep-hero-text" style={styles.h1}>Security claims you can execute</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          EMILIA is implemented security infrastructure, not merely an architecture proposal. Its
          current machine-verifiable case joins {SECURITY_CLAIMS} executable claims, a composed
          Tamarin adversary model, cross-language negative vectors, fault-schedule testing, and
          byte-pinned release evidence. Every engineering count on this page comes from generated
          repository evidence.
        </p>
        <div className="ep-hero-text" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="/proof" className="ep-cta" style={cta.primary}>Inspect the engineering evidence</a>
          <a href="/.well-known/emilia-context.json" className="ep-cta-secondary" style={cta.secondary}>Read the machine context</a>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 64 }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))',
          borderTop: `1px solid ${color.border}`,
          borderBottom: `1px solid ${color.border}`,
        }}>
          {ENGINEERING_EVIDENCE.map((item) => (
            <div key={item.label} style={{ padding: '24px 20px 24px 0' }}>
              <div style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, color: color.gold, lineHeight: 1, marginBottom: 8 }}>{item.value}</div>
              <div style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, lineHeight: 1.45 }}>{item.label}</div>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, lineHeight: 1.5, marginTop: 5 }}>{item.detail}</div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Shipped</h2>
        <p className="ep-reveal" style={styles.body}>
          Each item below is verifiable today — reproducible by anyone from the public repo or directly inspectable on this site.
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
          {COMPLIANCE_ROADMAP.inProgress.map((c, i) => {
            const targetText = isPlaceholder(c.target)
              ? 'Target window: pending engagement gate (named auditor + funded scope)'
              : `Target: ${c.target}`;
            const auditorText = !isPlaceholder(c.auditor) ? ` · ${c.auditor}` : '';
            return (
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
                  {targetText}{auditorText}
                </div>
              </div>
            );
          })}
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
          The strongest result is compositional: one Tamarin Dolev-Yao model follows a signed
          challenge through CAID, two distinct approvals, issuer and authority pins, an exact
          registry view, revocation, one-time consumption, and execution. It verifies
          {' '}{TAMARIN_OBLIGATIONS} obligations under its stated assumptions.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The model also keeps {TAMARIN_ATTACK_TRACES} intentionally weakened comparison obligations.
          Remove consumption and Tamarin finds same-receipt replay. Stop pinning the exact registry
          head and epoch and it finds a stale or equivocating authority-view acceptance. Those
          counterexamples demonstrate that the controls are load-bearing rather than decorative.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Separately, TLA+ checks {proofStats.tla.invariants} authorization-state invariants and
          Alloy checks {proofStats.alloy.facts} facts plus {proofStats.alloy.assertions} assertions.
          These models run in CI alongside executable negative vectors. A model failure or security-case
          mismatch fails the build; the proof record lives beside the implementation, not in a detached paper.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/proof" className="ep-cta-secondary" style={cta.secondary}>Read the evidence map</a>
          <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/formal/tamarin" className="ep-cta-ghost" style={cta.ghost}>Inspect the Tamarin models →</a>
          <a href="/blog/how-formal-verification-works-for-protocols" className="ep-cta-ghost" style={cta.ghost}>How verification works →</a>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the proofs do &mdash; and don&rsquo;t &mdash; cover</h2>
        <p className="ep-reveal" style={styles.body}>
          A guarantee you have to overstate isn&rsquo;t one. So, precisely:
        </p>
        <p className="ep-reveal" style={styles.body}>
          <strong style={{ color: color.t1 }}>What they prove.</strong> Protocol-level safety: a signoff is bound to the exact action, can&rsquo;t be replayed or forged, can&rsquo;t self-approve, and the receipt is tamper-evident. No actor following the protocol can authorize an action that wasn&rsquo;t approved by an accountable, named human.
        </p>
        <p className="ep-reveal" style={styles.body}>
          <strong style={{ color: color.t1 }}>What they do not prove &mdash; stated plainly:</strong>
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Not a proof of model behavior.</strong> The theorems constrain what the protocol <em>allows</em>, not what an AI model <em>attempts</em>. They say nothing about whether an LLM makes good decisions &mdash; only that a bad one still can&rsquo;t cross the gate without an accountable yes.</li>
          <li><strong style={{ color: color.t1 }}>Not a proof of deployment.</strong> If the gate runs inside a process the agent&rsquo;s operator fully controls, that operator can route around it &mdash; true of any in-process check. The enforcement guarantee is end-to-end only when the <em>system of record</em> (the bank API, the benefits system, the deploy pipeline) verifies the authorization receipt (formerly Trust Receipt) before it executes. Until that integration exists, EMILIA is a strong default and an offline-verifiable evidence layer &mdash; not a physical barrier.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          We lead with this because it&rsquo;s the first question a serious reviewer asks &mdash; and because the receipt is trustworthy precisely to the extent that we&rsquo;re exact about what it attests.
        </p>
        <div className="ep-reveal" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/THREAT_MODEL.md" className="ep-cta-secondary" style={cta.secondary}>Full threat model &amp; trust assumptions &rarr;</a>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Responsible disclosure</h2>
        <p className="ep-reveal" style={styles.body}>
          Security findings on the protocol, the reference runtime, the SDKs (<code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>@emilia-protocol/sdk</code>, <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>@emilia-protocol/verify</code>), the MCP server, or any *.emiliaprotocol.ai surface should be reported privately first.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Email: <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue, textDecoration: 'none' }}>{ENTITY.securityEmail}</a></li>
          <li>Disclosure metadata: <a href="/.well-known/security.txt" style={{ color: color.blue, textDecoration: 'none' }}>/.well-known/security.txt</a> (RFC 9116). Encrypted reports are accepted; request our PGP key in your initial email and we will respond with the fingerprint before you send sensitive details.</li>
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
          <li>CI gating: lint, type-check, unit tests, integration tests against Postgres, semgrep, CodeQL, npm audit, secret scanning, formal-verification suite, and conformance suite — all wired in CI.</li>
          <li>Dependencies: Dependabot enabled with auto-merge for vetted minor + patch upgrades.</li>
          <li>Cryptography: Ed25519 for receipt signatures, ECDSA P-256 (WebAuthn) for device signoffs, SHA-256 over deterministic (sorted-key) canonical JSON for action hashing, Merkle batching for trust-receipt anchoring. No custom crypto primitives.</li>
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
