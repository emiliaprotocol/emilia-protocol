// SPDX-License-Identifier: Apache-2.0
// /proof-vs-measurement — the regulatory-buyer differentiation cut for EU AI Act
// Article 14: a cryptographic authorization receipt (proof) vs an oversight score
// or dashboard (measurement). Out-clarifies the "evidence" category without naming
// any competitor. Cross-links the broader /human-control thesis + the live demo.

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'Proof, not measurement — EMILIA & EU AI Act Article 14 | EMILIA',
  description:
    'For Article 14 human oversight, a cryptographic authorization receipt can provide independently verifiable evidence that a pinned approver key authorized the exact action. It is one input to an oversight assessment, not compliance by itself.',
};

const ROWS = [
  ['Artifact', 'A number or narrative about the review', 'A cryptographic proof of the authorization itself'],
  ['Evidence', 'Statistical / behavioral — an indicator', 'A signature over the canonical, structured action'],
  ['What it binds', 'How attentive the reviewer probably was', 'A pinned approver key → an exact action, pre-execution'],
  ['Non-participant verification', 'Usually requires the operator’s records or service', 'Offline with pinned trust inputs; no issuer service at verification time'],
  ['Enforcement', 'Advisory — scores after the fact', 'Fail-closed — no receipt, no execution'],
  ['Tamper response', 'Depends on the operator’s logging controls', 'A forged or altered authorization fails cryptographic verification'],
];

const PROVIDES = [
  ['An artifact an assessor can independently check', 'Deterministic verification with pinned public keys; the authorization binding can be reproduced without the issuer’s service.'],
  ['Signed evidence of an override or intervention', 'Approve, decline, or stop captured as a signed, tamper-evident, per-action artifact — not only a database assertion.'],
  ['Enforcement, not exhortation', '428 — no receipt, no execution on the routed path. A deployment must still identify and control bypass paths.'],
  ['Two-person control where stakes demand it', 'Quorum receipts (a cryptographic two-person rule) + scoped delegation with verify-time constraint enforcement.'],
  ['Built from established primitives', 'Ed25519 (RFC 8032), JCS (RFC 8785), and WebAuthn for Class-A signoff. Active individual IETF Internet-Drafts; Apache-2.0 reference code.'],
];

export default function ProofVsMeasurementPage() {
  return (
    <>
      <SiteNav activePage="Standards" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 22 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EU AI ACT · ARTICLE 14 · ANNEX III 2 DEC 2027</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>Proof, not measurement.</h1>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16, fontStyle: 'italic', color: color.t2 }}>
              Decision logs are testimony. Scores are opinion. Receipts are evidence.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              Article 14 requires high-risk AI systems to be under <b>effective human oversight</b> — a person must be able to
              decline an output, <b>override</b> it, and <b>stop</b> the system. When a regulator, court, or insurer later asks the
              evidence question — <i>&ldquo;show me the authorization evidence for this exact action before it ran&rdquo;</i> — many
              oversight systems can answer only from operator-controlled records.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
              <a href="/briefs/emilia-article-14-proof-vs-measurement.pdf" target="_blank" rel="noopener noreferrer" style={cta.primary}>Download the one-pager (PDF)</a>
              <Link href="/try/receipt-required" style={cta.secondary}>See a receipt enforced</Link>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>What most &ldquo;oversight&rdquo; tooling actually produces</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 10 }}>
              A typical <b>decision log</b> — operator-controlled testimony whose evidential value depends on its controls. An <b>oversight score or dashboard</b> — a
              heuristic rating of how attentive the reviewer <i>probably</i> was, over self-reported telemetry; an opinion <i>about</i>
              the human, not a binding <i>of</i> the human to the act. A <b>&ldquo;human-in-the-loop&rdquo; toggle</b> — proof a step
              existed, not that a named person authorized <i>this</i> action. Having a human in the loop is not proof the human
              exercised authority over a specific irreversible act. Article 14 is about the latter.
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>The bright line: measurement vs. proof</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 10 }}>
              Evidence of oversight can do two things a score cannot: <b>bind</b> an enrolled approver key to an exact action before
              it ran, and support <b>non-participant verification</b> — reproducible offline with the relying party&rsquo;s pinned trust
              inputs, without calling the issuer&rsquo;s service.
            </p>
            <div style={{ marginTop: 12 }}>
              <div style={{ display: 'flex', gap: 14, padding: '8px 0', borderBottom: `1px solid ${color.border}` }}>
                <span style={{ flex: '0 0 150px', fontFamily: font.mono, fontSize: 11, color: color.t3, textTransform: 'uppercase' }}>&nbsp;</span>
                <span style={{ flex: 1, fontSize: 12.5, color: color.t3, fontFamily: font.mono }}>Oversight score / dashboard / log</span>
                <span style={{ flex: 1, fontSize: 12.5, color: color.gold, fontFamily: font.mono, fontWeight: 700 }}>EMILIA authorization receipt</span>
              </div>
              {ROWS.map(([k, a, b]) => (
                <div key={k} style={{ display: 'flex', gap: 14, padding: '10px 0', borderBottom: `1px solid ${color.border}` }}>
                  <span style={{ flex: '0 0 150px', fontSize: 13, color: color.t1, fontWeight: 600 }}>{k}</span>
                  <span style={{ flex: 1, fontSize: 13, color: color.t2 }}>{a}</span>
                  <span style={{ flex: 1, fontSize: 13, color: color.t1, fontWeight: 600 }}>{b}</span>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14 }}>
              A score describes an oversight process. A valid receipt establishes a narrower fact: a pinned key authorized the
              exact action under the verified policy context. A Gate can require that fact before execution. Identity enrolment,
              authority, comprehension, and legal adequacy remain separate questions.
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>What EMILIA provides for Article 14</h2>
            <div style={{ marginTop: 8 }}>
              {PROVIDES.map(([h, b]) => (
                <div key={h} style={{ padding: '11px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ ...styles.body, fontSize: 14.5, color: color.t1, fontWeight: 700 }}>{h}</div>
                  <div style={{ ...styles.body, fontSize: 13.5, color: color.t2, marginTop: 3 }}>{b}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
              <Link href="/human-control" style={cta.primary}>The meaningful-human-control thesis</Link>
              <Link href="/fire-drill/rr-1" style={cta.secondary}>RR-1 maintainer credential</Link>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 760 }}>
              Honest scope: a receipt is <b>necessary in some designs, never sufficient by itself</b>. It proves that the
              pinned approver key signed the exact action under the verified context; the strength of the human attribution
              depends on enrolment and authenticator assurance. It does not prove the decision was wise, lawful, understood,
              or adequate under Article 14. Engineering and standards material, not legal advice.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
