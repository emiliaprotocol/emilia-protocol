// SPDX-License-Identifier: Apache-2.0
// EP for insurers - verifiable proof a human authorized the transfer.
// Funds-transfer-fraud / social-engineering / agentic-AI risk landing page.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const BROKE = [
  {
    label: 'Deepfakes defeat the callback',
    body: 'The out-of-band call-back was the gold-standard proof of authorization. '
      + 'Now the "known number" can reach a voice-cloned executive (the Arup $25.6M '
      + 'case). The control you mandate no longer proves a real human authorized anything.',
  },
  {
    label: 'AI agents break attribution',
    body: 'Autonomous agents move money at machine speed. "The AI did it" is foreclosed '
      + '(California AB 316 pins liability on the deployer) exactly when the deployer can '
      + 'least prove who authorized the action. Underwriters cannot audit a model the way '
      + 'they audit a firewall.',
  },
];

const PILOT = [
  ['For the insured',
    'Run EMILIA in observe mode on one workflow (vendor bank-account changes over a '
    + 'threshold). Every flagged action emits a receipt your underwriter - or the '
    + 'insured’s auditor - verifies offline. The attestation becomes provable, '
    + 'claims-ready evidence.'],
  ['For the carrier',
    'Accept EMILIA receipts as proof the dual-authorization / verification control was '
    + 'followed - a premium credit or coverage condition that is, for the first time, '
    + 'machine-auditable rather than reconstructed forensically, and that survives the '
    + 'deepfake failure mode your actuaries are now pricing.'],
];

const FAQ = [
  ['How is this different from our existing dual-authorization requirement?',
    'It is the same control, made provable. Instead of reconstructing whether a callback '
    + 'happened from recorded calls and emails after a loss, you get a cryptographic '
    + 'receipt: a named human signed the exact action (amount, payee, account) on their '
    + 'own device, verifiable offline by anyone.'],
  ['Why is it deepfake-proof?',
    'The approval is a hardware-held signature over the exact action, not a phone '
    + 'conversation. A cloned voice cannot produce the signature, so EP-QUORUM (the '
    + 'two-person rule) cannot be defeated the way a callback can.'],
  ['Is it vendor lock-in?',
    'No. EMILIA Protocol is an open standard (Apache-2.0) published as IETF Internet-Drafts, '
    + 'with independent verifiers in three languages. Carrier and insured can verify '
    + 'receipts with open-source code, with no account and no trust in EMILIA.'],
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(([q, a]) => ({
    '@type': 'Question',
    name: q,
    acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

export default function InsurancePage() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <SiteNav activePage="Insurance" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>CYBER · CRIME / FIDELITY · AGENTIC-AI RISK</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 900 }}>
            Verifiable proof a human authorized the transfer.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            Your policies make dual authorization and out-of-band verification of wires and
            payment-instruction changes conditions precedent to funds-transfer-fraud cover.
            You deny claims and rescind policies when those controls were not followed - yet
            the proof today is ad hoc, reconstructed forensically after a loss. There is no
            machine-checkable artifact that a specific human authorized a specific transfer.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            EMILIA turns that control into a cryptographic, offline-verifiable authorization
            receipt - and a two-person rule a cloned voice cannot defeat.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href="/pilot?v=insurance" style={cta.primary}>Scope an observe-mode pilot</a>
            <a href="/briefs/emilia-insurance-onepager.pdf" style={cta.secondary}>Read the one-pager (PDF)</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>TWO THINGS JUST BROKE THE OLD CONTROL</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            The callback you require no longer proves authorization.
          </h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
            {BROKE.map((c) => (
              <div key={c.label} style={{ ...styles.card, padding: 24, borderTop: `3px solid ${color.gold}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>
                  {c.label}
                </div>
                <div style={{ ...styles.cardBody, marginTop: 12, fontSize: 15, lineHeight: 1.7 }}>{c.body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>WHAT EMILIA PROVIDES</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>An authorization receipt.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Before a transfer or instruction change executes, a named human approves the
            exact action - amount, payee, account - on their own device (passkey / Face ID),
            producing a signed artifact anyone can verify offline, with no account and no
            trust in the insured&rsquo;s systems. Alter one byte and it fails. EP-QUORUM binds
            two distinct, device-bound humans to the action - cryptographic dual control that
            a cloned voice cannot defeat. The portable receipt is the claims-ready artifact you
            reconstruct by hand today, verifiable years later without the insured&rsquo;s
            cooperation.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8, fontSize: 15, color: color.t2 }}>
            Try it in 30 seconds, offline, no account:{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npx @emilia-protocol/crash-test</span>
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE PILOT</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Observe one workflow. Prove the control.</h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
            {PILOT.map(([label, body]) => (
              <div key={label} style={{ ...styles.card, padding: 24 }}>
                <div style={{ ...styles.h3, fontSize: 22, marginBottom: 8 }}>{label}</div>
                <div style={{ ...styles.cardBody, fontSize: 15, lineHeight: 1.7 }}>{body}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 30 }}>
            <a href="/pilot?v=insurance" style={cta.primary}>Start a conversation</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>FREQUENTLY ASKED</div>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
              <div style={{ ...styles.h3, fontSize: 18, marginBottom: 6 }}>{q}</div>
              <p style={{ ...styles.body, margin: 0, fontSize: 15, maxWidth: 760 }}>{a}</p>
            </div>
          ))}
        </section>

        <section style={styles.section}>
          <p style={{ fontSize: 13, color: color.t3, maxWidth: 760, lineHeight: 1.6 }}>
            EMILIA proves a named human (or quorum) authorized this exact action before it
            executed. It does not prove the decision was correct, nor establish real-world
            identity beyond the enrollment layer. Open standard (Apache-2.0), IETF
            Internet-Drafts; no production deployment claim implied.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
