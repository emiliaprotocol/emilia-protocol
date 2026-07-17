// SPDX-License-Identifier: Apache-2.0
// EMILIA · European Digital Sovereignty — a public-sector / policymaker landing page.
// Frames the authorization-receipt layer as one inspectable Article 14 input that
// European institutions can verify under trust inputs they control.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const PILLARS = [
  {
    who: 'Article 14 evidence that can be checked',
    val: 'The Act requires effective human oversight but does not prescribe one universal receipt format. EMILIA provides a portable, tamper-evident authorization artifact relevant to an Article 14 assessment and Article 12 logging. It can compose with European identity and trust services without replacing them.',
  },
  {
    who: 'Institution-held verification',
    val: 'A European institution can verify the artifact offline using its own pinned keys and policy, without calling the operator or EMILIA at verification time. The software is open (Apache-2.0) and self-hostable; the institution retains both the evidence and its trust configuration.',
  },
  {
    who: 'A guarantee for citizens',
    val: 'When automation touches a citizen’s benefits, records, money, or rights, a deployer can require action-bound authorization from an enrolled person before execution. The receipt makes that authorization inspectable; it does not guarantee the decision was correct, lawful, or adequately overseen.',
  },
  {
    who: 'Shape the open specification',
    val: 'EMILIA is published through individual IETF Internet-Drafts, running code, and public conformance vectors. European institutions can test and shape the technical property without depending on EMILIA as a hosted vendor.',
  },
];

const STEPS = [
  { n: '1', title: 'Authorize', body: 'Before an AI agent takes a consequential action — moving funds, changing an official record, cutting a service — an enrolled human (or a policy-required quorum) signs that exact action with an approved authenticator.' },
  { n: '2', title: 'Gate', body: 'The action is refused unless a valid, in-scope authorization is present. No receipt, no execution — fail-closed by design, with self-approval rejected (separation of duties).' },
  { n: '3', title: 'Verify', body: 'A regulator, auditor, or court can verify the signature and action binding offline against pinned keys, without the issuing service or EMILIA. The strength of the human attribution still depends on enrolment and key governance.' },
];

export default function SovereigntyPage() {
  return (
    <>
      <SiteNav activePage="Sovereignty" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA · EUROPEAN DIGITAL SOVEREIGNTY</div>
            <h1 style={{ ...styles.h1, marginTop: 16, maxWidth: 860 }}>
              Verifiable human authority over AI — held in Europe, not in a foreign cloud.
            </h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              AI agents are starting to take irreversible actions — moving money, changing official
              records, cutting off services. EMILIA is an open evidence layer for showing that an
              enrolled approver key authorized an exact action, checkable offline by a European
              institution without depending on the operator&apos;s live service.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              It gives an Article 14 assessment a verifiable action-level artifact.{' '}
              <span style={{ color: color.gold }}>Europe holds the proof, not Big Tech.</span>
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="#why" style={cta.primary}>Why it matters for Europe</a>
              <a href="/briefs/emilia-eu-ai-oversight-onepager.pdf" style={cta.secondary}>Download the one-page brief</a>
              <a href="mailto:team@emiliaprotocol.ai" style={cta.secondary}>Request a briefing</a>
            </div>
          </div>
        </section>

        {/* The gap */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE GAP</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 820 }}>
              Human oversight needs evidence stronger than &quot;trust our dashboard.&quot;
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              When an autonomous system acts, the record that a named human authorized{' '}
              <em>that exact</em> action — at the right scope, currently, under the right authority —
              is today a log the operator keeps and could alter, backfill, or rubber-stamp. That
              operator is often a non-European hyperscaler. <span style={{ color: color.t1 }}>The
              accountability may exist in process, but remain difficult for an independent party to check.</span>
            </p>
          </div>
        </section>

        {/* How it works */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HOW IT WORKS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Authorize → gate → verify.</h2>
            <div style={{ marginTop: 32 }}>
              {STEPS.map((s) => (
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{s.n}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 18 }}>{s.title}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 700 }}>{s.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Why it matters for Europe */}
        <section id="why" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHY IT MATTERS FOR EUROPE</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Four things that make this undeniable.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {PILLARS.map((p) => (
                <div key={p.who} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ ...styles.h3, fontSize: 17 }}>{p.who}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{p.val}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Honest posture */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HONEST POSTURE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>
              EMILIA verifies authorization evidence — not legal or human adequacy.
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              A valid receipt establishes that a pinned key signed an exact action under a stated
              context. It does not establish that the key was properly enrolled, the signer understood
              the display, the action was lawful, or the full oversight design was proportionate.
              The core formats, verifier, and reference implementation are open and self-hostable.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="mailto:team@emiliaprotocol.ai" style={cta.primary}>Request a briefing</a>
              <a href="/briefs/emilia-eu-ai-oversight-onepager.pdf" style={cta.secondary}>Download policymaker brief</a>
              <a href="/govguard" style={cta.secondary}>For public institutions</a>
              <a href="/verify" style={cta.secondary}>Verify a receipt</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
