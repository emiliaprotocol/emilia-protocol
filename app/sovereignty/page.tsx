// SPDX-License-Identifier: Apache-2.0
// EMILIA · European Digital Sovereignty — a public-sector / policymaker landing page.
// Frames the authorization-receipt layer as EU AI Act Art. 14 made verifiable, held
// in Europe, without dependence on foreign hyperscalers.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const PILLARS = [
  {
    who: 'EU AI Act Article 14, made verifiable',
    val: 'The Act requires human-oversight measures for high-risk AI but does not prescribe one universal proof artifact. EMILIA offers an open, portable receipt profile that an independent party can verify under pinned inputs. It can support Article 12 logging and Article 14 oversight evidence without claiming legal compliance by itself.',
  },
  {
    who: 'Sovereignty by construction',
    val: 'Verification needs no trust in the operator and no foreign cloud. The proof is self-contained and checkable offline, on European soil, by European institutions. The software is open (Apache-2.0) and self-hostable - no dependence on, and no lock-in to, non-European hyperscalers. Europe holds the proof.',
  },
  {
    who: 'A guarantee for citizens',
    val: 'For a fully mediated action class, public institutions can require a named or quorum decision before the integrated executor acts, then preserve evidence another party can inspect. The institution defines the policy and keeps the trust roots.',
  },
  {
    who: 'Lead the standard, do not import it',
    val: 'EMILIA is being contributed through open IETF Internet-Drafts, with running code and conformance tests. Europe can be an early author of the accountability standard the world will need - rather than adopting one written elsewhere.',
  },
];

const STEPS = [
  { n: '1', title: 'Authorize', body: 'Before an AI agent takes an irreversible action - moving funds, changing an official record, cutting a service - a named, accountable human (or a quorum) signs that exact action on their own device.' },
  { n: '2', title: 'Gate', body: 'The integrated action path is refused unless valid, in-scope evidence is present. Profiles can require initiator exclusion, distinct-human quorum, and one-time consumption.' },
  { n: '3', title: 'Verify', body: 'Anyone - a regulator, an auditor, a court - can verify offline who approved what, without trusting the AI, the operator, or EMILIA itself. The proof travels with the record.' },
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
              records, cutting off services. EMILIA Gate can require a named or quorum decision on
              the protected path, while the open Protocol lets a European institution verify the
              resulting evidence under its own pinned inputs.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 14, fontSize: 17, color: color.t1 }}>
              It provides one concrete evidence mechanism that can support Article 14 oversight.{' '}
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
              Europe mandates human oversight of AI. Nothing yet proves it happened.
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              When an autonomous system acts, the record that a named human authorized{' '}
              <em>that exact</em> action — at the right scope, currently, under the right authority —
              is today a log the operator keeps and could alter, backfill, or rubber-stamp. That
              operator is often a non-European hyperscaler. <span style={{ color: color.t1 }}>The
              accountability exists on paper, but not as an artifact anyone independent can check.</span>
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
              EMILIA proves authorization — not that a decision was wise or lawful.
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              It is a necessary, not sufficient, condition for trustworthy AI — the verifiable
              foundation other safeguards build on. And EMILIA does not charge public institutions for
              the core protocol: the goal is adoption of the standard, in the public interest.
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
