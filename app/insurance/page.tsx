// SPDX-License-Identifier: Apache-2.0
// Shipped reliance-risk evidence for insurers and assurance teams.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const ARTIFACTS = [
  {
    label: 'RP policy',
    title: 'Loss-allocation schedule',
    body: 'The relying party pins separately signed responsibility terms to the exact Reliance Program. Verification establishes the signed bytes, issuer, status, and program binding—not legal enforceability, coverage, solvency, or payment.',
  },
  {
    label: 'Live control',
    title: 'Open Exposure Ledger',
    body: 'Declared exposure is reserved before provider invocation against configured ceilings. INVOKING and INDETERMINATE stay open; only the configured independent reconciliation authority can close them.',
  },
  {
    label: 'Transaction evidence',
    title: 'Exact-action refusal',
    body: 'A signed refusal binds the action, program, failed requirements, challenge, nonce, custody, and time. It is technical exact-action evidence—not a legal denial, adverse-benefit denial, or coverage decision.',
  },
  {
    label: 'Period evidence',
    title: 'Coverage reconciliation',
    body: 'The attestation signs supplied system-of-record and receipt roots, counts, joins, exclusions, exceptions, and uncertainty for a bounded period. Here “coverage” means declared-population reconciliation, not insurance coverage.',
  },
  {
    label: 'Portfolio evidence',
    title: 'Receipt census + loss feed',
    body: 'The census emits governed aggregate buckets with coarse primary suppression. The signed loss feed preserves external provenance and correction lineage; its observations are not verified or adjudicated losses.',
  },
];

const PILOT = [
  [
    'For the protected operator',
    'Select one fully mediated action, pin the Reliance Program and authorities, define declared exposure ceilings, and test refusals, uncertainty, reconciliation, and bounded-period evidence before production use.',
  ],
  [
    'For the carrier or assurer',
    'Re-perform the supplied artifacts under independently pinned inputs and decide what, if anything, they support for underwriting, control testing, or claims review. EMILIA supplies technical evidence; the relying party keeps the conclusion.',
  ],
];

const FAQ = [
  [
    'Does EMILIA provide insurance or decide coverage?',
    'No. EMILIA is technical enforcement and evidence infrastructure. It does not insure, decide policy coverage, allocate or bear loss, establish liability, adjudicate a claim, or move money.',
  ],
  [
    'What does an exact-action refusal prove?',
    'It proves that the signed technical statement binds the named action, program, failed requirements, challenge, nonce, custody, and time under the pinned verification inputs. It is not a legal denial, an adverse-benefit denial, or proof that a refusal was substantively correct.',
  ],
  [
    'Does the coverage attestation prove the population was complete?',
    'No. It signs the supplied inventory roots and conserving counts for a bounded period. Completeness needs separate system-of-record evidence. The receipt census also uses only coarse primary suppression, not differential privacy.',
  ],
  [
    'Can a carrier verify the artifacts without an EMILIA callback?',
    'Yes. The formats, verifier, vectors, and exact executable claim are public. The current stateful risk-plane and signed risk-artifact implementation is JavaScript; no insurer adoption or external deployment is claimed.',
  ],
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
          <div style={styles.eyebrow}>RELIANCE RISK PLANE · GATE 0.20.0</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 900 }}>
            Technical evidence for reliance decisions. Not an insurance decision.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            Gate 0.20.0 adds a bounded risk plane around the exact authorization lifecycle:
            customer-owned responsibility terms, declared open-exposure custody, signed technical
            refusals, period population reconciliation, aggregate receipt census, and externally
            reported loss experience with correction lineage.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            An insurer, auditor, or customer can re-perform those artifacts under independently
            pinned inputs. EMILIA does not supply the underwriting, legal, coverage, causation,
            completeness, solvency, adjudication, or payment conclusion.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href="/proof#reliance-risk-plane" style={cta.primary}>Inspect the shipped proof</a>
            <a href="/pilot?v=insurance" style={cta.secondary}>Scope one protected workflow</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>WHAT SHIPPED</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            Five evidence surfaces. None can authorize an action by itself.
          </h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
            {ARTIFACTS.map((artifact) => (
              <div key={artifact.title} style={{ ...styles.card, padding: 24, borderTop: `3px solid ${color.gold}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>
                  {artifact.label}
                </div>
                <div style={{ ...styles.h3, fontSize: 19, marginTop: 10 }}>{artifact.title}</div>
                <div style={{ ...styles.cardBody, marginTop: 10, fontSize: 14, lineHeight: 1.7 }}>{artifact.body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE CONTROL BOUNDARY</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Terms, authority, exposure, outcome, and recourse stay separate.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            The loss schedule records customer-supplied terms. Authorization still comes from the
            existing exact-action evidence and local policy. The Open Exposure Ledger reserves a
            declared amount before provider entry and preserves uncertainty without granting a retry.
            Reconciliation accepts authenticated outcome evidence; it does not decide legal loss or
            policy coverage.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8, fontSize: 15, color: color.t2 }}>
            The reference artifacts are open and reproducible:{' '}
            <a
              href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/architecture/RELIANCE-RISK-PLANE.md"
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontFamily: font.mono, color: color.gold }}
            >
              read the architecture contract
            </a>.
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE PILOT</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Start with one exact action and one declared exposure boundary.</h2>
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
            EMILIA does not insure, bear or allocate loss, adjudicate disputes or losses,
            establish legal enforceability, prove insurance coverage, causation, solvency, or
            source-population completeness, or move money. Refusal statements are exact technical
            evidence, not legal or adverse-benefit denials. No external deployment or insurer
            adoption is claimed.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
