// SPDX-License-Identifier: Apache-2.0

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, cta, font, radius, styles } from '@/lib/tokens';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';

const FLOW = [
  {
    number: '01',
    title: 'Discover the standing declaration',
    body: 'A media asset exposes an RSL-MEDIA declaration. An external evaluator resolves the operative rule, source identifier, purpose, territory, and any clearance endpoint.',
  },
  {
    number: '02',
    title: 'Issue a bounded grant',
    body: 'The rights-side authority signs an EP-CONSENT-GRANT-v1 naming the exact asset, use, purpose, territory, campaign, source-declaration digest, and expiry.',
  },
  {
    number: '03',
    title: 'Authorize one exact use',
    body: 'An enrolled approver completes a user-verified WebAuthn ceremony over the material action fields. The action also binds the standing grant by hash.',
  },
  {
    number: '04',
    title: 'Verify, execute, consume',
    body: 'The executor rechecks the current declaration against the grant, verifies its pinned keys and profile, atomically reserves the action digest, and performs the effect once.',
  },
];

const OUTCOMES = [
  ['Exact declared use', 'EXECUTE', 'All pinned evidence covers the same exact use; one execution reservation wins.'],
  ['Same action, replayed or independently re-signed', 'REFUSE', 'The action digest is already reserved or consumed; a second receipt cannot authorize a second effect.'],
  ['Campaign, territory, or purpose changed', 'REFUSE', 'The action no longer satisfies the signed grant constraints.'],
  ['Action changed after approval', 'REFUSE', 'The WebAuthn challenge and signed action digest no longer match.'],
  ['Declaration is prohibited, absent, or stale', 'REFUSE', 'No permissive fallback is inferred from missing or non-operative declaration state.'],
];

const LIMITS = [
  'It does not establish who owns the underlying rights.',
  'It does not determine whether the proposed use is lawful.',
  'It does not prove that the approver understood what was displayed.',
  'It does not evaluate the safety, truthfulness, or quality of generated output.',
  'It does not claim RSL-MEDIA conformance or endorsement by the RSL community.',
  'It depends on an external evaluator and the relying party’s pinned trust policy for the current declaration view.',
];

export default function DeclarationToProofPage() {
  return (
    <>
      <SiteNav activePage="EU" />
      <main style={styles.page}>
        <section
          style={{
            position: 'relative',
            minHeight: 500,
            display: 'flex',
            alignItems: 'flex-end',
            backgroundImage: 'url(/hero-human-machine-shoreline-v1.webp)',
            backgroundSize: 'cover',
            backgroundPosition: 'center 52%',
            overflow: 'hidden',
          }}
        >
          <div
            aria-hidden="true"
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(12, 10, 9, 0.62)',
            }}
          />
          <div
            style={{
              position: 'relative',
              width: '100%',
              maxWidth: 1080,
              margin: '0 auto',
              padding: '72px 24px 52px',
            }}
          >
            <div style={{ ...styles.eyebrow, color: '#E7D6A1', letterSpacing: 2 }}>
              INDEPENDENT COMPATIBILITY REFERENCE
            </div>
            <h1
              style={{
                ...styles.h1Large,
                maxWidth: 900,
                color: '#FFFFFF',
                lineHeight: 1.02,
                letterSpacing: 0,
              }}
            >
              A declaration states the rule. A receipt proves one exact use.
            </h1>
            <p
              style={{
                ...styles.body,
                maxWidth: 760,
                marginTop: 18,
                marginBottom: 0,
                color: '#F5F5F4',
                fontSize: 18,
              }}
            >
              This runnable reference composes an externally evaluated RSL-MEDIA
              declaration with a bounded consent grant, a user-verified authorization
              ceremony, and an executor that will act at most once.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <a
                href={`${REPO}/tree/main/examples/rsl-media-clearance`}
                style={{ ...cta.primary, background: '#FFFFFF', color: color.t1 }}
              >
                Run the reference
              </a>
              <a
                href="/briefs/emilia-declaration-to-proof.pdf"
                style={{ ...cta.secondary, color: '#FFFFFF', borderColor: 'rgba(255,255,255,0.62)' }}
              >
                Download the brief
              </a>
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 56, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>THE COMPOSITION</div>
          <h2 style={{ ...styles.h2, maxWidth: 760, letterSpacing: 0 }}>
            Policy and proof are different artifacts. The executor needs both.
          </h2>
          <p style={{ ...styles.body, maxWidth: 780 }}>
            RSL-MEDIA describes standing declarations and a path to obtain clearance.
            EMILIA contributes a reusable evidence and enforcement profile for one
            consequential use. The join is the asset identifier, source-declaration
            digest, grant hash, and exact action digest.
          </p>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
              gap: 14,
              marginTop: 28,
            }}
          >
            {FLOW.map((step) => (
              <article key={step.number} style={{ ...styles.card, minHeight: 220 }}>
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 12,
                    color: color.gold,
                    fontWeight: 700,
                    letterSpacing: 0,
                  }}
                >
                  {step.number}
                </div>
                <h3 style={{ ...styles.h3, marginTop: 18, letterSpacing: 0 }}>{step.title}</h3>
                <p style={{ ...styles.cardBody, margin: 0 }}>{step.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.sectionWide}>
            <div style={styles.eyebrow}>EXECUTOR VERDICTS</div>
            <h2 style={{ ...styles.h2, maxWidth: 760, letterSpacing: 0 }}>
              Permission does not survive mutation, expiry, or replay.
            </h2>
            <div style={{ marginTop: 24, overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 680 }}>
                <thead>
                  <tr>
                    <th style={styles.tableHead}>Presented condition</th>
                    <th style={styles.tableHead}>Result</th>
                    <th style={styles.tableHead}>Why</th>
                  </tr>
                </thead>
                <tbody>
                  {OUTCOMES.map(([condition, result, why]) => (
                    <tr key={condition}>
                      <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{condition}</td>
                      <td style={styles.tableCell}>
                        <span
                          style={{
                            display: 'inline-block',
                            minWidth: 74,
                            padding: '4px 8px',
                            borderRadius: radius.sm,
                            background: result === 'EXECUTE' ? '#DCFCE7' : '#FEE2E2',
                            color: result === 'EXECUTE' ? '#166534' : '#991B1B',
                            fontFamily: font.mono,
                            fontSize: 11,
                            fontWeight: 700,
                            textAlign: 'center',
                          }}
                        >
                          {result}
                        </span>
                      </td>
                      <td style={styles.tableCell}>{why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div
              style={{
                marginTop: 28,
                padding: 22,
                background: color.t1,
                borderRadius: radius.base,
                color: '#F5F5F4',
                fontFamily: font.mono,
                fontSize: 13,
                overflowX: 'auto',
              }}
            >
              <div style={{ color: '#D6D3D1', marginBottom: 8 }}>Run offline</div>
              <div>node examples/rsl-media-clearance/demo.mjs</div>
              <div>npx vitest run tests/rsl-media-clearance.test.js</div>
            </div>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: 32,
              alignItems: 'start',
            }}
          >
            <div>
              <div style={styles.eyebrow}>WHAT THE REFERENCE ESTABLISHES</div>
              <h2 style={{ ...styles.h2, letterSpacing: 0 }}>
                One exact use matched current declared terms, was authorized, and was admitted once.
              </h2>
              <p style={styles.body}>
                The verifier establishes that a fresh normalized declaration view
                still covers the signed grant, the grant was signed under a key the
                relying party pinned, its explicit constraints covered the signed
                action, the WebAuthn ceremony bound the exact material fields, and
                the executor admitted no second action digest.
              </p>
              <p style={styles.body}>
                That is a portable technical fact. It can support audit, contractual,
                and regulatory analysis without pretending to settle those analyses.
              </p>
            </div>
            <div>
              <div style={styles.eyebrow}>WHAT IT DOES NOT ESTABLISH</div>
              <ul style={{ ...styles.list, margin: 0 }}>
                {LIMITS.map((item) => <li key={item} style={{ marginBottom: 10 }}>{item}</li>)}
              </ul>
            </div>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrow}>DRAFT-STATUS NOTICE</div>
            <h2 style={{ ...styles.h2, letterSpacing: 0 }}>A compatibility experiment, not a production claim.</h2>
            <p style={styles.body}>
              RSL-MEDIA 1.0 is currently a draft and states that it must not be used
              for production. Its future OLP-MEDIA work is expected to define
              authorization-token mechanics. This reference does not parse the RSL
              document or claim RSL conformance; it consumes normalized output from
              an external declaration evaluator and demonstrates one possible
              clearance artifact at that open boundary.
            </p>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3 }}>
              Independent work by EMILIA Protocol. No partnership, endorsement, or
              standards-body adoption is implied.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <a href="https://rslmedia.org/media" style={cta.secondary}>Read RSL-MEDIA</a>
              <a href="/proof-vs-measurement" style={cta.secondary}>Proof vs. measurement</a>
              <a href="/briefs/emilia-jtc21-human-oversight-contribution.pdf" style={cta.secondary}>
                JTC21 technical input
              </a>
              <a href="mailto:team@emiliaprotocol.ai?subject=Declaration%20to%20proof%20technical%20review" style={cta.primary}>
                Review the mapping
              </a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
