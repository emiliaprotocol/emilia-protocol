// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const VECTOR_URL = `${REPO}/blob/main/conformance/vectors/aeb-consequence-conformance.v1.json`;
const REFEREE_ACTION_URL = `${REPO}/tree/main/.github/actions/referee`;
const DRAFT_URL = 'https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/';
const COMMAND = 'npx @emilia-protocol/verify aeb-conformance --reference';

export const metadata: Metadata = {
  title: 'AEB-1 Consequence-Admission Conformance Pack | EMILIA Protocol',
  description:
    'A free, open reference self-test for exact-action admission, one-time consumption, indeterminate outcomes, and authenticated reconciliation.',
};

const FORMATS = ['Receipt', 'Permit', 'Token', 'Credential', 'Mandate'];

const PIPELINE = [
  {
    number: '01',
    title: 'Verify natively',
    body: 'Keep each artifact under its own signature, issuer, audience, freshness, and status rules.',
  },
  {
    number: '02',
    title: 'Match the action',
    body: 'Compare verified evidence to the executor-owned, frozen material action without guessing equivalence.',
  },
  {
    number: '03',
    title: 'Keep roles distinct',
    body: 'Evidence satisfaction does not collapse identity, policy, human authority, or local authorization into one verdict.',
  },
  {
    number: '04',
    title: 'Consume before effect',
    body: 'Atomically consume or reserve one-time authority before dispatch so concurrent replay cannot win twice.',
  },
  {
    number: '05',
    title: 'Preserve uncertainty',
    body: 'Keep provider outcome separate from observed effect, and reconcile the same operation before any later attempt.',
  },
];

const CHECKS = [
  {
    code: 'ACTION_MISMATCH',
    title: 'Exact-action mismatch',
    body: 'Change a material field between evidence and effect. The expected result is refusal, even when the original artifact remains valid.',
    result: 'REFUSE',
    accent: color.red,
  },
  {
    code: 'STATUS_NOT_CURRENT',
    title: 'Stale, revoked, or unavailable',
    body: 'Present stale or revoked authority—or make a required status source unavailable. Ambiguity must never become permission.',
    result: 'HOLD CLOSED',
    accent: color.red,
  },
  {
    code: 'ROLE_CONFUSION',
    title: 'Role confusion',
    body: 'Try to use workload identity as a permit, machine policy as named-human authorization, or another artifact in the wrong evidence slot.',
    result: 'REFUSE',
    accent: color.red,
  },
  {
    code: 'REPLAY',
    title: 'One-time consumption and replay',
    body: 'Race or replay the same authority. The reference contract allows one atomic consume or reserve transition, never two effects.',
    result: 'AT MOST ONCE',
    accent: color.gold,
  },
  {
    code: 'INDETERMINATE',
    title: 'No blind retry',
    body: 'Lose the result after invocation may have begun. Provider outcome and observed effect remain INDETERMINATE, and the original authority stays closed to retry.',
    result: 'HOLD CLOSED',
    accent: color.gold,
  },
  {
    code: 'RECONCILIATION_AUTH',
    title: 'Authenticated reconciliation',
    body: 'Resolve uncertainty only with an authenticated source matched to the same action, operation, provider environment, audience, and target.',
    result: 'MATCH OR HOLD',
    accent: color.blue,
  },
];

const RESOURCES = [
  {
    href: '/proof',
    label: 'Engineering evidence',
    body: 'See the wider claim-to-code, formal-model, conformance, and fault-testing evidence.',
    external: false,
  },
  {
    href: '/protocol',
    label: 'Open protocol',
    body: 'Place AEB in the larger exact-action evidence and consequence-control architecture.',
    external: false,
  },
  {
    href: VECTOR_URL,
    label: 'Reference vectors',
    body: 'Inspect the deterministic AEB-1 consequence-admission cases on GitHub.',
    external: true,
  },
  {
    href: REFEREE_ACTION_URL,
    label: 'Referee GitHub Action',
    body: 'Run a checked-in implementation against the bounded offline self-test contract without granting execution authority.',
    external: true,
  },
  {
    href: DRAFT_URL,
    label: 'AEB Internet-Draft',
    body: 'Read the published individual Internet-Draft and its ordered processing model.',
    external: true,
  },
];

export default function ConformancePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Protocol" />

      <main>
        <section
          style={{
            borderBottom: `1px solid ${color.border}`,
            background: `linear-gradient(135deg, ${color.card} 0%, ${color.bg} 58%, ${color.cardHover} 100%)`,
          }}
        >
          <div
            style={{
              ...styles.sectionWide,
              paddingTop: 76,
              paddingBottom: 64,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 380px), 1fr))',
              gap: 52,
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>
                AEB-1 · Consequence-admission conformance
              </div>
              <h1 style={{ ...styles.h1Large, maxWidth: 760 }}>
                Test the boundary between evidence and effect.
              </h1>
              <p style={{ ...styles.body, maxWidth: 720, marginTop: 24, marginBottom: 0, fontSize: 18 }}>
                A free, open reference self-test for the last control point before a consequential
                action. It is format-neutral across a receipt, permit, token, credential, or
                mandate—and tests whether your boundary keeps each artifact&apos;s meaning intact.
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 26 }} aria-label="Supported artifact categories">
                {FORMATS.map((format) => (
                  <span
                    key={format}
                    style={{
                      padding: '7px 10px',
                      border: `1px solid ${color.border}`,
                      borderRadius: radius.sm,
                      background: color.card,
                      color: color.t2,
                      fontFamily: font.mono,
                      fontSize: 11,
                      letterSpacing: 0.4,
                    }}
                  >
                    {format}
                  </span>
                ))}
              </div>
            </div>

            <div
              style={{
                background: color.t1,
                color: color.bg,
                borderRadius: radius.base,
                padding: '26px 24px 24px',
                borderTop: `3px solid ${color.gold}`,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: 12,
                  paddingBottom: 18,
                  borderBottom: `1px solid ${color.t2}`,
                }}
              >
                <span style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.2, textTransform: 'uppercase' }}>
                  Reference self-test
                </span>
                <span style={{ fontFamily: font.mono, fontSize: 10, color: color.gold }}>
                  FREE · OPEN · LOCAL
                </span>
              </div>
              <div style={{ marginTop: 24 }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginBottom: 10 }}>
                  Run from your project
                </div>
                <div
                  aria-label={`Command: ${COMMAND}`}
                  style={{
                    padding: '16px 0',
                    overflowX: 'auto',
                    color: color.card,
                    fontFamily: font.mono,
                    fontSize: 14,
                    lineHeight: 1.7,
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ color: color.gold }}>$</span> {COMMAND}
                </div>
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
                  gap: 10,
                  marginTop: 20,
                }}
              >
                {[
                  ['22', 'hostile vectors'],
                  ['01', 'reference contract'],
                  ['SELF', 'test only'],
                ].map(([value, label]) => (
                  <div key={label} style={{ borderTop: `1px solid ${color.t2}`, paddingTop: 12 }}>
                    <div style={{ fontFamily: font.mono, color: color.card, fontSize: 17 }}>{value}</div>
                    <div style={{ color: color.t3, fontSize: 11, marginTop: 4 }}>{label}</div>
                  </div>
                ))}
              </div>
              <a
                href={VECTOR_URL}
                target="_blank"
                rel="noopener noreferrer"
                style={{ ...cta.secondary, color: color.card, borderColor: color.t2, marginTop: 24 }}
              >
                Inspect the reference vectors &nearr;
              </a>
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 68, paddingBottom: 68 }}>
          <div style={styles.eyebrow}>THE ADMISSION CONTRACT</div>
          <h2 style={{ ...styles.h2, margin: 0, maxWidth: 760, fontSize: 30 }}>
            One ordered boundary. Native semantics stay native.
          </h2>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 18 }}>
            AEB does not turn every artifact into an AEB object. The relying party verifies each
            input under its own rules, joins only verified facts to the exact action, makes a
            separate local authorization decision, and takes custody of the outcome.
          </p>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 190px), 1fr))',
              gap: 12,
              marginTop: 30,
            }}
          >
            {PIPELINE.map((step) => (
              <div key={step.number} style={{ ...styles.card, padding: 22, minHeight: 190 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontFamily: font.mono, fontSize: 11, color: color.gold }}>{step.number}</span>
                  <span style={{ height: 1, flex: 1, background: color.border }} />
                </div>
                <h3 style={{ ...styles.h3, marginTop: 22 }}>{step.title}</h3>
                <p style={{ ...styles.cardBody, margin: 0 }}>{step.body}</p>
              </div>
            ))}
          </div>
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, lineHeight: 1.7, marginTop: 20, maxWidth: 920 }}>
            VERIFIED ≠ MATCHED ≠ SATISFIED ≠ AUTHORIZED ≠ RESERVED ≠ INVOKING ≠ PROVIDER OUTCOME ≠ OBSERVED EFFECT
          </p>
        </section>

        <section style={{ ...styles.sectionAlt }}>
          <div style={{ ...styles.sectionWide, paddingTop: 68, paddingBottom: 68 }}>
            <div style={styles.eyebrow}>WHAT AEB-1 TRIES TO BREAK</div>
            <h2 style={{ ...styles.h2, margin: 0, maxWidth: 760, fontSize: 30 }}>
              Passing the happy path is not the test.
            </h2>
            <p style={{ ...styles.body, maxWidth: 740, marginTop: 18 }}>
              The pack targets the places where valid-looking evidence can still produce an
              unsafe effect. Every case has a bounded expected result that can be compared across
              implementations.
            </p>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))',
                gap: 16,
                marginTop: 28,
              }}
            >
              {CHECKS.map((check) => (
                <article
                  key={check.code}
                  style={{
                    ...styles.card,
                    padding: 26,
                    borderTop: `3px solid ${check.accent}`,
                    display: 'flex',
                    flexDirection: 'column',
                    minHeight: 220,
                  }}
                >
                  <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1, color: check.accent }}>
                    {check.code}
                  </div>
                  <h3 style={{ ...styles.h3, marginTop: 18, fontSize: 19 }}>{check.title}</h3>
                  <p style={{ ...styles.cardBody, margin: 0, flex: 1 }}>{check.body}</p>
                  <div
                    style={{
                      marginTop: 22,
                      paddingTop: 14,
                      borderTop: `1px solid ${color.border}`,
                      fontFamily: font.mono,
                      fontSize: 11,
                      color: check.accent,
                    }}
                  >
                    EXPECTED · {check.result}
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 68, paddingBottom: 68 }}>
          <div style={styles.eyebrow}>FORMAT-NEUTRAL BY DESIGN</div>
          <h2 style={{ ...styles.h2, margin: 0, maxWidth: 780, fontSize: 30 }}>
            Bring the artifact your system already trusts.
          </h2>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18 }}>
            A receipt, permit, token, credential, or mandate can enter through a pinned native
            verifier and adapter. The pack tests consequence-admission behavior at the common
            boundary; it does not redefine the artifact, its issuer, or what it proves.
          </p>
          <div
            style={{
              ...styles.card,
              marginTop: 30,
              padding: 30,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))',
              gap: 28,
              alignItems: 'center',
              borderLeft: `3px solid ${color.gold}`,
            }}
          >
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.4, color: color.gold, textTransform: 'uppercase' }}>
                Native input
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 16 }}>
                {FORMATS.map((format) => (
                  <span key={format} style={{ padding: '8px 10px', background: color.cardHover, borderRadius: radius.sm, fontFamily: font.mono, fontSize: 12, color: color.t2 }}>
                    {format.toLowerCase()}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.4, color: color.t3, textTransform: 'uppercase' }}>
                Shared boundary question
              </div>
              <p style={{ ...styles.body, color: color.t1, margin: '14px 0 0', fontSize: 17 }}>
                Does verified evidence satisfy the requirements for this exact action now, can
                local policy authorize it once, and can the boundary retain custody when provider
                outcome or observed effect is unknown?
              </p>
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionAlt }}>
          <div style={{ ...styles.sectionWide, paddingTop: 68, paddingBottom: 68 }}>
            <div style={styles.eyebrow}>THE CLAIM BOUNDARY</div>
            <h2 style={{ ...styles.h2, margin: 0, maxWidth: 800, fontSize: 30 }}>
              A useful self-test, with no borrowed authority.
            </h2>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 340px), 1fr))',
                gap: 16,
                marginTop: 30,
              }}
            >
              <div style={{ ...styles.card, padding: 28, borderTop: `3px solid ${color.green}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.green, letterSpacing: 1.2, textTransform: 'uppercase' }}>
                  What it is
                </div>
                <h3 style={{ ...styles.h3, marginTop: 18, fontSize: 21 }}>Free. Open. Self-run.</h3>
                <p style={{ ...styles.cardBody, margin: 0, fontSize: 15 }}>
                  A deterministic reference pack for checking your implementation&apos;s verdicts
                  against the published AEB-1 consequence-admission cases. Run it locally, inspect
                  the vectors, and report the exact scope you tested.
                </p>
              </div>
              <div style={{ ...styles.card, padding: 28, borderTop: `3px solid ${color.red}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.red, letterSpacing: 1.2, textTransform: 'uppercase' }}>
                  What it is not
                </div>
                <h3 style={{ ...styles.h3, marginTop: 18, fontSize: 21 }}>No certification by implication.</h3>
                <ul style={{ ...styles.list, margin: 0, fontSize: 14.5 }}>
                  <li>Not a certification.</li>
                  <li>Not an audit or assurance opinion.</li>
                  <li>Not evidence of adoption or endorsement.</li>
                  <li>Not proof of complete mediation in a deployment.</li>
                </ul>
              </div>
            </div>
            <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.7, marginTop: 20, maxWidth: 880 }}>
              AEB is an individual Internet-Draft. A passing reference run says only that the
              tested implementation produced the expected results for the tested vectors under
              the stated configuration. Deployment topology, bypass paths, durable state, trust
              inputs, and operational controls remain separate evidence. A local atomicity result
              applies only inside the consequence owner&apos;s demonstrated transaction domain; it is
              not a claim of atomicity across a remote or federated boundary.
            </p>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 68, paddingBottom: 76 }}>
          <div style={styles.eyebrow}>READ THE CONTRACT</div>
          <h2 style={{ ...styles.h2, margin: 0, maxWidth: 760, fontSize: 30 }}>
            Inspect every layer behind the result.
          </h2>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 230px), 1fr))',
              gap: 14,
              marginTop: 28,
            }}
          >
            {RESOURCES.map((resource) => (
              <a
                key={resource.href}
                href={resource.href}
                target={resource.external ? '_blank' : undefined}
                rel={resource.external ? 'noopener noreferrer' : undefined}
                style={{ ...styles.card, padding: 24, textDecoration: 'none', minHeight: 150 }}
              >
                <div style={{ ...styles.h3, fontSize: 17, marginBottom: 10 }}>
                  {resource.label} {resource.external ? '↗' : '→'}
                </div>
                <div style={styles.cardBody}>{resource.body}</div>
              </a>
            ))}
          </div>

          <div
            style={{
              marginTop: 34,
              padding: '30px 28px',
              borderRadius: radius.base,
              background: color.t1,
              color: color.bg,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 24,
            }}
          >
            <div style={{ minWidth: 0 }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.4, textTransform: 'uppercase' }}>
                Run AEB-1 now
              </div>
              <code
                style={{
                  display: 'block',
                  marginTop: 12,
                  maxWidth: '100%',
                  overflowX: 'auto',
                  whiteSpace: 'nowrap',
                  color: color.card,
                  fontFamily: font.mono,
                  fontSize: 14,
                  lineHeight: 1.7,
                }}
              >
                {COMMAND}
              </code>
            </div>
            <a href={VECTOR_URL} target="_blank" rel="noopener noreferrer" style={{ ...cta.primary, background: color.card, color: color.t1 }}>
              Open the reference pack &nearr;
            </a>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
