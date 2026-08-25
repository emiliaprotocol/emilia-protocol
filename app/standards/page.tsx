// SPDX-License-Identifier: Apache-2.0
// /standards - product outcome first, then the canonical four-document evidence
// path, followed by the adjacent IETF landscape. Internal links use next/link
// <Link> (lint rule).

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import standardsStatus from '@/standards/STATUS.json';

const goldText = '#765A13';

export const metadata = {
  title: 'Let agents act within limits you approve in advance',
  description:
    'EMILIA Gate is designed to control configured action paths when a deployment provides complete mediation. Four individual Internet-Drafts define the portable evidence path beneath that product boundary.',
  alternates: { canonical: '/standards' },
};

const ADOPTION_ROLES: Record<string, string> = {
  'draft-schrock-ep-authorization-receipts': 'Create the evidence',
  'draft-schrock-human-authorization-binding': 'Attach it to the action record',
  'draft-schrock-ep-authority-introduction': 'Establish scoped authority',
  'draft-schrock-ep-authorization-evidence-chain': 'Evaluate the evidence requirement',
};

const ADOPTION_PATH = standardsStatus.canonical_four_document_surface.documents.map((document) => ({
  step: String(document.order).padStart(2, '0'),
  title: document.label,
  revision: `${document.draft}-${document.revision}`,
  role: ADOPTION_ROLES[document.draft] ?? 'Read this layer',
  body: document.canonical_question,
  result: document.boundary,
  href: document.datatracker,
}));

// Three interfaces with adjacent standards. These are composition points, not
// claims that another standards body has adopted EMILIA.
const PILLARS = [
  {
    role: 'AUTHENTICATION TRIGGER',
    status: 'published RFC',
    title: 'OAuth Step-Up Authentication - RFC 9470 (Proposed Standard)',
    body:
      'Step-Up can require a stronger authentication event for a sensitive action. An EMILIA integration can request separate, durable approval evidence after that trigger; the receipt proves only its own signed fields and bindings.',
  },
  {
    role: 'MACHINE EVIDENCE',
    status: 'published / active work',
    title: 'Machine attestation - RATS (RFC 9334) + EAT (RFC 9711), SPIFFE/SPIRE, WIMSE',
    body:
      'Machine attestation and workload identity describe the platform or workload. EMILIA authorization evidence remains a distinct input: it records an approval claim bound to the action and is evaluated under relying-party-pinned enrollment and authority roots.',
  },
  {
    role: 'TRANSPARENCY RAIL',
    status: 'active drafts',
    title: 'SCITT - RFC 9943 + SCRAPI',
    body:
      'A SCITT receipt is transparency or inclusion evidence: it shows that a statement was registered. An EMILIA authorization receipt can be carried as a SCITT Signed Statement, while SCITT returns the separate proof that it was logged.',
  },
];

// Tier 1 - published RFCs / deployed. Anchor here.
const TIER1 = [
  ['OAuth 2.0 / OIDC - RFC 6749', 'Published - ubiquitous', 'Grants access. EMILIA can add separate, exact-action approval evidence evaluated against the relying party\'s pinned trust inputs.'],
  ['Step-Up Authentication - RFC 9470', 'Proposed Standard', 'Can trigger stronger authentication. An EMILIA receipt is a separate artifact and does not prove a Step-Up event unless the integration explicitly binds the two.'],
  ['Rich Authorization Requests (RAR) - RFC 9396', 'Proposed Standard', 'An EMILIA profile can bind approval evidence to the same authorization_details under an explicit action mapping.'],
  ['RATS - RFC 9334 + EAT - RFC 9711', 'Published', 'Supplies platform or workload attestation. EMILIA authorization evidence stays separate, with its own native verifier and trust inputs.'],
  ['HTTP Message Signatures - RFC 9421', 'Proposed Standard', 'An authorization receipt can accompany a signed request; the message signature does not itself create authority.'],
  ['JWS - RFC 7515 / COSE - RFC 9052 / CWT - RFC 8392', 'Published', 'Serialization options in which EMILIA receipt claims can be expressed.'],
  ['Token Exchange - RFC 8693', 'Proposed Standard', 'Delegates authority between services. Exact-action approval evidence remains a separate input at the consequence boundary.'],
  ['SPIFFE / SPIRE', 'CNCF graduated', 'Identifies a workload. EMILIA adds separately verified evidence about the approval and action, not proof of a natural person.'],
  ['Trusted timestamp - RFC 3161 - Evidence Record Syntax (ERS) - RFC 4998 - JCS - RFC 8785', 'Published', 'RFC 3161 can supply trusted time, RFC 4998 informs long-term renewal, and JCS is the EMILIA canonical base.'],
];

// Tier 2 - active drafts. Position relative to; do not anchor.
const TIER2 = [
  ['SCITT - architecture + SCRAPI + COSE Receipts', 'Active drafts', 'EMILIA authorization receipts can be registered as Signed Statements; SCITT can return a distinct transparency receipt.'],
  ['OAuth Transaction Tokens (Txn-Tokens)', 'Active draft', 'Carries short-lived call-chain context. EMILIA supplies separate exact-action authorization evidence, not a transport token.'],
  ['WIMSE (Workload Identity in Multi-System Environments)', 'Active drafts', 'Supplies workload identity. EMILIA authorization evidence remains an independently verified input above that trust root.'],
  ['SD-JWT-VC / EUDI', 'Active drafts', 'Selective-disclosure credentials can be carried or referenced as native evidence without being treated as authorization by default.'],
];

interface StatusPillProps {
  children: React.ReactNode;
}

function StatusPill({ children }: StatusPillProps) {
  return (
    <span style={{
      fontFamily: font.mono, fontSize: 11, color: color.t3,
      border: `1px solid ${color.border}`, borderRadius: 4, padding: '2px 8px',
      whiteSpace: 'nowrap',
    }}>{children}</span>
  );
}

interface ComplementTableProps {
  rows: (string | string[])[];
}

function ComplementTable({ rows }: ComplementTableProps) {
  return (
    <div style={{ overflowX: 'auto', marginTop: 14 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
        <thead>
          <tr>
            <th style={{ ...(styles.tableHead as React.CSSProperties), width: '38%' }}>Standard</th>
            <th style={{ ...(styles.tableHead as React.CSSProperties), width: '16%' }}>Status</th>
            <th style={styles.tableHead as React.CSSProperties}>How EMILIA complements it</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([standard, status, how]) => (
            <tr key={standard as string}>
              <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{standard}</td>
              <td style={styles.tableCell}><StatusPill>{status}</StatusPill></td>
              <td style={styles.tableCell}>{how}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function StandardsPage() {
  return (
    <>
      <SiteNav activePage="Standards" />
      <main style={styles.page}>
        {/* HERO */}
        <section
          style={{
            borderBottom: `1px solid ${color.border}`,
            background: `linear-gradient(135deg, ${color.card} 0%, ${color.bg} 58%, ${color.cardHover} 100%)`,
          }}
        >
          <div
            style={{
              ...styles.sectionWide,
              paddingTop: 80,
              paddingBottom: 64,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 390px), 1fr))',
              gap: 48,
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ ...styles.eyebrow, color: goldText }}>PRODUCT BOUNDARY · OPEN EVIDENCE</div>
              <h1 style={{ ...styles.h1Large, maxWidth: 760 }}>
                Let agents act within limits you approve in advance.
              </h1>
              <p style={{ ...styles.body, maxWidth: 700, marginTop: 24, marginBottom: 0, fontSize: 18 }}>
                EMILIA Gate puts a decision point before configured consequential actions. Local policy decides whether
                the required exact-action authority is present; the open protocol makes the supporting evidence portable
                and independently verifiable.
              </p>
              <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
                <Link href="/agent-guard" style={cta.primary}>See the product boundary</Link>
                <Link href="#four-document-path" style={cta.secondary}>Follow the four-document path</Link>
              </div>
            </div>

            <aside
              aria-label="Prevention boundary"
              style={{
                ...styles.card,
                borderTop: `3px solid ${color.gold}`,
                padding: '28px 30px',
              }}
            >
              <div style={{ ...styles.eyebrow, color: goldText, marginBottom: 12 }}>PREVENTION BOUNDARY</div>
              <div style={{ ...styles.h3, fontSize: 22, lineHeight: 1.3, marginBottom: 12 }}>
                Configured paths. Complete mediation.
              </div>
              <p style={{ ...styles.body, margin: 0, fontSize: 15 }}>
                Prevention applies only to configured action paths under complete mediation. Complete mediation is a
                deployment property to verify with bypass inventory and live architecture testing; neither the protocol
                nor this repository can prove that a deployment has no alternate route.
              </p>
            </aside>
          </div>
        </section>

        {/* CANONICAL FOUR-DOCUMENT PATH */}
        <section id="four-document-path" style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 56 }}>
          <div style={{ ...styles.eyebrow, color: goldText }}>OPEN STANDARDS · ONE BEAT BEHIND THE PRODUCT</div>
          <h2 style={{ ...styles.h2, fontSize: 30, maxWidth: 760 }}>The canonical four-document adoption path</h2>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            The product is designed to control a configured execution path. These four individual Internet-Drafts define
            the evidence path beneath that decision: create the approval artifact, attach it to the action record,
            establish scoped authority, then evaluate the resulting evidence bundle.
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 14,
              marginTop: 28,
            }}
          >
            {ADOPTION_PATH.map((document) => (
              <a
                key={document.step}
                href={document.href}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  minHeight: 330,
                  padding: '24px 22px',
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  background: color.card,
                  color: color.t1,
                  textDecoration: 'none',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
                  <span style={{ fontFamily: font.mono, fontSize: 12, color: goldText }}>{document.step}</span>
                  <span style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, textTransform: 'uppercase' }}>
                    Individual I-D
                  </span>
                </div>
                <div style={{ ...styles.h3, fontSize: 20, lineHeight: 1.25, marginTop: 28, marginBottom: 8 }}>
                  {document.title}
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, lineHeight: 1.5, overflowWrap: 'anywhere' }}>
                  {document.revision}
                </div>
                <div style={{ ...styles.eyebrow, color: goldText, marginTop: 22, marginBottom: 8 }}>
                  {document.role}
                </div>
                <p style={{ ...styles.cardBody, margin: 0 }}>{document.body}</p>
                <p style={{ ...styles.cardBody, color: color.t1, fontWeight: 600, marginTop: 'auto', paddingTop: 20, marginBottom: 0 }}>
                  {document.result}
                </p>
              </a>
            ))}
          </div>

          <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 860, marginTop: 20, marginBottom: 0 }}>
            This is EMILIA&rsquo;s reader-facing implementation sequence. It is not a claim of working-group adoption,
            endorsement, production deployment, or consolidation of the wider draft portfolio. Verification, evidence
            satisfaction, local authorization, and observed execution remain separate decisions.
          </p>
        </section>

        {/* ADJACENT-STANDARD INTERFACES */}
        <section style={{ ...styles.section, paddingTop: 28, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>Three interfaces with adjacent standards</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12 }}>
              Authentication can trigger the flow, machine evidence can sit beside it, and a transparency service can
              log it. These are composition points, not claims that another standard or working group has adopted EMILIA.
            </p>
            <div style={{ marginTop: 10 }}>
              {PILLARS.map((p) => (
                <div key={p.role} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ ...styles.eyebrow, color: goldText, marginBottom: 0 }}>{p.role}</span>
                    <StatusPill>{p.status}</StatusPill>
                  </div>
                  <div style={{ ...styles.h3, marginTop: 10 }}>{p.title}</div>
                  <p style={{ ...styles.body, fontSize: 15, marginBottom: 0, marginTop: 6, maxWidth: 760 }}>{p.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* TIER 1 TABLE */}
        <section style={{ ...styles.sectionWide, paddingTop: 24, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: goldText }}>TIER 1 · PUBLISHED RFCs / DEPLOYED — ANCHOR HERE</div>
            <h2 style={styles.h2}>Published standards to compose with</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              These are published or widely deployed standards and projects. EMILIA&rsquo;s specifications define possible
              complement relationships; they do not imply integration or adoption by those communities.
            </p>
            <ComplementTable rows={TIER1} />
          </div>
        </section>

        {/* TIER 2 TABLE */}
        <section style={{ ...styles.sectionWide, paddingTop: 24, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>TIER 2 · ACTIVE DRAFTS — POSITION RELATIVE TO, DON&rsquo;T ANCHOR</div>
            <h2 style={styles.h2}>Where EMILIA positions for what&rsquo;s standardizing</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              These efforts are still moving through the IETF. EMILIA tracks them as complements; the relationship is a
              composition story, not a claim of adoption by those working groups.
            </p>
            <ComplementTable rows={TIER2} />
          </div>
        </section>

        {/* INTEROP NOTE */}
        <section style={{ ...styles.section, paddingTop: 24, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>Interop: one canonical base, three serializations</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              EMILIA keeps <b>JCS (RFC 8785)</b> as its canonical base and offers receipts as <b>JWS (RFC 7515)</b> for
              universal web reach and <b>COSE_Sign1 / CWT (RFC 9052 / RFC 8392)</b> CBOR-native form for SCITT interop. The
              same receipt claims can travel across all three — no lock-in to a wire format.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 12, flexWrap: 'wrap' }}>
              <Link href="/fire-drill/rr-1" style={cta.secondary}>Inspect an example receipt</Link>
              <Link href="/spec" style={cta.secondary}>draft-schrock-ep-authorization-receipts</Link>
            </div>
          </div>
        </section>

        {/* RATS + SCITT MAPPING DETAIL */}
        <section style={{ ...styles.sectionWide, paddingTop: 24, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: goldText }}>MAPPING DETAIL · RATS + SCITT</div>
            <h2 style={styles.h2}>How the evidence can sit beside RATS and inside SCITT</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              These are narrow composition mappings, not adoption claims. Machine attestation and EMILIA authorization
              evidence remain orthogonal inputs that can meet at the relying party.
            </p>

            <div style={{ ...styles.h3, marginTop: 22 }}>The attest loop as a RATS profile (RFC&nbsp;9334)</div>
            {[
              ['Attester', 'the agent / host — produces Evidence about its compute context'],
              ['Verifier', 'the "God Terminal" — appraises Evidence into an Attestation Result'],
              ['Relying Party', 'the gateway / substrate — consumes the Attestation Result AND the EMILIA authorization receipt'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 14, padding: '9px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                <span style={{ flex: '0 0 130px', fontFamily: font.mono, fontSize: 13, color: goldText }}>{k}</span>
                <span style={{ flex: 1, ...styles.body, fontSize: 14, margin: 0 }}>{v}</span>
              </div>
            ))}
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 10, maxWidth: 760 }}>
              The EMILIA receipt is <b>not</b> RATS Evidence. RATS can attest the platform or workload; EMILIA verifies an
              authorization artifact and its action binding under relying-party-pinned trust inputs. A named-human claim
              is only as strong as its independent enrollment and authority evidence; EMILIA does not prove a natural person.
            </p>

            <div style={{ ...styles.h3, marginTop: 24 }}>Statements &amp; lineage as SCITT Signed Statements (draft-ietf-scitt)</div>
            {[
              ['Signed Statement', 'an EMILIA authorization receipt / a COSA Bill of Lading — COSE_Sign1 over the exact action'],
              ['Transparency Service', 'the append-only log that registers the statements and orders them non-equivocally'],
              ['Receipt', 'the inclusion proof that a statement was logged — structural, not an authorization'],
              ['Lineage chain', 'EMILIA/COSA content: each hop carries a prev-state hash; SCITT logs the order, EMILIA supplies the link'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 14, padding: '9px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                <span style={{ flex: '0 0 130px', fontFamily: font.mono, fontSize: 13, color: goldText }}>{k}</span>
                <span style={{ flex: 1, ...styles.body, fontSize: 14, margin: 0 }}>{v}</span>
              </div>
            ))}
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 10, maxWidth: 760 }}>
              Keep the two &ldquo;receipts&rdquo; distinct: <b>authorization receipt</b> (EMILIA — authorization evidence bound to an action)
              vs <b>transparency / inclusion receipt</b> (SCITT — proof it was logged). An EMILIA profile can supply the
              lineage link and authorization evidence; SCITT can supply the tamper-evident log.
            </p>
          </div>
        </section>

        {/* HONEST FRAMING */}
        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 760 }}>
              <b>Honest framing.</b> The four-document path above is the repository&rsquo;s canonical reader-facing surface,
              not a Datatracker consolidation or external adoption claim. The repository tracks 22 active Datatracker
              records as of August 3, 2026.
              The latest six filings are{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/" style={{ color: goldText }}>AEB -03</a>,{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/" style={{ color: goldText }}>AEC -05</a>,{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-model-to-matter/" style={{ color: goldText }}>Model-to-Matter -03</a>,{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-reliance-agreement/" style={{ color: goldText }}>Reliance Agreement -00</a>,{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-bounded-capability-receipts/" style={{ color: goldText }}>Bounded Capability Receipts -01</a>, and{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-bounded-execution-program/" style={{ color: goldText }}>Bounded Execution Program -00</a>.
              They are licensed Apache-2.0 where applicable, are <b>not</b> IETF standards, and do <b>not</b> imply
              endorsement by any working group. The relationships above are <b>complement relationships</b> — how
              EMILIA composes with these standards — not claims of adoption by the OAuth, RATS, SCITT, WIMSE, or
              any other WG.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
