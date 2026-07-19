// SPDX-License-Identifier: Apache-2.0
// /standards — EMILIA in the IETF landscape. Frames EP as a COMPLEMENT, not a
// competitor, to the accepted standards the ecosystem already runs: the
// human-authorization-receipt layer that Step-Up triggers, RATS/EAT sits beside,
// and SCITT logs. Content is verified IETF research presented cleanly — no
// re-research. Internal links use next/link <Link> (lint rule).

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'EMILIA in the IETF landscape — a complement, not a competitor | EMILIA',
  description:
    'EMILIA Protocol is the human-authorization-receipt layer. It composes with the accepted standards the ecosystem already runs — OAuth Step-Up triggers it, RATS/EAT sits beside it, SCITT logs it — rather than replacing them.',
};

// The three-pillar story.
const PILLARS = [
  {
    role: 'TRIGGER',
    status: 'deployed',
    title: 'OAuth Step-Up Authentication — RFC 9470 (Proposed Standard)',
    body:
      'Step-Up demands a fresh human challenge for a sensitive action, but produces no durable artifact. ' +
      'EMILIA is the offline, verifiable receipt of that step-up — the proof that survives after the challenge passes.',
  },
  {
    role: 'ORTHOGONAL TRUST ROOT',
    status: 'deployed',
    title: 'Machine attestation — RATS (RFC 9334) + EAT (RFC 9711), SPIFFE/SPIRE, WIMSE',
    body:
      'Attestation answers "is this agent’s platform trustworthy / which workload is this." ' +
      'EMILIA answers the orthogonal question: "did the DIRECTORY-BOUND APPROVER authorize THIS exact irreversible action." ' +
      'Same evidence bundle, different trust root.',
  },
  {
    role: 'ACCOUNTABILITY RAIL',
    status: 'standardizing now',
    title: 'SCITT — RFC 9943 + SCRAPI',
    body:
      'A SCITT "Receipt" is a transparency / INCLUSION proof: it proves a statement was logged in an append-only ledger. ' +
      'SCITT is deliberately AGNOSTIC about who authorized anything — that delegated-away question is exactly EMILIA’s payload. ' +
      'An EMILIA authorization receipt rides AS a SCITT Signed Statement; SCITT returns a transparency receipt that it was logged. ' +
      'Defuse the shared word: "authorization receipt" (EMILIA) vs "transparency / inclusion receipt" (SCITT).',
  },
];

// Tier 1 — published RFCs / deployed. Anchor here.
const TIER1 = [
  ['OAuth 2.0 / OIDC — RFC 6749', 'Published · ubiquitous', 'Grants access. EMILIA proves an enrolled approver authorized the exact act under the relying party’s pinned directory.'],
  ['Step-Up Authentication — RFC 9470', 'Proposed Standard', 'The trigger. EMILIA is the durable proof that the step-up happened.'],
  ['Rich Authorization Requests (RAR) — RFC 9396', 'Proposed Standard', 'EMILIA signs the human approval of the same authorization_details (RAR = request schema; EMILIA = evidence over it).'],
  ['RATS — RFC 9334 + EAT — RFC 9711', 'Published', 'Machine attestation (platform / workload). EMILIA = human authorization. Orthogonal trust roots, same bundle.'],
  ['HTTP Message Signatures — RFC 9421', 'Proposed Standard', 'EMILIA rides inside a signed request.'],
  ['JWS — RFC 7515 / COSE — RFC 9052 / CWT — RFC 8392', 'Published', 'Interop serializations EMILIA receipts express in.'],
  ['Token Exchange — RFC 8693', 'Proposed Standard', 'Delegates authority between services. EMILIA proves the human authorized the irreversible act at the chain’s end.'],
  ['SPIFFE / SPIRE', 'CNCF graduated', 'Agent identity. EMILIA adds who approved what it does.'],
  ['Trusted timestamp — RFC 3161 · Evidence Record Syntax (ERS) — RFC 4998 · JCS — RFC 8785', 'Published', 'RFC 3161 trusted time; RFC 4998 ERS is the lineage for EMILIA’s evidence-record renewal; JCS is EMILIA’s canonical base.'],
];

// Tier 2 — active drafts. Position relative to; do not anchor.
const TIER2 = [
  ['SCITT — architecture + SCRAPI + COSE Receipts', 'Active drafts', 'EMILIA authorization receipts ride as SCITT Signed Statements; SCITT logs them and returns transparency receipts.'],
  ['OAuth Transaction Tokens (Txn-Tokens)', 'Active draft', 'Short-lived call-chain context. EMILIA is the human-authorization evidence over the irreversible act, not the transport token.'],
  ['WIMSE (Workload Identity in Multi-System Environments)', 'Active drafts', 'Workload identity. EMILIA adds the human-authorization layer above the workload trust root.'],
  ['SD-JWT-VC / EUDI', 'Active drafts', 'Selective-disclosure credentials. EMILIA receipts can be carried / referenced; the authorization claim is EMILIA’s.'],
];

function StatusPill({ children }) {
  return (
    <span style={{
      fontFamily: font.mono, fontSize: 11, color: color.t3,
      border: `1px solid ${color.border}`, borderRadius: 4, padding: '2px 8px',
      whiteSpace: 'nowrap',
    }}>{children}</span>
  );
}

function ComplementTable({ rows }) {
  return (
    <div style={{ overflowX: 'auto', marginTop: 14 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
        <thead>
          <tr>
            <th style={{ ...(/** @type {import('react').CSSProperties} */ (styles.tableHead)), width: '38%' }}>Standard</th>
            <th style={{ ...(/** @type {import('react').CSSProperties} */ (styles.tableHead)), width: '16%' }}>Status</th>
            <th style={/** @type {import('react').CSSProperties} */ (styles.tableHead)}>How EMILIA complements it</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([standard, status, how]) => (
            <tr key={standard}>
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
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 24 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>IETF LANDSCAPE · COMPLEMENT, NOT COMPETITOR</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>
              EMILIA in the IETF landscape &mdash; a complement, not a competitor.
            </h1>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              EMILIA Protocol is the <b>human-authorization-receipt layer</b>. It composes with the accepted standards the
              ecosystem already runs &mdash; it rides inside them, sits beside them, and is logged by them &mdash; rather
              than replacing any of them. The receipt EMILIA produces is the one durable artifact none of these standards
              emit on their own: portable, offline-verifiable proof that a directory-bound approver authorized one exact
              irreversible action. Attribution to a real-world person is only as strong as the independently trusted
              enrollment and directory binding.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
              <Link href="/fire-drill/rr-1" style={cta.primary}>See it on a real action</Link>
              <Link href="/spec" style={cta.secondary}>Read the spec</Link>
            </div>
          </div>
        </section>

        {/* THE 3-PILLAR STORY */}
        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>The three-pillar story</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12 }}>
              EMILIA is the human-authorization receipt that <b>Step-Up triggers</b>, <b>RATS/EAT sits beside</b>, and{' '}
              <b>SCITT logs</b>.
            </p>
            <div style={{ marginTop: 10 }}>
              {PILLARS.map((p) => (
                <div key={p.role} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ ...styles.eyebrow, color: color.gold, marginBottom: 0 }}>{p.role}</span>
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
            <div style={{ ...styles.eyebrow, color: color.gold }}>TIER 1 · PUBLISHED RFCs / DEPLOYED — ANCHOR HERE</div>
            <h2 style={styles.h2}>Where EMILIA composes today</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              These are shipped, widely-deployed standards. EMILIA does not compete with any of them; it supplies the
              human-authorization evidence that sits on top.
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
              same authorization claim travels across all three &mdash; no lock-in to a wire format.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 12, flexWrap: 'wrap' }}>
              <Link href="/fire-drill/rr-1" style={cta.secondary}>Receipt on a real action</Link>
              <Link href="/spec" style={cta.secondary}>draft-schrock-ep-authorization-receipts</Link>
            </div>
          </div>
        </section>

        {/* RATS + SCITT MAPPING DETAIL */}
        <section style={{ ...styles.sectionWide, paddingTop: 24, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>MAPPING DETAIL · RATS + SCITT PROFILES</div>
            <h2 style={styles.h2}>How EMILIA expresses as RATS and SCITT profiles</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 4 }}>
              Two narrow profiles on accepted work &mdash; not a new framework. Machine attestation (RATS) and the
              human-authorization receipt (EMILIA) are orthogonal and meet at the relying party.
            </p>

            <div style={{ ...styles.h3, marginTop: 22 }}>The attest loop as a RATS profile (RFC&nbsp;9334)</div>
            {[
              ['Attester', 'the agent / host — produces Evidence about its compute context'],
              ['Verifier', 'the “God Terminal” — appraises Evidence into an Attestation Result'],
              ['Relying Party', 'the gateway / substrate — consumes the Attestation Result AND the EMILIA authorization receipt'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 14, padding: '9px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                <span style={{ flex: '0 0 130px', fontFamily: font.mono, fontSize: 13, color: color.gold }}>{k}</span>
                <span style={{ flex: 1, ...styles.body, fontSize: 14, margin: 0 }}>{v}</span>
              </div>
            ))}
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 10, maxWidth: 760 }}>
              The EMILIA receipt is <b>not</b> RATS Evidence &mdash; RATS attests the platform; EMILIA attests the human.
              Different trust roots (platform root-of-trust vs the human&rsquo;s device key), composed at the relying party.
            </p>

            <div style={{ ...styles.h3, marginTop: 24 }}>Statements &amp; lineage as SCITT Signed Statements (draft-ietf-scitt)</div>
            {[
              ['Signed Statement', 'an EMILIA authorization receipt / a COSA Bill of Lading — COSE_Sign1 over the exact action'],
              ['Transparency Service', 'the append-only log that registers the statements and orders them non-equivocally'],
              ['Receipt', 'the inclusion proof that a statement was logged — structural, not an authorization'],
              ['Lineage chain', 'EMILIA/COSA content: each hop carries a prev-state hash; SCITT logs the order, EMILIA supplies the link'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 14, padding: '9px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                <span style={{ flex: '0 0 130px', fontFamily: font.mono, fontSize: 13, color: color.gold }}>{k}</span>
                <span style={{ flex: 1, ...styles.body, fontSize: 14, margin: 0 }}>{v}</span>
              </div>
            ))}
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 10, maxWidth: 760 }}>
              Keep the two &ldquo;receipts&rdquo; distinct: <b>authorization receipt</b> (EMILIA &mdash; who authorized what)
              vs <b>transparency / inclusion receipt</b> (SCITT &mdash; proof it was logged). EMILIA supplies the lineage
              link and the human authorization; SCITT supplies the tamper-evident log.
            </p>
          </div>
        </section>

        {/* HONEST FRAMING */}
        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 760 }}>
              <b>Honest framing.</b> EMILIA currently has four active individual Internet-Drafts:{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/" style={{ color: color.gold }}>
                Authorization Receipts -06
              </a>,{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/" style={{ color: color.gold }}>
                EP-QUORUM -02
              </a>, and{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/" style={{ color: color.gold }}>
                EP-AEC -02
              </a>, and{' '}
              <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-evidence-record/" style={{ color: color.gold }}>
                EP-EVIDENCE-RECORD -01
              </a>. They are licensed Apache-2.0 where applicable, are <b>not</b> IETF standards, and do <b>not</b> imply
              endorsement by any working group. The relationships above are <b>complement relationships</b> &mdash; how
              EMILIA composes with these standards &mdash; not claims of adoption by the OAuth, RATS, SCITT, WIMSE, or
              any other WG.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
