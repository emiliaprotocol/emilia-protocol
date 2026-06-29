/**
 * /rfp — RFP Language for AI Accountability.
 * @license Apache-2.0
 *
 * Pre-written procurement clauses a buyer can paste into an RFP or vendor
 * questionnaire. The strategic mechanism: the clauses are anchored to the open
 * EP specification (draft-schrock-ep-authorization-receipts), not to EMILIA the
 * vendor — any conformant implementation satisfies them. Every RFP that carries
 * the clause plants the spec in a procurement file.
 */

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius, styles } from '@/lib/tokens';

export const metadata = {
  title: 'RFP Language for AI Accountability — EMILIA Protocol',
  description:
    'Copy-paste procurement clauses requiring offline-verifiable, cryptographically bound human approval for autonomous AI actions. Anchored to an open IETF-submitted specification — not to any vendor.',
  alternates: { canonical: '/rfp' },
};

const CLAUSES = [
  {
    id: 'A',
    title: 'Baseline — human approval for irreversible actions',
    use: 'Any procurement involving AI agents that can move money, change records, or communicate externally.',
    text: `The Vendor's AI agents and autonomous systems shall not execute Irreversible Actions — including funds transfers, payment-instruction or beneficiary changes, creation or modification of records in systems of record, outbound communications at scale, production configuration changes, and access-control changes — without prior approval by a named, authenticated human approver.

Each approval shall be cryptographically bound to the specific action's parameters (including amount, counterparty, target system, and validity window), such that any post-approval modification of those parameters invalidates the approval. Approvals shall be single-use and shall expire after a defined period.

For each approved Irreversible Action, the Vendor shall retain and produce on request evidence of the approval that the Customer can verify without reliance on Vendor-operated systems.`,
  },
  {
    id: 'B',
    title: 'EU AI Act — Article 14 human oversight',
    use: 'Systems in scope of Regulation (EU) 2024/1689 Annex III (high-risk) — obligations provisionally deferred to December 2, 2027 by the Digital Omnibus (May 2026); the requirements themselves are unchanged.',
    text: `For AI systems within scope of Regulation (EU) 2024/1689 (EU AI Act) Annex III, the Vendor shall implement technical measures enabling human oversight, intervention, and override consistent with Article 14, including pre-execution human approval for actions producing legal or similarly significant effects on natural persons.

The Vendor shall maintain records sufficient to demonstrate such oversight consistent with Article 12 (record-keeping), in a machine-verifiable format. Upon request, the Vendor shall provide the Customer with the records and the means to verify their integrity and authenticity independently of the Vendor, including verification while offline.

Statements of policy, manual review procedures, or dashboard-based approval queues that do not produce independently verifiable records shall not satisfy this requirement.`,
  },
  {
    id: 'C',
    title: 'Full specification — verifiable authorization receipts',
    use: 'High-assurance deployments: financial controls, government benefits, treasury, healthcare.',
    text: `For each approved Irreversible Action, the Vendor shall produce an authorization receipt containing at minimum:

(a) a cryptographic digest of the approved action computed over a canonical serialization of its parameters (e.g., RFC 8785 JSON Canonicalization Scheme);
(b) the identity of the human approver and the class of authenticator used;
(c) a digital signature produced by an approver-held key over material derived from the action digest — for high-assurance actions, a device-bound WebAuthn/FIDO2 assertion with user verification (biometric or PIN);
(d) issuance and expiry timestamps and single-use (anti-replay) semantics; and
(e) sufficient material for the Customer to verify the receipt offline using a published, open-source verifier distributed under an OSI-approved license.

Authorization receipts conforming to draft-schrock-ep-authorization-receipts (IETF, individual submission) or a successor specification satisfy this requirement in full.`,
  },
];

const RESPONSES = [
  ['“We maintain comprehensive audit logs.”', 'Logs are written after execution and assert rather than prove. They do not bind a human to the specific action before it ran.', 'fail'],
  ['“Approvals happen in our admin dashboard.”', 'Dashboard queues are server-state: the evidence lives in the vendor’s database and cannot be verified independently or offline.', 'fail'],
  ['“All operators use MFA / SSO.”', 'MFA authenticates a session identity. It does not bind anyone to one specific action’s parameters — the agent still acts under delegated credentials.', 'fail'],
  ['“Here is a signed receipt for each action; verify it with the open-source verifier — no access to our systems needed.”', 'This is the compliant shape: action-bound, human-bound, offline-verifiable.', 'pass'],
];

export default function RfpPage() {
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 860, margin: '0 auto', padding: '56px 24px 96px' }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          For buyers &amp; procurement teams
        </div>
        <h1 style={{ ...styles.h1, maxWidth: 720 }}>RFP language for AI accountability.</h1>
        <p style={{ ...styles.body, maxWidth: 680 }}>
          If your vendors run AI agents that can move money, change records, or contact your customers,
          your RFPs should require proof of human authorization — not promises of it. The clauses below are
          written to paste directly into an RFP, vendor questionnaire, or MSA security schedule.
        </p>
        <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 680, marginBottom: 40 }}>
          These clauses are anchored to an <strong style={{ color: color.t2 }}>open specification</strong>{' '}
          (<a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/" style={lnk} target="_blank" rel="noopener noreferrer">draft-schrock-ep-authorization-receipts</a>, IETF individual submission)
          — not to any vendor. Any conformant implementation satisfies them, including ours. That is the point:
          require the property, not the brand.
        </p>

        {CLAUSES.map((c) => (
          <section key={c.id} style={{ marginBottom: 36 }}>
            <h2 style={{ ...styles.h2, marginBottom: 6 }}>Clause {c.id} — {c.title}</h2>
            <p style={{ fontSize: 13, color: color.t3, margin: '0 0 14px' }}>
              <strong style={{ color: color.t2 }}>When to use:</strong> {c.use}
            </p>
            <pre style={{
              background: color.card,
              border: `1px solid ${color.border}`,
              borderRadius: radius.base,
              padding: '20px 22px',
              fontFamily: font.mono,
              fontSize: 13,
              lineHeight: 1.7,
              color: color.t1,
              whiteSpace: 'pre-wrap',
              margin: 0,
              userSelect: 'all',
            }}>{c.text}</pre>
          </section>
        ))}

        <section style={{ marginTop: 48 }}>
          <h2 style={styles.h2}>Evaluating vendor responses</h2>
          <p style={{ ...styles.body, maxWidth: 680 }}>
            The clause does the filtering for you. What you are listening for in responses:
          </p>
          <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
            {RESPONSES.map(([answer, why, verdict], i) => (
              <div key={i} style={{ display: 'flex', gap: 14, padding: '16px 20px', borderTop: i ? `1px solid ${color.border}` : 'none', background: verdict === 'pass' ? '#F0FDF4' : color.card }}>
                <span style={{ fontSize: 15, lineHeight: '22px', flexShrink: 0, color: verdict === 'pass' ? color.green : color.red }}>
                  {verdict === 'pass' ? '✓' : '✕'}
                </span>
                <div>
                  <div style={{ fontSize: 14.5, fontWeight: 600, color: color.t1, marginBottom: 4 }}>{answer}</div>
                  <div style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.6 }}>{why}</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section style={{ marginTop: 48 }}>
          <h2 style={styles.h2}>Compliance mappings by sector</h2>
          <p style={{ ...styles.body, maxWidth: 680 }}>
            Two-page mappings of EU AI Act articles to the receipt architecture, written for a compliance file:
          </p>
          <ul style={styles.list}>
            <li><a href="/compliance/emilia-eu-ai-act-financial-services.pdf" style={lnk}>Financial services (FinGuard)</a> — wire release, beneficiary changes, dual authorization</li>
            <li><a href="/compliance/emilia-eu-ai-act-government.pdf" style={lnk}>Government programs (GovGuard)</a> — vendor payment destinations, disbursements, benefit routing, provider enrollment, eligibility overrides</li>
            <li><a href="/compliance/emilia-eu-ai-act-healthcare.pdf" style={lnk}>Healthcare</a> — high-risk clinical and administrative actions</li>
          </ul>
        </section>

        <div style={{ marginTop: 48, paddingTop: 24, borderTop: `1px solid ${color.border}`, fontSize: 13, color: color.t3, lineHeight: 1.7 }}>
          Auditing a vendor that claims conformance? See the{' '}
          <a href="/auditors" style={lnk}>auditor&rsquo;s guide to verifying authorization receipts</a> — verification takes
          about two minutes and requires nothing from us. This page supports your procurement program; it is not legal advice.
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

const lnk = { color: color.blue, textDecoration: 'none' };
