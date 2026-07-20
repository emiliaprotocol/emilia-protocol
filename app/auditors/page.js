/**
 * /auditors — Verify an authorization receipt: a guide for auditors.
 * @license Apache-2.0
 *
 * The audit-firm channel (the SOC 2 playbook): auditors who learn to verify
 * authorization receipts independently become distribution — every engagement where a
 * receipt is re-verified in workpapers normalizes the evidence format. Written
 * for assurance professionals, not engineers: what the artifact is, how to
 * re-verify it without trusting the auditee (or us), what to record, and the
 * honest boundary of what offline verification does and does not prove.
 */

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius, styles } from '@/lib/tokens';

export const metadata = {
  title: 'Verify an Authorization Receipt — A Guide for Auditors — EMILIA Protocol',
  description:
    'How SOC 2, ISO 42001, and EU AI Act assessors independently verify EMILIA authorization receipts and Class-A device signoffs: two minutes, offline, no reliance on the auditee or on EMILIA.',
  alternates: { canonical: '/auditors' },
};

const CHECKS = [
  ['challenge_binding', 'The approval is bound to this exact action. Any altered parameter — amount, payee, target — invalidates it.'],
  ['user_verified', 'The approver passed biometric or PIN verification (Face ID · Touch ID · passkey) at the moment of approval.'],
  ['user_present', 'A human was physically present at the signing device.'],
  ['signature', 'Signed by an enrolled device key (ECDSA P-256); receipts are signed by the issuer (Ed25519). Attribution requires the relying party’s independently trusted key/directory binding.'],
  ['client_data_type', 'A genuine authenticator assertion — not a replayed enrollment ceremony.'],
  ['rp_id_hash', 'The signature is scoped to the expected service, not lifted from another site.'],
  ['anchor', 'For receipts: included in the published Merkle anchor — the history cannot be silently rewritten.'],
];

const WORKPAPER_FIELDS = [
  ['receipt_id / signoff id', 'The artifact’s identifier, from the evidence packet'],
  ['action / context hash', 'The digest the approval is bound to'],
  ['key_class', 'A = approver-held device key (highest); C = platform-held'],
  ['verifier + version', 'e.g. @emilia-protocol/verify 3.8.0 (record the version you ran)'],
  ['result', 'valid: true/false and each individual check'],
  ['verified on / by', 'Date and team member — the verification is reproducible by anyone'],
];

const RED_FLAGS = [
  'A governed action class (e.g. payment release) with no receipt produced for a sampled transaction — absence of evidence is the finding.',
  'key_class C on actions the auditee’s own policy designates as requiring Class A (approver-held key).',
  'challenge_binding: false on any artifact — the approval evidence does not match the action it is attached to.',
  'Receipts that can only be “verified” inside the auditee’s or vendor’s own dashboard. Independently verifiable evidence requires no such access.',
];

const SIEM_FIELDS = [
  ['@version', 'Format identifier (EP-RECEIPT-v1)'],
  ['payload.receipt_id', 'Unique receipt identifier'],
  ['payload.action_hash', 'SHA-256 digest of the canonicalized action'],
  ['payload.approver_id / key_class', 'Named approver and authenticator class'],
  ['payload.decision', 'approved / rejected'],
  ['signature.algorithm / value', 'Signature material (verify before ingest)'],
  ['anchor.merkle_root', 'Anchor for tamper-evidence correlation'],
];

export default function AuditorsPage() {
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 860, margin: '0 auto', padding: '56px 24px 96px' }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          For auditors &amp; compliance reviewers
        </div>
        <h1 style={{ ...styles.h1, maxWidth: 740 }}>Verify an authorization receipt yourself. Two minutes, offline, no one&rsquo;s word for it.</h1>
        <p style={{ ...styles.body, maxWidth: 700 }}>
          An <strong>authorization receipt</strong> (formerly Trust Receipt) is a signed, machine-verifiable evidence packet proving that an enrolled
          approver key authorized a specific AI-agent action before it executed. When the auditor independently trusts the
          directory binding for that key, the receipt supports attribution to the named approver. Unlike an audit log — which <em>asserts</em> what
          happened inside a system you cannot inspect — a receipt is something you <strong>re-verify yourself</strong>,
          with public-key cryptography, without relying on the auditee&rsquo;s systems or on EMILIA.
        </p>
        <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 700, marginBottom: 44 }}>
          Written for U.S. government auditors (GAGAS / the GAO Yellow Book), single-audit practitioners and state
          auditors, SOC 2 and ISO/IEC 42001 assessors, EU AI Act conformity reviewers, and internal audit. No
          cryptography background required.
        </p>

        {/* The 4 steps */}
        <h2 style={styles.h2}>The verification procedure</h2>
        <ol style={{ ...styles.list, marginBottom: 36 }}>
          <li style={{ marginBottom: 14 }}>
            <strong style={{ color: color.t1 }}>Obtain the evidence packet.</strong> Request the receipt or device-signoff
            JSON for the sampled action from the auditee. Some packets carry a public key for a self-consistency check,
            but a key carried by the artifact cannot establish its own identity. Obtain the relying party&rsquo;s
            independently pinned issuer key and, for named-person attribution, the trusted approver-directory binding.
            If the auditee can only show you a dashboard, that is a finding, not evidence.
          </li>
          <li style={{ marginBottom: 14 }}>
            <strong style={{ color: color.t1 }}>Re-verify it independently.</strong> Two equivalent paths:
            in the browser at <a href="/verify" style={lnk}>emiliaprotocol.ai/verify</a> (the check runs locally in your
            tab — open the network panel and observe that nothing uploads), or fully offline in a terminal:
            <pre style={preStyle}>npx @emilia-protocol/verify receipt.json</pre>
            The verifier is open source (Apache-2.0, published on npm) — your firm can pin and review the exact code it ran.
            Firms standardizing on Python or Go can use the equivalent reference verifiers
            (<a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/packages/python-verify" style={lnk} target="_blank" rel="noopener noreferrer">Python</a>,{' '}
            <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/packages/go-verify" style={lnk} target="_blank" rel="noopener noreferrer">Go</a>) in the same
            public repository — three same-team reference ports, all held to the same published conformance
            suites (21 active suites and 328 vectors), so the verdict does not depend on which language your team runs.
          </li>
          <li style={{ marginBottom: 14 }}>
            <strong style={{ color: color.t1 }}>Read the checks.</strong> Each line is one verified property (table below).
            A valid artifact passes all of them; any single failure invalidates it.
          </li>
          <li>
            <strong style={{ color: color.t1 }}>Record the result.</strong> The workpaper fields below make the
            verification reproducible by anyone, years later — the receipt does not expire and does not need our servers.
          </li>
        </ol>

        {/* Check meanings */}
        <h2 style={styles.h2}>What each check proves</h2>
        <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden', marginBottom: 36 }}>
          {CHECKS.map(([key, meaning], i) => (
            <div key={key} style={{ display: 'flex', gap: 16, padding: '13px 20px', borderTop: i ? `1px solid ${color.border}` : 'none', background: color.card }}>
              <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.blue, flexShrink: 0, width: 150, lineHeight: '20px' }}>{key}</code>
              <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.55 }}>{meaning}</span>
            </div>
          ))}
        </div>

        {/* Honest boundary */}
        <div style={{ background: '#FFFBEB', border: `1px solid ${color.gold}`, borderRadius: radius.base, padding: '18px 22px', marginBottom: 36 }}>
          <div style={{ fontWeight: 700, fontSize: 14.5, color: color.t1, marginBottom: 6 }}>The honest boundary: what offline verification does not prove</div>
          <p style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.65, margin: 0 }}>
            Offline verification proves the artifact is <strong>authentic, intact, and bound to the exact action under
            the verifier&rsquo;s pinned inputs</strong>. It does not independently prove the real-world identity of the
            person named by an approver identifier; that attribution rests on the enrollment ceremony and directory
            authority the auditor chooses to trust.
            A revocation can also be evidenced offline: a <strong>portable, signed revocation statement</strong>
            (EP-REVOCATION-v1) is checkable with <code>npx @emilia-protocol/verify revocation</code>, fail-closed, with no
            EP server. What offline checking cannot prove is a <strong>negative</strong> — the <em>absence</em> of a
            revocation you were never handed (a liveness/transparency problem), and <strong>one-time use</strong> (that a
            signoff was consumed exactly once) remains server-state. The question to ask the auditee:
            <em>&ldquo;Show me your consumption record and any revocation statement for this signoff_id.&rdquo;</em> A
            conformant deployment rejects replays before any state changes.
          </p>
        </div>

        {/* Workpapers */}
        <h2 style={styles.h2}>What to record in workpapers</h2>
        <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden', marginBottom: 36 }}>
          {WORKPAPER_FIELDS.map(([field, note], i) => (
            <div key={field} style={{ display: 'flex', gap: 16, padding: '12px 20px', borderTop: i ? `1px solid ${color.border}` : 'none', background: color.card }}>
              <span style={{ fontSize: 13.5, fontWeight: 600, color: color.t1, flexShrink: 0, width: 175 }}>{field}</span>
              <span style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.5 }}>{note}</span>
            </div>
          ))}
        </div>

        <a href="/briefs/emilia-auditor-workpaper-sample.pdf" target="_blank" rel="noopener noreferrer" style={{ display: 'inline-block', fontFamily: font.mono, fontSize: 13, color: color.t1, fontWeight: 600, textDecoration: 'none', border: `1px solid ${color.borderHover}`, borderRadius: radius.sm, padding: '10px 18px', marginBottom: 40 }}>
          &darr; Download a completed sample workpaper (PDF)
        </a>

        {/* Red flags */}
        <h2 style={styles.h2}>Red flags</h2>
        <ul style={{ ...styles.list, marginBottom: 36 }}>
          {RED_FLAGS.map((f, i) => <li key={i} style={{ marginBottom: 8 }}>{f}</li>)}
        </ul>

        {/* SIEM */}
        <h2 style={styles.h2}>Ingesting receipts into a SIEM</h2>
        <p style={{ ...styles.body, maxWidth: 700 }}>
          Receipts are canonical JSON (RFC 8785) — Splunk, Datadog, and Elastic parse them natively, which lets a
          compliance dashboard correlate every governed action with its human approval. Core fields:
        </p>
        <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden', marginBottom: 12 }}>
          {SIEM_FIELDS.map(([field, note], i) => (
            <div key={field} style={{ display: 'flex', gap: 16, padding: '11px 20px', borderTop: i ? `1px solid ${color.border}` : 'none', background: color.card }}>
              <code style={{ fontFamily: font.mono, fontSize: 12, color: color.blue, flexShrink: 0, width: 220 }}>{field}</code>
              <span style={{ fontSize: 13.5, color: color.t2 }}>{note}</span>
            </div>
          ))}
        </div>
        <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.6, marginBottom: 44 }}>
          Full schema in the <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/" style={lnk} target="_blank" rel="noopener noreferrer">specification</a>. Verify signatures before ingest; treat the SIEM copy as an index, the signed JSON as the evidence.
        </p>

        {/* Sector mappings + CTA */}
        <h2 style={styles.h2}>Compliance and control mappings</h2>
        <ul style={{ ...styles.list, marginBottom: 40 }}>
          <li><a href="/compliance/emilia-gagas-greenbook-government.pdf" style={lnk}>U.S. government audit mapping — GAGAS / GAO Green Book / Uniform Guidance (2 CFR 200)</a></li>
          <li><a href="/compliance/emilia-eu-ai-act-financial-services.pdf" style={lnk}>EU AI Act mapping — financial services</a></li>
          <li><a href="/compliance/emilia-eu-ai-act-government.pdf" style={lnk}>EU AI Act mapping — government programs</a></li>
          <li><a href="/compliance/emilia-eu-ai-act-healthcare.pdf" style={lnk}>EU AI Act mapping — healthcare</a></li>
          <li><a href="/compliance/emilia-soc2-evidence-map.pdf" style={lnk}>SOC 2 evidence map — authorization receipts → CC6.1 / CC6.2 / CC7.2 / CC7.3</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/EMILIA-FOR-SOX-CONTROLS.md" style={lnk} target="_blank" rel="noopener noreferrer">SOX ICFR mapping — receipts as authorization evidence in key controls (§302/404)</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/EMILIA-FOR-TREASURY-PAYMENT-CONTROLS.md" style={lnk} target="_blank" rel="noopener noreferrer">Treasury and payment controls mapping — wires, beneficiary changes, releases</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/NIST-AI-RMF-MAPPING.md" style={lnk} target="_blank" rel="noopener noreferrer">NIST AI RMF mapping — MEASURE / MANAGE subcategories, per-subcategory evidence</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/EMILIA-FOR-AGENTIC-AI-RUNTIME-CONTROLS.md" style={lnk} target="_blank" rel="noopener noreferrer">Agentic AI runtime controls — evidence for agent-action oversight testing</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/EMILIA-FOR-PUBLIC-BENEFITS-INTEGRITY.md" style={lnk} target="_blank" rel="noopener noreferrer">Public benefits integrity — improper-payment and disbursement controls</a></li>
          <li><a href="/human-control" style={lnk}>Human-control crosswalk — EU AI Act Art. 14, NIST, ISO/IEC 42001 side by side</a></li>
          <li><a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/AUDITOR-CONTROL-CATALOG.md" style={lnk} target="_blank" rel="noopener noreferrer">Auditor control catalog — copy-paste RCM rows with executable test commands</a></li>
        </ul>

        <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
          <div style={{ fontWeight: 700, fontSize: 16, color: color.t1, marginBottom: 6 }}>Bring this to a client&rsquo;s control test</div>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: '0 0 14px' }}>
            Auditors are how this evidence format spreads: every engagement where a receipt is re-verified in
            workpapers normalizes it. Forward the <a href="/briefs/emilia-auditor-workpaper-sample.pdf" style={lnk} target="_blank" rel="noopener noreferrer">sample workpaper</a> to
            the team running the control test &mdash; it shows exactly what to record. Want a 30-minute briefing?
            We&rsquo;ll walk your team through a live verification on your own laptops, including a forged receipt your
            team catches themselves. Try it first-hand now: <a href="/try" style={lnk}>approve an action with Face&nbsp;ID on /try</a>,
            then verify what you signed on <a href="/verify" style={lnk}>/verify</a>.
          </p>
          <a href="mailto:team@emiliaprotocol.ai?subject=Auditor%20briefing" style={{ fontFamily: font.mono, fontSize: 13, color: color.t1, fontWeight: 600, textDecoration: 'none', border: `1px solid ${color.borderHover}`, borderRadius: radius.sm, padding: '10px 18px', display: 'inline-block' }}>
            team@emiliaprotocol.ai →
          </a>
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

const lnk = { color: color.blue, textDecoration: 'none' };
const preStyle = {
  background: color.card,
  border: `1px solid ${color.border}`,
  borderRadius: radius.sm,
  padding: '10px 14px',
  fontFamily: font.mono,
  fontSize: 13,
  color: color.t1,
  margin: '10px 0 4px',
  whiteSpace: 'pre-wrap',
};
