import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, cta } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Deploy EMILIA Gate',
  description:
    'Deploy the EMILIA consequence firewall, connect an Approver app, verify open Protocol evidence, and re-perform it through the Assurance Plane.',
  alternates: { canonical: '/docs' },
  openGraph: {
    title: 'Deploy EMILIA Gate',
    description: 'Start at the enforcement boundary, then inspect the open Protocol and Assurance tooling underneath it.',
    url: 'https://www.emiliaprotocol.ai/docs',
    type: 'website',
  },
};

const DOC_SECTIONS = [
  {
    eyebrow: 'Deploy',
    title: 'Gate quickstart',
    desc: 'Place Gate before a configured mutating action and connect the verification and evidence paths.',
    href: '/quickstart',
  },
  {
    eyebrow: 'Developer on-ramp',
    title: 'Protect an MCP tool',
    desc: 'Require authorization evidence before a consequential MCP tool call reaches its executor.',
    href: '/guides/require-receipt',
  },
  {
    eyebrow: 'Inspect',
    title: 'Live Gate',
    desc: 'Walk through the challenge, evidence, decision, and refusal path in the browser.',
    href: '/gate/live',
  },
  {
    eyebrow: 'Human ceremony',
    title: 'Approver apps',
    desc: 'Capture a person’s decision over the material action fields and return signed evidence to Gate.',
    href: '/product/accountable-signoff',
  },
  {
    eyebrow: 'Re-performance',
    title: 'Assurance Plane',
    desc: 'Run open verification, preserve conformance records, and prepare bounded audit or underwriter packages.',
    href: '/assurance',
  },
  {
    eyebrow: 'Open substrate',
    title: 'Protocol and specifications',
    desc: 'Read the receipt formats, trust inputs, security boundaries, and interoperability documents.',
    href: '/protocol',
  },
  {
    eyebrow: 'Evidence',
    title: 'Engineering proof',
    desc: 'Inspect formal-model status, conformance vectors, security-case claims, and external verification evidence.',
    href: '/proof',
  },
  {
    eyebrow: 'Verify',
    title: 'Open verifier',
    desc: 'Check an artifact under explicit relying-party inputs without depending on EMILIA’s hosted service.',
    href: '/verify',
  },
];

const SYSTEM = [
  ['Gate', 'Mediates configured consequential actions at the executor boundary.', '/gate'],
  ['Approver Apps', 'Capture the human decision and return action-bound evidence.', '/product/accountable-signoff'],
  ['Protocol', 'Defines portable formats and open verification rules.', '/protocol'],
  ['Assurance', 'Re-performs the evidence and packages reproducible records.', '/assurance'],
];

const GH_BLOB = 'https://github.com/emiliaprotocol/emilia-protocol/blob/main';

// Experimental extension profiles — additive over the frozen EP-RECEIPT-v1,
// each governed by a Draft PIP. Not part of the frozen core. The site renders
// only the posted authorization-receipts I-D under /spec, so these link to the
// spec + conformance-vector source on GitHub.
const EXPERIMENTAL_PROFILES = [
  { profile: 'EP-PROVENANCE-CHAIN-v1', pip: 'PIP-009', spec: `${GH_BLOB}/docs/EP-PROVENANCE-RECEIPT-SPEC.md`, vectors: `${GH_BLOB}/conformance/vectors/provenance-chains.v1.json` },
  { profile: 'EP-DISPLAY-ATTESTATION-v1 / EP-EXECUTION-INTEGRITY-v1', pip: 'PIP-010', spec: `${GH_BLOB}/docs/EP-WYSIWYS-SPEC.md`, vectors: `${GH_BLOB}/conformance/vectors/wysiwys.v1.json` },
  { profile: 'EP-REVOCATION-v1', pip: 'PIP-011', spec: `${GH_BLOB}/docs/EP-REVOCATION-SPEC.md`, vectors: `${GH_BLOB}/conformance/vectors/revocation.v1.json` },
  { profile: 'EP-EYE-SET-v1', pip: 'PIP-011', spec: `${GH_BLOB}/docs/EP-EYE-SET-SPEC.md`, vectors: `${GH_BLOB}/conformance/vectors/eye-set.v1.json` },
];

export default function DocsPage(): React.JSX.Element {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Docs" />
      <div style={{ ...styles.sectionWide, paddingTop: 100, paddingBottom: 80, maxWidth: 900 }}>
        <div style={styles.eyebrow}>Documentation</div>
        <h1 style={styles.h1}>Deploy Gate first. Inspect every proof underneath it.</h1>
        <p style={{ ...styles.body, maxWidth: 690 }}>
          Start at the system that can create the consequence. Gate decides whether the configured action may
          proceed, Approver apps capture human decisions, the open Protocol makes the evidence portable, and
          Assurance re-performs the result.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 48 }}>
          <Link href="/quickstart" className="ep-cta" style={cta.primary}>Deploy Gate &rarr;</Link>
          <Link href="/protocol" className="ep-cta-secondary" style={cta.secondary}>Read the Protocol</Link>
        </div>

        <div style={{ borderTop: `1px solid ${color.border}`, marginBottom: 48 }}>
          {SYSTEM.map(([name, desc, href]) => (
            <Link
              key={name}
              href={href}
              className="ep-docs-system-row"
              style={{
                display: 'grid',
                gridTemplateColumns: '150px minmax(0, 1fr) auto',
                gap: 20,
                alignItems: 'center',
                padding: '18px 0',
                borderBottom: `1px solid ${color.border}`,
                textDecoration: 'none',
              }}
            >
              <strong style={{ fontFamily: font.sans, fontSize: 15, color: color.t1 }}>{name}</strong>
              <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.55 }}>{desc}</span>
              <span style={{ color: color.blue }}>&rarr;</span>
            </Link>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          {DOC_SECTIONS.map(doc => (
            <Link key={doc.title} href={doc.href} className="ep-card-hover" style={{ ...styles.card, textDecoration: 'none', color: color.t1, display: 'block' }}>
              <div style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: color.gold, marginBottom: 9 }}>{doc.eyebrow}</div>
              <div style={styles.cardTitle}>{doc.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 12 }}>{doc.desc}</div>
              <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 500, color: color.blue, letterSpacing: 1 }}>View &#8594;</span>
            </Link>
          ))}
        </div>
        <div style={{ marginTop: 48, padding: '32px 0', borderTop: `1px solid ${color.border}` }}>
          <div style={{ ...styles.h3, fontSize: 18 }}>Experimental extension profiles</div>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, maxWidth: 620, marginBottom: 16 }}>
            Additive proposals over EP-RECEIPT-v1, each governed by a Draft PIP. They are not part of the frozen
            core and are not presented here as production-ready. Spec proposals and conformance vectors live on GitHub.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16, marginBottom: 16 }}>
            {EXPERIMENTAL_PROFILES.map(p => (
              <div key={p.profile} style={{ ...styles.card }}>
                <div style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: color.gold, marginBottom: 8 }}>Experimental · {p.pip} (Draft)</div>
                <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 600, color: color.t1, marginBottom: 12, wordBreak: 'break-word' }}>{p.profile}</div>
                <a href={p.spec} target="_blank" rel="noopener noreferrer" style={{ display: 'block', fontSize: 13, color: color.blue, textDecoration: 'none', marginBottom: 6 }}>Spec proposal &#8594;</a>
                <a href={p.vectors} target="_blank" rel="noopener noreferrer" style={{ display: 'block', fontSize: 13, color: color.blue, textDecoration: 'none' }}>Conformance vectors &#8594;</a>
              </div>
            ))}
          </div>
        </div>

        <div style={{ padding: '32px 0', borderTop: `1px solid ${color.border}` }}>
          <div style={{ ...styles.h3, fontSize: 18 }}>Additional Resources</div>
          <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" rel="noopener noreferrer" style={{ display: 'block', fontSize: 14, color: color.blue, textDecoration: 'none', marginBottom: 8 }}>GitHub Repository</a>
          <a href="/quickstart" style={{ display: 'block', fontSize: 14, color: color.blue, textDecoration: 'none', marginBottom: 8 }}>Quickstart Guide</a>
          <a href="/governance" style={{ display: 'block', fontSize: 14, color: color.blue, textDecoration: 'none', marginBottom: 8 }}>Governance</a>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
