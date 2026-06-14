import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Documentation | EMILIA Protocol',
  description: 'Technical documentation, specifications, and integration guides for EP.',
};

const DOC_SECTIONS = [
  { title: 'Architecture', desc: 'System architecture, component topology, and deployment models.', href: '/spec' },
  { title: 'Security', desc: 'Threat model, cryptographic bindings, and security guarantees.', href: '/spec' },
  { title: 'Conformance', desc: 'Conformance levels, test suites, and certification process.', href: '/spec' },
  { title: 'API Reference', desc: 'OpenAPI specification for the 5-endpoint ceremony flow.', href: '/spec' },
  { title: 'Operations', desc: 'Deployment guides, monitoring, and operational runbooks.', href: '/quickstart' },
  { title: 'Positioning', desc: 'How EP compares to existing authorization frameworks.', href: '/spec' },
  { title: 'Guides', desc: 'Integration guides, SDK quickstarts, and tutorials.', href: '/quickstart' },
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

export default function DocsPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Docs" />
      <div style={{ ...styles.sectionWide, paddingTop: 100, paddingBottom: 80, maxWidth: 900 }}>
        <div style={styles.eyebrow}>Documentation</div>
        <h1 style={styles.h1}>EMILIA Protocol Docs</h1>
        <p style={{ ...styles.body, maxWidth: 620 }}>Technical documentation, specifications, and integration guides for EP.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          {DOC_SECTIONS.map(doc => (
            <a key={doc.title} href={doc.href} className="ep-card-hover" style={{ ...styles.card, textDecoration: 'none', color: color.t1, display: 'block' }}>
              <div style={styles.cardTitle}>{doc.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 12 }}>{doc.desc}</div>
              <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 500, color: color.blue, letterSpacing: 1 }}>View &#8594;</span>
            </a>
          ))}
        </div>
        <div style={{ marginTop: 48, padding: '32px 0', borderTop: `1px solid ${color.border}` }}>
          <div style={{ ...styles.h3, fontSize: 18 }}>Experimental extension profiles</div>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, maxWidth: 620, marginBottom: 16 }}>
            EXPERIMENTAL · additive over the frozen EP-RECEIPT-v1 · each governed by a Draft PIP. Not
            part of the frozen core and not production-ready. Spec proposals and conformance vectors live
            on GitHub.
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
