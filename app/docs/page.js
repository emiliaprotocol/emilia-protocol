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
