'use client';

import SiteNav from '@/components/SiteNav';

const DOC_SECTIONS = [
  { title: 'Architecture', desc: 'System architecture, component topology, and deployment models.', href: '/spec' },
  { title: 'Security', desc: 'Threat model, cryptographic bindings, and security guarantees.', href: '/spec' },
  { title: 'Conformance', desc: 'Conformance levels, test suites, and certification process.', href: '/spec' },
  { title: 'API Reference', desc: 'OpenAPI specification for the 5-endpoint ceremony flow.', href: '/spec' },
  { title: 'Operations', desc: 'Deployment guides, monitoring, and operational runbooks.', href: '/quickstart' },
  { title: 'Positioning', desc: 'How EP compares to existing authorization frameworks.', href: '/spec' },
  { title: 'Guides', desc: 'Integration guides, SDK quickstarts, and tutorials.', href: '/quickstart' },
];

const s = {
  page: { minHeight: '100vh', background: '#0a0f1e', color: '#f0f2f5', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  section: { maxWidth: 900, margin: '0 auto', padding: '100px 24px 80px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 16 },
  h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
  body: { fontSize: 16, color: '#8b95a5', lineHeight: 1.75, marginBottom: 48, maxWidth: 620 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 },
  card: {
    background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10,
    padding: '28px 24px', textDecoration: 'none', color: '#f0f2f5',
    transition: 'all 0.25s', display: 'block',
  },
  cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, marginBottom: 8 },
  cardDesc: { fontSize: 14, color: '#8b95a5', lineHeight: 1.65, marginBottom: 12 },
  cardLink: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, fontWeight: 500, color: '#4a90d9', letterSpacing: 1 },
  extLinks: { marginTop: 48, padding: '32px 0', borderTop: '1px solid rgba(255,255,255,0.06)' },
  extTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 18, fontWeight: 700, marginBottom: 16 },
  extLink: { display: 'block', fontSize: 14, color: '#4a90d9', textDecoration: 'none', marginBottom: 8, transition: 'color 0.2s' },
};

export default function DocsPage() {
  return (
    <div style={s.page}>
      <SiteNav activePage="Docs" />
      <div style={s.section}>
        <div style={s.eyebrow}>Documentation</div>
        <h1 style={s.h1}>EMILIA Protocol Docs</h1>
        <p style={s.body}>Technical documentation, specifications, and integration guides for EP.</p>
        <div style={s.grid}>
          {DOC_SECTIONS.map(doc => (
            <a key={doc.title} href={doc.href} style={s.card}
              onMouseEnter={e => { e.currentTarget.style.background = '#1a2238'; }}
              onMouseLeave={e => { e.currentTarget.style.background = '#111827'; }}
            >
              <div style={s.cardTitle}>{doc.title}</div>
              <div style={s.cardDesc}>{doc.desc}</div>
              <span style={s.cardLink}>View &#8594;</span>
            </a>
          ))}
        </div>
        <div style={s.extLinks}>
          <div style={s.extTitle}>Additional Resources</div>
          <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" rel="noopener noreferrer" style={s.extLink}>GitHub Repository</a>
          <a href="/quickstart" style={s.extLink}>Quickstart Guide</a>
          <a href="/governance" style={s.extLink}>Governance</a>
        </div>
      </div>
    </div>
  );
}
