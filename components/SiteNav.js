'use client';

const NAV_LINKS = [
  ['/', 'Overview'],
  ['/demo.html', 'Demo'],
  ['/quickstart.html', 'Quickstart'],
  ['/spec', 'Docs'],
  ['/partners', 'Partners'],
];

const FOOTER_LINKS = [
  ['/governance', 'Governance'],
  ['/partners', 'Partners'],
  ['mailto:team@emiliaprotocol.ai', 'Contact'],
  ['/investors', 'Investor Inquiries'],
];

export default function SiteNav({ activePage, showFooter = false }) {
  return (
    <>
    <nav style={{
      position: 'sticky', top: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 40px', height: 60,
      left: 0, right: 0, width: '100%', boxSizing: 'border-box',
      background: 'rgba(0,0,0,0.85)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
    }}>
      <a href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none', flexShrink: 0 }}>
        <svg width="34" height="34" viewBox="0 0 34 34" fill="none">
          <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#sng)"/>
          <rect x="9.5" y="5" width="16" height="2.5" rx="1.25" fill="#60a5fa"/>
          <rect x="9.5" y="15.5" width="12" height="2.5" rx="1.25" fill="#f59e0b"/>
          <rect x="9.5" y="26.5" width="14" height="2.5" rx="1.25" fill="#60a5fa"/>
          <defs><linearGradient id="sng" x1="8" y1="5" x2="8" y2="29"><stop offset="0%" stopColor="#60a5fa"/><stop offset="100%" stopColor="#f59e0b"/></linearGradient></defs>
        </svg>
        <span style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontWeight: 700, fontSize: 14, letterSpacing: 3,
          color: '#e8e6e3', textTransform: 'uppercase',
        }}>EMILIA</span>
      </a>

      <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
        {NAV_LINKS.map(([href, label]) => (
          <a key={label} href={href}
            style={{
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
              color: label === activePage ? '#00d4ff' : '#4a4f6a',
              textDecoration: 'none', transition: 'color 0.2s',
            }}
            onMouseEnter={e => { if (label !== activePage) e.target.style.color = '#00d4ff'; }}
            onMouseLeave={e => { if (label !== activePage) e.target.style.color = '#4a4f6a'; }}
          >{label}</a>
        ))}
      </div>

      <a href="/partners#inquiry" style={{
        background: '#00d4ff', color: '#05060a',
        padding: '8px 18px', borderRadius: 8,
        textDecoration: 'none', fontSize: 12,
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
        flexShrink: 0,
      }}>Partner with Us</a>
    </nav>

    {showFooter && (
      <footer style={{
        borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '40px 40px 32px', marginTop: 80,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', letterSpacing: 1 }}>
          EMILIA PROTOCOL · APACHE 2.0
        </div>
        <div style={{ display: 'flex', gap: 24 }}>
          {FOOTER_LINKS.map(([href, label]) => (
            <a key={label} href={href} style={{
              fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
              color: '#4a4f6a', textDecoration: 'none', letterSpacing: 1,
              textTransform: 'uppercase',
            }}>{label}</a>
          ))}
        </div>
      </footer>
    )}
    </>
  );
}

export { FOOTER_LINKS };
