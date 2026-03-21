'use client';

const NAV_LINKS = [
  ['/', 'Overview'],
  ['/demo.html', 'Demo'],
  ['/quickstart', 'Quickstart'],
  ['/spec', 'Docs'],
  ['/partners', 'Partners'],
  ['https://github.com/emiliaprotocol/emilia-protocol', 'GitHub'],
];

const GOV_LINKS = [
  ['/appeal', 'Appeal'],
  ['/operators', 'Operators'],
  ['/apply', 'Apply'],
  ['/governance', 'Governance'],
];

const FOOTER_LINKS = [
  ['/partners', 'Partners'],
  ['mailto:team@emiliaprotocol.ai', 'Contact'],
  ['/investors', 'Investor Inquiries'],
];

const FOOTER_GOV_LINKS = [
  ['/governance', 'Governance'],
  ['/operators', 'Operators'],
  ['/apply', 'Apply'],
  ['/appeal', 'Appeal'],
];

export default function SiteNav({ activePage }) {
  return (
    <nav style={{
      position: 'sticky', top: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 40px', height: 60,
      left: 0, right: 0, width: '100%', boxSizing: 'border-box',
      background: 'rgba(10,15,30,0.88)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
    }}>
      <a href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none', flexShrink: 0 }}>
        <svg width="34" height="34" viewBox="0 0 34 34" fill="none">
          <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#sng)"/>
          <rect x="9.5" y="5" width="16" height="2.5" rx="1.25" fill="#4a90d9"/>
          <rect x="9.5" y="15.5" width="12" height="2.5" rx="1.25" fill="#d4af55"/>
          <rect x="9.5" y="26.5" width="14" height="2.5" rx="1.25" fill="#4a90d9"/>
          <defs><linearGradient id="sng" x1="8" y1="5" x2="8" y2="29"><stop offset="0%" stopColor="#4a90d9"/><stop offset="100%" stopColor="#d4af55"/></linearGradient></defs>
        </svg>
        <span style={{
          fontFamily: "'IBM Plex Mono', monospace",
          fontWeight: 700, fontSize: 14, letterSpacing: 3,
          color: '#f0f2f5', textTransform: 'uppercase',
        }}>EMILIA</span>
      </a>

      <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
        {NAV_LINKS.map(([href, label]) => (
          <a key={label} href={href}
            target={href.startsWith('http') ? '_blank' : undefined}
            rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
            style={{
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
              color: label === activePage ? '#d4af55' : '#8b95a5',
              textDecoration: 'none', transition: 'color 0.2s',
              borderBottom: label === activePage ? '2px solid #d4af55' : '2px solid transparent',
              paddingBottom: 2,
            }}
            onMouseEnter={e => { if (label !== activePage) e.target.style.color = '#d4af55'; }}
            onMouseLeave={e => { if (label !== activePage) e.target.style.color = '#8b95a5'; }}
          >{label}</a>
        ))}

        {/* Governance / Accountability dropdown */}
        <div style={{ position: 'relative' }}
          onMouseEnter={e => { const dd = e.currentTarget.querySelector('[data-gov-dd]'); if (dd) dd.style.display = 'flex'; }}
          onMouseLeave={e => { const dd = e.currentTarget.querySelector('[data-gov-dd]'); if (dd) dd.style.display = 'none'; }}
        >
          <span style={{
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
            color: GOV_LINKS.some(([, l]) => l === activePage) ? '#d4af55' : '#8b95a5',
            cursor: 'pointer', transition: 'color 0.2s', userSelect: 'none',
            borderBottom: GOV_LINKS.some(([, l]) => l === activePage) ? '2px solid #d4af55' : '2px solid transparent',
            paddingBottom: 2,
          }}>Accountability &#9662;</span>
          <div data-gov-dd="" style={{
            display: 'none', flexDirection: 'column', position: 'absolute',
            top: '100%', left: 0, marginTop: 8,
            background: 'rgba(10,15,30,0.97)', border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 10, padding: '8px 0', minWidth: 160, zIndex: 200,
            backdropFilter: 'blur(12px)',
          }}>
            {GOV_LINKS.map(([href, label]) => (
              <a key={label} href={href} style={{
                fontFamily: "'IBM Plex Mono', monospace",
                fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
                color: label === activePage ? '#d4af55' : '#8b95a5',
                textDecoration: 'none', padding: '8px 16px', transition: 'color 0.2s',
              }}
                onMouseEnter={e => { e.target.style.color = '#d4af55'; }}
                onMouseLeave={e => { if (label !== activePage) e.target.style.color = '#8b95a5'; }}
              >{label}</a>
            ))}
          </div>
        </div>
      </div>

      <a href="/partners#inquiry" style={{
        background: 'transparent', color: '#d4af55',
        padding: '8px 18px', borderRadius: 8,
        textDecoration: 'none', fontSize: 12,
        fontFamily: "'IBM Plex Mono', monospace",
        fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
        flexShrink: 0,
        border: '1px solid #d4af55',
        transition: 'background 0.2s, color 0.2s',
      }}>Partner with Us</a>
    </nav>
  );
}

export { FOOTER_LINKS, FOOTER_GOV_LINKS, GOV_LINKS };
