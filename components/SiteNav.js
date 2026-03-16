'use client';

/**
 * SiteNav — canonical navigation bar for all EMILIA Protocol pages.
 * Used by: /spec, /appeal, /entity/[entityId]
 * 
 * Static HTML pages (landing, demo, quickstart, operators, apply) use
 * the same visual design via CSS classes but render their own HTML.
 */

const NAV_LINKS = [
  ['/', 'Home'],
  ['/quickstart.html', 'Quickstart'],
  ['/demo.html', 'Demo'],
  ['/spec', 'Spec'],
  ['/operators.html', 'Operators'],
  ['/appeal', 'Appeal'],
  ['https://github.com/emiliaprotocol/emilia-protocol', 'GitHub'],
];

export default function SiteNav({ activePage }) {
  return (
    <nav style={{
      position: 'sticky', top: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 40px', height: 60,
      background: 'rgba(0,0,0,0.85)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
    }}>
      <a href="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
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
            target={href.startsWith('http') ? '_blank' : undefined}
            rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
            style={{
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
              color: label === activePage ? '#00d4ff' : '#4a4f6a',
              textDecoration: 'none',
              transition: 'color 0.2s',
            }}
            onMouseEnter={e => { if (label !== activePage) e.target.style.color = '#00d4ff'; }}
            onMouseLeave={e => { if (label !== activePage) e.target.style.color = '#4a4f6a'; }}
          >{label}</a>
        ))}
        <a href="/apply" style={{
          background: '#00d4ff', color: '#05060a',
          padding: '8px 18px', borderRadius: 8,
          textDecoration: 'none', fontSize: 12,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
        }}>Apply to Review</a>
      </div>
    </nav>
  );
}
