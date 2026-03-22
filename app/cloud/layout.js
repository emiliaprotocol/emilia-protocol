'use client';

import { usePathname } from 'next/navigation';

const SIDEBAR_LINKS = [
  { href: '/cloud', label: 'Dashboard', icon: '\u25A3' },
  { href: '/cloud/policies', label: 'Policies', icon: '\u25C7' },
  { href: '/cloud/signoffs', label: 'Signoffs', icon: '\u2713' },
  { href: '/cloud/events', label: 'Events', icon: '\u25CE' },
  { href: '/cloud/audit', label: 'Audit', icon: '\u25A1' },
  { href: '/cloud/tenants', label: 'Tenants', icon: '\u25CB' },
  { href: '/cloud/alerts', label: 'Alerts', icon: '\u26A0' },
  { href: '/cloud/settings', label: 'Settings', icon: '\u2699' },
];

const s = {
  wrapper: {
    display: 'flex',
    minHeight: '100vh',
    background: '#0a0f1e',
    color: '#e8eaf0',
    fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
  },
  sidebar: {
    width: 220,
    flexShrink: 0,
    background: '#070810',
    borderRight: '1px solid rgba(255,255,255,0.06)',
    display: 'flex',
    flexDirection: 'column',
    position: 'fixed',
    top: 0,
    left: 0,
    bottom: 0,
    zIndex: 50,
  },
  logoArea: {
    padding: '20px 20px 24px',
    borderBottom: '1px solid rgba(255,255,255,0.04)',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  logoText: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontWeight: 700,
    fontSize: 13,
    letterSpacing: 2,
    color: '#e8e6e3',
    textTransform: 'uppercase',
  },
  cloudBadge: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: 2,
    textTransform: 'uppercase',
    color: '#4a90d9',
    background: 'rgba(0,212,255,0.08)',
    border: '1px solid rgba(0,212,255,0.15)',
    borderRadius: 4,
    padding: '2px 6px',
    marginLeft: 4,
  },
  navSection: {
    padding: '16px 12px',
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
  },
  navLink: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '9px 12px',
    borderRadius: 6,
    textDecoration: 'none',
    fontSize: 13,
    fontWeight: 500,
    color: '#7a809a',
    transition: 'all 0.15s',
    cursor: 'pointer',
    border: 'none',
    background: 'none',
    width: '100%',
    textAlign: 'left',
  },
  navLinkActive: {
    background: 'rgba(0,212,255,0.08)',
    color: '#e8eaf0',
  },
  navIcon: {
    fontSize: 14,
    width: 18,
    textAlign: 'center',
    flexShrink: 0,
    opacity: 0.6,
  },
  sidebarFooter: {
    padding: '16px 20px',
    borderTop: '1px solid rgba(255,255,255,0.04)',
  },
  backLink: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: '#4a4f6a',
    textDecoration: 'none',
  },
  main: {
    flex: 1,
    marginLeft: 220,
    minHeight: '100vh',
  },
  topBar: {
    height: 52,
    borderBottom: '1px solid rgba(255,255,255,0.04)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 32px',
    background: 'rgba(5,6,10,0.9)',
    backdropFilter: 'blur(8px)',
    position: 'sticky',
    top: 0,
    zIndex: 40,
  },
  breadcrumb: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 11,
    color: '#4a4f6a',
    letterSpacing: 1,
  },
  envBadge: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: '#00ff88',
    background: 'rgba(0,255,136,0.06)',
    border: '1px solid rgba(0,255,136,0.12)',
    borderRadius: 4,
    padding: '3px 8px',
  },
  content: {
    padding: '32px',
  },
};

export default function CloudLayout({ children }) {
  const pathname = usePathname();

  const isActive = (href) => {
    if (href === '/cloud') return pathname === '/cloud';
    return pathname.startsWith(href);
  };

  return (
    <div style={s.wrapper}>
      {/* Sidebar */}
      <aside style={s.sidebar}>
        <div style={s.logoArea}>
          <svg width="26" height="26" viewBox="0 0 34 34" fill="none">
            <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#clg)"/>
            <rect x="9.5" y="5" width="16" height="2.5" rx="1.25" fill="#60a5fa"/>
            <rect x="9.5" y="15.5" width="12" height="2.5" rx="1.25" fill="#f59e0b"/>
            <rect x="9.5" y="26.5" width="14" height="2.5" rx="1.25" fill="#60a5fa"/>
            <defs><linearGradient id="clg" x1="8" y1="5" x2="8" y2="29"><stop offset="0%" stopColor="#60a5fa"/><stop offset="100%" stopColor="#f59e0b"/></linearGradient></defs>
          </svg>
          <span style={s.logoText}>EP</span>
          <span style={s.cloudBadge}>Cloud</span>
        </div>

        <nav style={s.navSection}>
          {SIDEBAR_LINKS.map(({ href, label, icon }) => (
            <a
              key={href}
              href={href}
              style={{
                ...s.navLink,
                ...(isActive(href) ? s.navLinkActive : {}),
              }}
            >
              <span style={s.navIcon}>{icon}</span>
              {label}
            </a>
          ))}
        </nav>

        <div style={s.sidebarFooter}>
          <a href="/" style={s.backLink}>{'\u2190'} Back to site</a>
        </div>
      </aside>

      {/* Main area */}
      <div style={s.main}>
        <header style={s.topBar}>
          <span style={s.breadcrumb}>
            EP Cloud {pathname !== '/cloud' ? ` / ${pathname.replace('/cloud/', '').split('/')[0]}` : ''}
          </span>
          <span style={s.envBadge}>production</span>
        </header>
        <div style={s.content}>
          {children}
        </div>
      </div>
    </div>
  );
}
