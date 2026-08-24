// SPDX-License-Identifier: Apache-2.0

'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import shellStyles from './cloud-shell.module.css';

const SIDEBAR_LINKS = [
  { href: '/cloud', label: 'Prototype overview', icon: '\u25A3' },
  { href: '/cloud/policies', label: 'Policy samples', icon: '\u25C7' },
  { href: '/cloud/signoffs', label: 'Signoff prototype', icon: '\u2713' },
  { href: '/cloud/authority-inbox', label: 'Authority Inbox', icon: '\u25EB' },
  { href: '/cloud/events', label: 'Synthetic events', icon: '\u25CE' },
  { href: '/cloud/audit', label: 'Evidence exports', icon: '\u25A1' },
  { href: '/cloud/tenants', label: 'Isolation samples', icon: '\u25CB' },
  { href: '/cloud/alerts', label: 'Synthetic alerts', icon: '\u26A0' },
  { href: '/cloud/settings', label: 'Settings prototype', icon: '\u2699' },
] as const;

const s = {
  wrapper: {
    display: 'flex',
    minHeight: '100vh',
    background: '#020617',
    color: '#e8eaf0',
    fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
  } as React.CSSProperties,
  sidebar: {
    width: 220,
    flexShrink: 0,
    background: '#0F172A',
    borderRight: '1px solid rgba(255,255,255,0.06)',
    display: 'flex',
    flexDirection: 'column',
    position: 'fixed',
    top: 0,
    left: 0,
    bottom: 0,
    zIndex: 50,
  } as React.CSSProperties,
  logoArea: {
    padding: '20px 20px 24px',
    borderBottom: '1px solid rgba(255,255,255,0.04)',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  } as React.CSSProperties,
  logoText: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontWeight: 700,
    fontSize: 13,
    letterSpacing: 2,
    color: '#e8e6e3',
    textTransform: 'uppercase',
  } as React.CSSProperties,
  cloudBadge: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
    color: '#F59E0B',
    background: 'rgba(245,158,11,0.08)',
    border: '1px solid rgba(245,158,11,0.18)',
    borderRadius: 4,
    padding: '2px 6px',
    marginLeft: 4,
  } as React.CSSProperties,
  navSection: {
    padding: '16px 12px',
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
  } as React.CSSProperties,
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
  } as React.CSSProperties,
  navLinkActive: {
    background: 'rgba(245,158,11,0.08)',
    color: '#e8eaf0',
  } as React.CSSProperties,
  navIcon: {
    fontSize: 14,
    width: 18,
    textAlign: 'center',
    flexShrink: 0,
    opacity: 0.6,
  } as React.CSSProperties,
  sidebarFooter: {
    padding: '16px 20px',
    borderTop: '1px solid rgba(255,255,255,0.04)',
  } as React.CSSProperties,
  backLink: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: '#7a809a',
    textDecoration: 'none',
  } as React.CSSProperties,
  main: {
    flex: 1,
    marginLeft: 220,
    minHeight: '100vh',
  } as React.CSSProperties,
  topBar: {
    minHeight: 52,
    borderBottom: '1px solid rgba(255,255,255,0.04)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 16,
    padding: '10px 32px',
    background: 'rgba(2,6,23,0.94)',
    backdropFilter: 'blur(8px)',
    position: 'sticky',
    top: 0,
    zIndex: 40,
  } as React.CSSProperties,
  breadcrumb: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 11,
    color: '#7a809a',
    letterSpacing: 0.8,
  } as React.CSSProperties,
  envBadge: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: '#F59E0B',
    background: 'rgba(245,158,11,0.08)',
    border: '1px solid rgba(245,158,11,0.18)',
    borderRadius: 4,
    padding: '3px 8px',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  content: {
    padding: '32px',
  } as React.CSSProperties,
  demoBanner: {
    marginBottom: 18,
    padding: '12px 14px',
    borderRadius: 6,
    border: '1px solid rgba(245,158,11,0.24)',
    background: 'rgba(245,158,11,0.07)',
    color: '#FCD34D',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 11,
    lineHeight: 1.6,
    letterSpacing: 0.25,
  } as React.CSSProperties,
};

export default function CloudShell({ children }: { children: React.ReactNode }): React.ReactElement {
  const pathname = usePathname();

  const isActive = (href: string): boolean => {
    if (href === '/cloud') return pathname === '/cloud';
    return pathname.startsWith(href);
  };

  return (
    <div className={shellStyles.wrapper} style={s.wrapper}>
      <aside className={shellStyles.sidebar} style={s.sidebar}>
        <div style={s.logoArea}>
          <svg width="26" height="26" viewBox="0 0 34 34" fill="none" aria-hidden="true">
            <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#clg)" />
            <rect x="9.5" y="5" width="16" height="2.5" rx="1.25" fill="#60a5fa" />
            <rect x="9.5" y="15.5" width="12" height="2.5" rx="1.25" fill="#f59e0b" />
            <rect x="9.5" y="26.5" width="14" height="2.5" rx="1.25" fill="#60a5fa" />
            <defs><linearGradient id="clg" x1="8" y1="5" x2="8" y2="29"><stop offset="0%" stopColor="#60a5fa" /><stop offset="100%" stopColor="#f59e0b" /></linearGradient></defs>
          </svg>
          <span style={s.logoText}>EP</span>
          <span style={s.cloudBadge}>Prototype</span>
        </div>

        <nav style={s.navSection} aria-label="Gate operations prototype">
          {SIDEBAR_LINKS.map(({ href, label, icon }) => (
            <a
              key={href}
              href={href}
              aria-current={isActive(href) ? 'page' : undefined}
              style={{ ...s.navLink, ...(isActive(href) ? s.navLinkActive : {}) }}
            >
              <span style={s.navIcon} aria-hidden="true">{icon}</span>
              {label}
            </a>
          ))}
        </nav>

        <div style={s.sidebarFooter}>
          <Link href="/product/cloud" style={s.backLink}>{'\u2190'} Operations profile</Link>
        </div>
      </aside>

      <div className={shellStyles.main} style={s.main}>
        <header className={shellStyles.topBar} style={s.topBar}>
          <span style={s.breadcrumb}>
            Gate operations prototype {pathname !== '/cloud' ? ` / ${pathname.replace('/cloud/', '').split('/')[0]}` : ''}
          </span>
          <span style={s.envBadge}>Non-operating</span>
        </header>
        <div className={shellStyles.content} style={s.content}>
          <div role="note" style={s.demoBanner}>
            Non-operating implementation prototype. Records are synthetic unless a developer
            connects a local or sandbox test backend. This is not a hosted Cloud service,
            customer deployment, provider-credential surface, or production actuation path.
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}
