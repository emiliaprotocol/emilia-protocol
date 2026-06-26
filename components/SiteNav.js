'use client';

import Link from 'next/link';
import Image from 'next/image';
import { useState } from 'react';
import { color, font, radius, cta } from '@/lib/tokens';

const NAV_LINKS = [
  ['/gate', 'Gate'],
  ['/agent-guard', 'Agent Guard'],
  ['/protocol', 'Protocol'],
  ['/mcp', 'MCP'],
  ['/govguard', 'GovGuard'],
  ['/sovereignty', 'Sovereignty'],
  ['/finguard', 'FinGuard'],
  ['/quorum', 'Quorum'],
  ['/demo', 'Demo'],
  ['/try', 'Try it'],
  ['/verify', 'Verify'],
  ['/pricing', 'Pricing'],
  ['/docs', 'Docs'],
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
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      <nav style={{
        position: 'sticky', top: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: 60,
        left: 0, right: 0, width: '100%', boxSizing: 'border-box',
        background: 'rgba(250,250,249,0.85)',
        backdropFilter: 'blur(16px)',
        borderBottom: `1px solid ${color.border}`,
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          width: '100%', maxWidth: 1280, padding: '0 32px', gap: 24,
        }}>
          {/* Logo */}
          <Link href="/" className="ep-logo-link" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none', flexShrink: 0 }}>
            <Image
              src="/logo-wordmark.png"
              alt="EMILIA Protocol"
              width={110}
              height={28}
              priority
              style={{ height: 28, width: 'auto', display: 'block' }}
            />
          </Link>

          {/* Desktop links */}
          <div className="ep-nav-links" style={{ display: 'flex', alignItems: 'center', gap: 18, margin: '0 auto' }}>
            {NAV_LINKS.map(([href, label]) => (
              <a
                key={label}
                href={href}
                className="ep-nav-link"
                data-active={label === activePage ? 'true' : undefined}
                target={href.startsWith('http') ? '_blank' : undefined}
                rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
              >{label}</a>
            ))}
          </div>

          {/* Actions */}
          <div className="ep-nav-actions" style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" rel="noopener noreferrer" className="ep-gh-star">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
              Star
            </a>
            <a href="/partners" className="ep-cta-secondary" style={cta.secondary}>Request Pilot</a>

            {/* Mobile toggle */}
            <button
              className="ep-mobile-toggle"
              onClick={() => setMobileOpen(v => !v)}
              aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? (
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
              ) : (
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12h18M3 6h18M3 18h18"/></svg>
              )}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile menu */}
      <div className="ep-mobile-menu" data-open={mobileOpen ? 'true' : undefined}>
        {NAV_LINKS.map(([href, label]) => (
          <a
            key={label}
            href={href}
            data-active={label === activePage ? 'true' : undefined}
            onClick={() => setMobileOpen(false)}
          >{label}</a>
        ))}
        <a
          href="/partners"
          onClick={() => setMobileOpen(false)}
          style={{ color: color.gold, borderBottomColor: 'transparent', marginTop: 8 }}
        >Request Pilot</a>
      </div>
    </>
  );
}

export { FOOTER_LINKS, FOOTER_GOV_LINKS, GOV_LINKS };
