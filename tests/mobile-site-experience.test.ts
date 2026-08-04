import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

describe('mobile public-site experience contract', () => {
  it('keeps the mobile navigation below the sticky header and exposes accessible controls', () => {
    const nav = read('components/SiteNav.tsx');
    const layout = read('app/layout.tsx');
    const css = read('app/ep.css');

    expect(nav).toContain('className="ep-site-header"');
    expect(nav).toContain('aria-controls="ep-mobile-navigation"');
    expect(nav).toContain("event.key === 'Escape'");
    expect(layout).toContain('className="ep-skip-link"');
    expect(css).toContain('min-height: 44px');
    expect(css).toContain('min-height: calc(100dvh - 60px)');
  });

  it('keeps the protocol hub fluid instead of leaking fixed desktop columns off-screen', () => {
    const protocol = read('app/protocol/page.tsx');
    const css = read('app/ep.css');

    expect(protocol.match(/repeat\(auto-fit, minmax\(260px, 1fr\)\)/g)?.length).toBeGreaterThanOrEqual(3);
    expect(protocol).toContain('ep-protocol-detail-row');
    expect(css).toContain('.ep-protocol-detail-row');
  });

  it('keeps the category and auth-to-consequence handoff visible on phones', () => {
    const homepage = read('app/HomePageClient.tsx');
    const css = read('app/ep.css');

    expect(homepage).toContain('The Consequence Firewall</span>');
    expect(homepage).toContain('Auth opens the door. EMILIA controls what crosses it.');
    expect(homepage).toContain('ep-home-auth-map');
    expect(css).toContain('.ep-home-calm-kicker span');
    expect(css).toContain('.ep-home-auth-handoff');
  });
});
