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

    expect(protocol.match(/repeat\(auto-fit, minmax\(min\((?:260|280)px, 100%\), 1fr\)\)/g)?.length).toBeGreaterThanOrEqual(4);
    expect(protocol).toContain('ep-protocol-detail-row');
    expect(css).toContain('.ep-protocol-detail-row');
  });

  it('keeps the workforce story readable and its handover record responsive on phones', () => {
    const homepage = read('app/HomePageClient.tsx');
    const story = read('components/workforce/WorkforceStory.tsx');
    const css = read('components/workforce/workforce.module.css');

    expect(homepage).toContain('<WorkforceIntroduction />');
    expect(homepage).toContain('<WorkforceHandover />');
    expect(story).toContain('Build your<br />AI workforce.');
    expect(story).toContain('aria-label="Illustrative refunds job before and after replacement"');
    expect(css).toContain('font-size: clamp(48px, 6.2vw, 82px)');
    expect(story).toContain('role="group" aria-label="Illustrative refunds job before and after replacement"');
    expect(story).toContain('/emilia-workforce-atelier-v1.webp');
    expect(css).toContain('object-fit: contain');
    expect(css).toContain('.journeyLayout { grid-template-columns: 1fr; gap: 36px; }');
    expect(css).toContain('min-height: 48px');
    expect(css).toContain('@media (max-width: 760px)');
    expect(css).toContain('@media (max-width: 390px)');
    expect(css).toContain('.handoverLayout { grid-template-columns: 1fr; gap: 28px; }');
    expect(css).toContain('.primary:focus-visible');
  });
});
