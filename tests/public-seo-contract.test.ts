// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import robots from '@/app/robots';
import sitemap from '@/app/sitemap';

const ROOT = resolve(import.meta.dirname, '..');
const read = (relativePath: string): string => readFileSync(resolve(ROOT, relativePath), 'utf8');

const SELF_CANONICAL_PAGES = [
  ['app/gate/consequence-coverage/page.tsx', '/gate/consequence-coverage'],
  ['app/gate/control-plane/page.tsx', '/gate/control-plane'],
  ['app/gate/live/page.tsx', '/gate/live'],
  ['app/grace/flex-passport/page.tsx', '/grace/flex-passport'],
  ['app/grace/live/page.tsx', '/grace/live'],
  ['app/grace/demo/page.tsx', '/grace/demo'],
  ['app/works/page.tsx', '/works'],
] as const;

const PRIVATE_CRAWL_PATHS = [
  '/api/',
  '/cloud',
  '/internal/',
  '/approvers/',
  '/mobile/',
  '/release-lock/',
  '/signoff/',
  '/evidence-readiness',
  '/trust-desk/upload',
] as const;

const AI_ANSWER_CRAWLERS = [
  'OAI-SearchBot',
  'ChatGPT-User',
  'PerplexityBot',
  'Claude-SearchBot',
  'Claude-User',
  'Google-Extended',
] as const;

describe('public SEO source contract', () => {
  it('does not let nested product pages inherit the parent canonical URL', () => {
    for (const [relativePath, canonical] of SELF_CANONICAL_PAGES) {
      expect(read(relativePath)).toContain(`alternates: { canonical: '${canonical}' }`);
    }

    const trustDeskUploadLayout = read('app/trust-desk/upload/layout.tsx');
    expect(trustDeskUploadLayout).toMatch(/robots:\s*\{\s*index:\s*false,\s*follow:\s*false\s*\}/);
  });

  it('keeps linked, indexable Gate and GRACE surfaces in the sitemap', () => {
    const urls = new Set(sitemap().map((entry) => new URL(entry.url).pathname));
    for (const path of [
      '/gate/consequence-coverage',
      '/gate/control-plane',
      '/gate/live',
      '/grace/flex-passport',
      '/grace/live',
    ]) {
      expect(urls.has(path), `${path} should be in the sitemap`).toBe(true);
    }
  });

  it('does not append the EMILIA brand to titles that already contain it', () => {
    const layout = read('app/layout.tsx');
    expect(layout).toContain("template: '%s'");
    expect(layout).not.toMatch(/template:\s*['"`]%s[^'"`]*EMILIA/);
  });

  it('keeps the specification title as a real rendered h1', () => {
    expect(read('app/spec/page.tsx')).toMatch(/<h1(?:\s[^>]*)?>EMILIA authorization receipts specification<\/h1>/);
  });

  it('declares each favicon once with sizes present in the ICO', () => {
    const layout = read('app/layout.tsx');
    const ico = readFileSync(resolve(ROOT, 'public/favicon.ico'));
    const count = ico.readUInt16LE(4);
    const sizes = Array.from({ length: count }, (_, index) => {
      const offset = 6 + index * 16;
      return `${ico[offset] || 256}x${ico[offset + 1] || 256}`;
    });

    expect(sizes).toEqual(['16x16', '32x32', '48x48']);
    expect(layout.match(/url:\s*['"]\/favicon\.ico['"]/g)).toHaveLength(1);
    expect(layout.match(/href=['"]\/favicon\.ico['"]/g) ?? []).toHaveLength(0);
    expect(layout).toContain("sizes: '16x16 32x32 48x48'");
    expect(layout.match(/url:\s*['"]\/favicon\.svg['"]/g)).toHaveLength(1);
    expect(layout.match(/href=['"]\/favicon\.svg['"]/g) ?? []).toHaveLength(0);
  });

  it('declares the real dimensions of the static home social image', () => {
    const image = readFileSync(resolve(ROOT, 'public/emilia-authority-tollbooth-v1.png'));
    expect(image.subarray(1, 4).toString('ascii')).toBe('PNG');
    const width = image.readUInt32BE(16);
    const height = image.readUInt32BE(20);
    expect({ width, height }).toEqual({ width: 1717, height: 916 });

    for (const relativePath of ['app/layout.tsx', 'app/page.tsx']) {
      const source = read(relativePath);
      expect(source).toContain("url: '/emilia-authority-tollbooth-v1.png'");
      expect(source).toContain(`width: ${width}`);
      expect(source).toContain(`height: ${height}`);
    }
  });

  it('allows answer crawlers while keeping non-public routes out of crawl scope', () => {
    const policy = robots();
    const rules = Array.isArray(policy.rules) ? policy.rules : [policy.rules];
    const flattenedAgents = rules.flatMap((rule) => (
      Array.isArray(rule.userAgent) ? rule.userAgent : [rule.userAgent || '*']
    ));

    for (const crawler of AI_ANSWER_CRAWLERS) expect(flattenedAgents).toContain(crawler);
    for (const rule of rules) {
      const disallow = Array.isArray(rule.disallow) ? rule.disallow : [rule.disallow].filter(Boolean);
      for (const path of PRIVATE_CRAWL_PATHS) expect(disallow).toContain(path);
    }
    expect(policy.sitemap).toBe('https://www.emiliaprotocol.ai/sitemap.xml');
  });

  it('keeps public diligence and machine-readable context one footer click away', () => {
    const footer = read('components/SiteFooter.tsx');
    expect(footer).toContain("['/diligence', 'Public Diligence']");
    expect(footer).toContain("['/llms.txt', 'LLM Context']");
    expect(footer).toContain("['/.well-known/emilia-context.json', 'Machine Context']");
  });

  it('audits canonical metadata on linked pages outside the sitemap', () => {
    const audit = read('scripts/audit-public-seo.mjs');
    expect(audit).toContain('linked indexable page expected one canonical');
    expect(audit).toContain('linked indexable page canonical');
    expect(audit).toContain('if (sitemapCanonicalUrls.has(url)) return;');
  });

  it('renders only source-backed organization, site, product, diligence, and PE schemas', () => {
    expect(read('app/layout.tsx').match(/type="application\/ld\+json"/g)).toHaveLength(2);
    expect(read('app/gate/layout.tsx')).toContain("'@type': ['SoftwareApplication', 'Product']");
    expect(read('app/diligence/page.tsx')).toContain("'@type': 'BreadcrumbList'");
    const privateEquity = read('app/private-equity/page.tsx');
    expect(privateEquity).toContain("'@type': 'Service'");
    expect(privateEquity).toContain("'@type': 'FAQPage'");
    expect(privateEquity).toContain('{FAQ.map(({ question, answer }) => (');
  });
});
