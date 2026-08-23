// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/private-equity/page.tsx'), 'utf8');
const lab = readFileSync(resolve(ROOT, 'app/private-equity/PortfolioActionRiskLab.tsx'), 'utf8');
const fixture = readFileSync(resolve(ROOT, 'app/private-equity/finance-lab-fixture.ts'), 'utf8');
const openGraphImage = readFileSync(resolve(ROOT, 'app/private-equity/opengraph-image.tsx'), 'utf8');
const sitemap = readFileSync(resolve(ROOT, 'app/sitemap.ts'), 'utf8');
const footer = readFileSync(resolve(ROOT, 'components/SiteFooter.tsx'), 'utf8');

describe('private-equity portfolio customer page', () => {
  it('is an indexable, finance-first customer route with dedicated share metadata', () => {
    expect(page).toContain("alternates: { canonical: '/private-equity' }");
    expect(page).toContain('Agentic AI Risk Controls for Private Equity Portfolios');
    expect(page).toContain('Protect the capital behind agentic action.');
    expect(page).toContain("url: '/private-equity/opengraph-image'");
    expect(page).toContain('robots: { index: true, follow: true }');
    expect(openGraphImage).toContain('export const size = { width: 1200, height: 630 }');
    expect(sitemap).toContain("{ path: '/private-equity'");
    expect(footer).toContain("['/private-equity', 'Private Equity']");
  });

  it('keeps the portfolio promise inside the complete-mediation boundary', () => {
    expect(page).toContain('On completely mediated covered paths');
    expect(page).toContain('no accepted exact-action authority and required');
    expect(page).toContain('Gate does not establish');
    expect(page).toContain('does not cover every agent risk or make an investment safe');
    expect(page).toContain('Source truth, bypass paths, fraud absence, provider outcome');
    expect(page).not.toContain('eliminates agent risk');
    expect(page).not.toContain('guarantees your investment');
  });

  it('keeps private investment outreach separate from the public customer conversion', () => {
    expect(page).toContain('Scope one portfolio pilot');
    expect(page).toContain('Customer deployment path only');
    expect(page).not.toContain('href="/investors"');
    expect(page).not.toMatch(/invest now|request investment|investment opportunity/i);
  });

  it('publishes WebPage and FAQ schema with script-breaking characters sanitized', () => {
    expect(page).toContain("'@type': 'WebPage'");
    expect(page).toContain("'@type': 'FAQPage'");
    expect(page).toContain(".replace(/</g, '\\\\u003c')");
    expect(page).toContain('dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}');
  });

  it('uses only the existing observe-mode finance prechecks in the synthetic lab', () => {
    expect(fixture).toContain('/api/v1/adapters/fin/vendor-bank-change/precheck');
    expect(fixture).toContain('/api/v1/adapters/fin/payment-release/precheck');
    expect(fixture.match(/enforcement_mode: 'observe'/g)).toHaveLength(2);
    expect(fixture).toContain('Northstar Components (fictional, consenting sandbox company)');
    expect(lab).toContain('/api/pilot/sandbox/provision');
    expect(lab).toContain('does not authorize, block, mutate, or execute');
    expect(lab).not.toContain('/api/pilot/sandbox/report');
    expect(lab).not.toContain('GG-1');
    expect(lab).not.toContain('offline-verifiable');
    expect(lab).not.toContain("'\\n+  -H");
  });

  it('shows the single canonical $25K, 90-day offer without a second public package', () => {
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.workflowLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.durationLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.shortPriceLabel');
    expect(page).toContain('One finance workflow. 90 days. $25K.');
    expect(page).not.toMatch(/free pilot|portfolio-wide platform commitment required/i);
  });
});
