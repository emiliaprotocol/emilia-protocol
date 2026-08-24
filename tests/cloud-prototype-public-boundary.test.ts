// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

const ROUTE_FILES = [
  'app/cloud/page.tsx',
  'app/cloud/alerts/page.tsx',
  'app/cloud/audit/page.tsx',
  'app/cloud/authority-inbox/page.tsx',
  'app/cloud/events/page.tsx',
  'app/cloud/guard-receipts/page.tsx',
  'app/cloud/policies/page.tsx',
  'app/cloud/settings/page.tsx',
  'app/cloud/signoffs/page.tsx',
  'app/cloud/tenants/page.tsx',
] as const;

const routes = Object.fromEntries(ROUTE_FILES.map((file) => [file, read(file)]));
const joined = Object.values(routes).join('\n');
const layout = read('app/cloud/layout.tsx');
const page = routes['app/cloud/page.tsx'];
const shell = read('app/cloud/cloud-shell.tsx');

describe('deindexed Gate operations prototype boundary', () => {
  it('deindexes the entire route tree and supplies truthful social metadata', () => {
    expect(layout).toContain("title: 'Gate Operations Prototype | EMILIA'");
    expect(page).toContain("canonical: '/cloud'");
    expect(layout).toContain('robots: { index: false, follow: false }');
    expect(layout).toContain("type: 'website'");
    expect(layout).toContain('No hosted Cloud service, customer deployment');
  });

  it('labels every child view through one persistent non-operating shell boundary', () => {
    expect(shell).toContain('Non-operating implementation prototype');
    expect(shell).toContain('Records are synthetic unless a developer');
    expect(shell).toContain('This is not a hosted Cloud service');
    expect(shell).toContain('provider-credential surface, or production actuation path');
    expect(layout).toContain('<CloudShell>{children}</CloudShell>');
  });

  it('removes managed-service, customer, pricing, access, and deployment implications', () => {
    expect(joined).not.toMatch(
      /Request Cloud Access|Managed Control Plane|Per-tenant pricing|customers pay for|VPC \+ SSO \+ Residency|real Cloud approval API|ept_live|ep_live|acme-corp|globex-fin|initech-eu/i,
    );
    expect(joined).not.toMatch(
      /view and manage organizations using your EMILIA Gate Cloud deployment|Generate compliance evidence packages|compliance policies enforced across handshakes|browser-cookie authentication[\s\S]{0,80}lands in/i,
    );
    expect(routes['app/cloud/tenants/page.tsx']).not.toMatch(/\bplan\b|enterprise|business/i);
  });

  it('keeps connected paths explicitly local or sandbox-only', () => {
    for (const file of [
      'app/cloud/authority-inbox/page.tsx',
      'app/cloud/guard-receipts/page.tsx',
      'app/cloud/signoffs/page.tsx',
    ]) {
      expect(routes[file]).toMatch(/local or sandbox|local or sandbox test|local or sandbox environment/i);
      expect(routes[file]).toMatch(/Never enter (?:a )?production|Never enter production/i);
    }
    expect(routes['app/cloud/signoffs/page.tsx']).toContain('cannot release a payment');
    expect(routes['app/cloud/signoffs/page.tsx']).toContain('does not call a payment provider');
    expect(routes['app/cloud/authority-inbox/page.tsx']).toContain('contacts a provider');
  });

  it('routes commercial interest only to the canonical pilot or separate implementation', () => {
    expect(page).toContain("from '@/lib/commercial-offer'");
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(page).toContain('GATE_IMPLEMENTATION');
    expect(page).toContain('href="/pilot"');
    expect(page).toContain('Gate%20Implementation%20inquiry');
    expect(page).not.toContain('/partners');
  });
});
