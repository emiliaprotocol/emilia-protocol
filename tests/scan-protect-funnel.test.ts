// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..');
const read = (path: string) => readFileSync(resolve(root, path), 'utf8');

describe('scan to protected MCP boundary funnel', () => {
  const homepage = read('app/HomePageClient.tsx');
  const scan = read('app/scan/page.tsx');
  const guard = read('app/agent-guard/page.tsx');
  const mcp = read('app/mcp/page.tsx');
  const guide = read('app/guides/require-receipt/page.tsx');
  const repositoryReadme = read('README.md');
  const packageReadme = read('packages/scan/README.md');
  const packageChangelog = read('packages/scan/CHANGELOG.md');
  const sitemap = read('app/sitemap.ts');

  it('starts with a passive local scan and offers one bounded protection step', () => {
    expect(homepage).toContain('href="/scan"');
    expect(homepage).toContain('Scan what your agents can reach');
    expect(homepage).toContain('href="/agent-guard"');
    expect(homepage).toContain('Protect one flagged tool');
  });

  it('routes a scan result into Agent Guard and then the MCP integration', () => {
    expect(scan).toContain('Scan locally');
    expect(scan).toContain('Choose one consequential tool');
    expect(scan).toContain('Mediate its real executor path');
    expect(scan).toContain('npx @emilia-protocol/scan protect ./tools.json');
    expect(scan).toContain('href="/agent-guard"');
    expect(scan).toContain('href="/mcp"');

    expect(guard).toContain('Coming from Scan? Start with one flagged tool.');
    expect(guard).toContain('reviewable protection scaffold—not a patch');
    expect(guard).toContain('href="/guides/require-receipt"');
    expect(guard).toContain('href="/mcp"');
    expect(guard).toContain('href="/scan"');
    expect(guide).toContain('npx @emilia-protocol/scan protect ./tools.json');
    expect(guide).toContain('node emilia/verify-setup.mjs');
    expect(guide).toContain('durable provenance ledger');
    expect(guide).toContain('shared atomic consumption store');
    expect(guard).not.toContain('due process, proven');
    expect(guard).toContain('does not prove due process');
    expect(guard).toContain('A signature verifies those bytes under the pinned key');
    expect(guard).toContain('does not prove identity, authority, due process, or correctness');
  });

  it('distinguishes protecting an existing tool from adding verifier tools', () => {
    expect(mcp).toContain('Protect an existing MCP tool');
    expect(mcp).toContain('@emilia-protocol/mcp-guard');
    expect(mcp).toContain('Add EMILIA verification tools to an MCP client');
    expect(mcp).toContain('@emilia-protocol/mcp-server');
    expect(mcp).toContain('href="/guides/require-receipt"');
    expect(mcp).toContain('href="/scan"');
  });

  it('makes the passive scanner discoverable without bloating global navigation', () => {
    expect(sitemap).toContain("{ path: '/scan'");
    expect(repositoryReadme).toContain('npx @emilia-protocol/scan protect ./tools.json');
    expect(repositoryReadme).toContain('node emilia/verify-setup.mjs');
    expect(repositoryReadme).toContain('durable provenance ledger');
    expect(repositoryReadme).toContain('shared atomic consumption store');
    expect(repositoryReadme).not.toContain('const guarded = withMcpGuard(handleTool, {');
  });

  it('publishes exit 64 consistently for authority CLI usage, argument, and filesystem errors', () => {
    for (const publicCopy of [scan, packageReadme, packageChangelog]) {
      expect(publicCopy).toContain('64');
      expect(publicCopy.replace(/\s+/g, ' ')).toMatch(/usage, argument, (?:or )?filesystem error/i);
    }
  });
});
