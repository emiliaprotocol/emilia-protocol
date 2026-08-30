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
  const protectionBuilder = read('app/protect/ProtectionBuilder.tsx');
  const sitemap = read('app/sitemap.ts');

  it('starts with a passive local scan and offers one bounded protection step', () => {
    expect(homepage).toContain('href="/scan#run-local"');
    expect(homepage).toContain('Map and prepare one action');
    expect(homepage).toContain('PRODUCT_STORIES');
    expect(homepage).toContain('Protect one workflow');
  });

  it('routes a scan result into Agent Guard and then the MCP integration', () => {
    expect(scan).toContain('Map');
    expect(scan).toContain('Choose');
    expect(scan).toContain('Prepare');
    expect(scan).toContain('Activate');
    expect(scan).toContain("import scanPackage from '../../packages/scan/package.json'");
    expect(scan).toContain('const SCAN_INSTALL_SPEC = `@emilia-protocol/scan@${scanPackage.version}`');
    expect(scan).toContain('npx ${SCAN_INSTALL_SPEC} protect ./tools.json --action sendWire --apply --verify');
    expect(scan).toContain('npm install --save-exact @emilia-protocol/mcp-guard@${mcpGuardPackage.version}');
    expect(scan).toContain('npx ${SCAN_INSTALL_SPEC} protect --sample --action sendWire --apply --verify');
    expect(scan).toContain('npx ${SCAN_INSTALL_SPEC} protect ./tools.json --action sendWire --reviewed');
    expect(scan).toContain('Activate this boundary in production');
    expect(scan).toContain('href="/pilot"');
    expect(scan).toContain('href="/mcp"');

    expect(guard).toContain('Coming from Scan? Start with one flagged tool.');
    expect(guard).toContain('reviewable protection scaffold, not a patch');
    expect(guard).toContain('href="/guides/require-receipt"');
    expect(guard).toContain('href="/mcp"');
    expect(guard).toContain('href="/scan"');
    expect(guide).toContain('npm install --save-exact @emilia-protocol/mcp-guard@0.5.0');
    expect(guide).toContain('npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action release_payment --apply --verify');
    expect(guide).toContain('npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action release_payment --reviewed');
    expect(guide).toContain('durable provenance ledger');
    expect(guide).toContain('shared atomic consumption store');
    expect(guard).not.toContain('due process, proven');
    expect(guard).toContain('does not prove due process');
    expect(guard).toContain('A signature verifies those bytes under the pinned key');
    expect(guard).toContain('does not prove identity, authority, due process, or correctness');
  });

  it('keeps the free Gate Starter local and separates it from production activation', () => {
    expect(scan).toContain('Free local Gate Starter');
    expect(scan).not.toContain('EMILIA Protection Package');
    expect(scan).toContain('No account, upload, or telemetry');
    expect(scan).toContain('Package installation may contact npm');
    expect(scan).toContain('The command does not');
    expect(scan).toContain('launch the configured server or call the selected tool');
    expect(scan).toContain('A passing local check is not production protection');
    expect(scan).toContain('Record review as a second, explicit action');
    expect(scan).toContain('It does not activate Gate');
    expect(scan).toContain('Customer mandate');
    expect(scan).toContain('Owning connector');
    expect(scan).toContain('Durable state');
    expect(scan).toContain('Verified refusal');
    expect(scan).not.toContain('You are protected');
  });

  it('sources the activation CLI version from the Gate package instead of a stale literal', () => {
    expect(protectionBuilder).toContain("import gatePackage from '../../packages/gate/package.json'");
    expect(protectionBuilder).toContain('@emilia-protocol/gate@{gatePackage.version}');
    expect(protectionBuilder).not.toContain('@emilia-protocol/gate@0.23.17');
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
    expect(repositoryReadme).toContain('npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --apply --verify');
    expect(repositoryReadme).toContain('npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --reviewed');
    expect(repositoryReadme).toContain('durable provenance ledger');
    expect(repositoryReadme).toContain('shared atomic consumption store');
    expect(repositoryReadme).not.toContain('const guarded = withMcpGuard(handleTool, {');
  });

  it('publishes bounded exit contracts for Gate Starter and the older authority diagnostic', () => {
    expect(scan).toContain("['0', 'Requested preview, generation, local check, or reviewed handoff completed']");
    expect(scan).toContain("['64', 'An option or selected-action contract is invalid']");
    expect(scan).toContain('Exit 0 means only that the requested local CLI operation completed');
    for (const publicCopy of [packageReadme, packageChangelog]) {
      expect(publicCopy).toContain('64');
      expect(publicCopy.replace(/\s+/g, ' ')).toMatch(/usage, argument, (?:or )?filesystem error/i);
    }
  });
});
