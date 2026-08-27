// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

const host = read('app/host/page.tsx');
const nav = read('components/SiteNav.tsx');
const footer = read('components/SiteFooter.tsx');
const sitemap = read('app/sitemap.ts');
const gate = read('app/gate/page.tsx');
const mcp = read('app/mcp/page.tsx');
const docs = read('app/docs/page.tsx');
const products = read('components/product-story/ProductStory.tsx');
const productStories = read('lib/product-stories.ts');
const pilot = read('app/pilot/page.tsx');
const machineContext = read('docs/ai/context-source.v1.json');
const marketingContext = read('.agents/product-marketing-context.md');
const messageArchitecture = read('docs/strategy/PRODUCT-MESSAGE-ARCHITECTURE.md');

describe('EMILIA Host public product contract', () => {
  it('positions Host as the local deployment form of Gate with a concrete customer story', () => {
    expect(host).toContain('Put the consequence firewall where the credentials live.');
    expect(host).toContain('HTTP local service alpha');
    expect(host).toContain('HTTP and MCP SDK protection');
    expect(host).toContain('Governed pilots');
    expect(host).toContain('href="/pilot?v=host"');
    expect(host).toContain('href="/gate"');
    expect(host).toContain('EMILIA_AUTHORITY_REQUIRED');
    expect(host).toContain('INDETERMINATE');
    expect(host).toContain('In the Host deployment pattern, the agent never receives the provider credential.');
    expect(host).toContain('owner-permissioned Unix socket');
    expect(host).toContain('not a general HTTP reverse proxy');
    expect(host).toContain('One provider attempt may enter');
  });

  it('keeps the promise bounded to activated covered paths and exact authority', () => {
    expect(host).toContain('not a prompt or model classifier');
    expect(host).toContain('credential-owning provider boundary');
    expect(host).toContain('activated covered paths');
    expect(host).toContain('does not prove the external effect occurred');
    expect(host).toContain('does not establish complete mediation');
    expect(host).toContain('does not reconcile the Consequence Ledger');
    expect(host).toContain('Scan does not automatically activate Host');
    expect(host).not.toMatch(/generally available|universal firewall|network appliance/i);
  });

  it('is discoverable without becoming a sixth product', () => {
    expect(nav).toContain("'host'");
    expect(footer).toContain("['/host', 'EMILIA Host']");
    expect(sitemap).toContain("{ path: '/host'");
    expect(gate).toContain('href="/host"');
    expect(mcp).toContain('href="/host"');
    expect(docs).toContain("href: '/host'");
    expect(products).toContain('Host is a deployment form of Gate, not a sixth core product.');
    expect(products).toContain('href="/host"');
    expect(productStories.match(/chapter: '0[1-5]'/g)).toHaveLength(5);
    expect(productStories).not.toContain("key: 'host'");
  });

  it('publishes bounded SEO, FAQ, and LLM-readable context', () => {
    expect(host).toContain("alternates: { canonical: '/host' }");
    expect(host).toContain("'AI agent firewall'");
    expect(host).toContain("'@type': ['SoftwareApplication', 'Product']");
    expect(host).toContain("'@type': 'FAQPage'");
    expect(host).toContain('dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}');
    expect(host).toContain(".replace(/</g, '\\\\u003c')");
    expect(machineContext).toContain('https://www.emiliaprotocol.ai/host');
    expect(machineContext).toContain('local deployment form of EMILIA Gate');
    expect(marketingContext).toContain('EMILIA Host');
    expect(messageArchitecture).toContain('EMILIA Host');
  });

  it('preserves an intentional closed Host pilot preselection', () => {
    expect(pilot).toContain("host: 'other'");
    expect(pilot).toContain('Object.hasOwn(PRESELECT, v)');
    expect(pilot).toContain("params.get('source') === 'private_equity' ? 'private_equity' : 'direct'");
    expect(pilot).not.toContain('source: params.get');
  });
});
