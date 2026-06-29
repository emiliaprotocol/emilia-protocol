#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Agent Action Firewall Index — registry scale. Paginate the official MCP
 * registry and classify each server by its advertised name + description.
 *
 *   node ingest.mjs [cap] [--json] [--out registry-index.json]
 *
 * HONEST SCOPE: the registry exposes a server's name + description, NOT its
 * per-tool manifest. So this measures the share of registered servers that
 * ADVERTISE a high-risk capability (money / data destruction / deploy /
 * permission / export / regulated). It is a registry-metadata signal — coarser
 * than the tool-level scan in `corpus.mjs` / the per-server result pages, and
 * it does not claim those servers are ungated. Label it as such everywhere.
 * @license Apache-2.0
 */
import fs from 'node:fs';
import { classifyOperation } from './index.js';

const BASE = 'https://registry.modelcontextprotocol.io/v0/servers';
const args = process.argv.slice(2);
const cap = Number(args.find((a) => /^\d+$/.test(a))) || 12000;
const json = args.includes('--json');
const outIdx = args.indexOf('--out');
const outFile = outIdx >= 0 ? args[outIdx + 1] : null;

let cursor = '';
let total = 0;
let highRisk = 0;
const byFamily = {};
const examples = [];
let pages = 0;

while (total < cap) {
  const url = `${BASE}?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
  let d;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) { process.stderr.write(`registry HTTP ${res.status}\n`); break; }
    d = await res.json();
  } catch (e) {
    process.stderr.write(`fetch error: ${e.message}\n`);
    break;
  }
  const servers = d.servers || [];
  if (servers.length === 0) break;
  pages += 1;
  for (const entry of servers) {
    const s = entry.server || {};
    total += 1;
    const c = classifyOperation({ name: s.name || '', description: s.description || '' });
    if (c.dangerous) {
      highRisk += 1;
      byFamily[c.family] = (byFamily[c.family] || 0) + 1;
      if (examples.length < 25) examples.push({ name: s.name, family: c.family });
    }
  }
  cursor = d.metadata?.nextCursor;
  if (!cursor) break;
}

const result = {
  '@version': 'EP-FIRE-DRILL-REGISTRY-v1',
  source: 'registry.modelcontextprotocol.io',
  scanned_at_note: 'registry-advertised capability scan (server name + description), not a tool-level or deployment scan',
  servers_scanned: total,
  advertise_high_risk: highRisk,
  pct_advertise_high_risk: total ? Math.round((highRisk / total) * 100) : 0,
  by_family: byFamily,
  examples,
};

if (outFile) fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
if (json) { console.log(JSON.stringify(result, null, 2)); process.exit(0); }

console.log('='.repeat(66));
console.log('  Agent Action Firewall Index — public MCP registry');
console.log('='.repeat(66));
console.log(`  scanned ${total} registered servers (${pages} pages)`);
console.log(`  ${result.pct_advertise_high_risk}% advertise a high-risk capability (money/data/deploy/perms/export/regulated)`);
console.log(`  by family: ${Object.entries(byFamily).map(([k, v]) => `${k}=${v}`).join(' · ') || 'none'}`);
console.log(`  note: registry name+description signal — coarser than the tool-level scan.`);
console.log('='.repeat(66));
