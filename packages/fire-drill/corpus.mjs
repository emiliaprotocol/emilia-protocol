#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Agent Action Firewall Index — scan a corpus of MCP manifests / OpenAPI specs
 * and aggregate. The number behind the Report.
 *
 *   node corpus.mjs <dir>     scan every *.json under <dir>
 *   node corpus.mjs           scan the bundled representative sample
 *   node corpus.mjs <dir> --json
 *
 * @license Apache-2.0
 */
import fs from 'node:fs';
import path from 'node:path';
import { scan, aggregate } from './index.js';
import { REPRESENTATIVE_CORPUS } from './corpus.js';

const argv = process.argv.slice(2);
const json = argv.includes('--json');
const dir = argv.find((a) => !a.startsWith('--'));

const reports = [];
const labels = [];
if (dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  for (const f of files) {
    try {
      reports.push(scan(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))));
      labels.push(f);
    } catch (e) {
      console.error(`skip ${f}: ${e.message}`);
    }
  }
} else {
  for (const { name, manifest } of REPRESENTATIVE_CORPUS) {
    reports.push(scan(manifest));
    labels.push(name);
  }
}

const agg = aggregate(reports);

if (json) {
  console.log(JSON.stringify(agg, null, 2));
  process.exit(0);
}

const R = (s) => `\x1b[31m${s}\x1b[0m`;
const G = (s) => `\x1b[32m${s}\x1b[0m`;
console.log('='.repeat(66));
console.log('  Agent Action Firewall Index');
console.log('='.repeat(66));
reports.forEach((r, i) => {
  const tag = r.eg1 === 'pass' ? G('EG-1') : R(`${r.summary.ungated} unguarded`);
  console.log(`  ${String(r.score).padStart(3)}/100  ${labels[i].padEnd(22)} ${tag}`);
});
console.log('  ' + '-'.repeat(62));
console.log(`  ${agg.servers} servers · ${R(`${agg.pct_servers_with_unguarded_action}%`)} expose a dangerous action with NO receipt requirement`);
console.log(`  ${agg.unguarded_operations} unguarded dangerous operations · mean score ${agg.mean_score}/100`);
console.log(`  by family: ${Object.entries(agg.by_family).map(([k, v]) => `${k}=${v}`).join(' · ') || 'none'}`);
console.log('='.repeat(66));
