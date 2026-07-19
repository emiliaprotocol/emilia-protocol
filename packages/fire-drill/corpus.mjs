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
let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }

const MAX_INPUT_BYTES = 8 * 1024 * 1024;

const argv = process.argv.slice(2);
const json = argv.includes('--json');
const dir = argv.find((a) => !a.startsWith('--'));

const reports = [];
const labels = [];
if (dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  for (const f of files) {
    try {
      const raw = fs.readFileSync(path.join(dir, f));
      if (raw.length > MAX_INPUT_BYTES) throw new Error(`input exceeds ${MAX_INPUT_BYTES} bytes`);
      const text = raw.toString('utf8');
      const gate = strictJsonGate(text);
      if (!gate.ok) throw new Error(gate.reason);
      reports.push(scan(JSON.parse(text)));
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
const Y = (s) => `\x1b[33m${s}\x1b[0m`;
console.log('='.repeat(66));
console.log('  Static Receipt Declaration Index');
console.log('='.repeat(66));
reports.forEach((r, i) => {
  const tag = r.static_result === 'complete' ? Y('declared') : R(`${r.summary.missing_declaration} missing`);
  console.log(`  ${String(r.score).padStart(3)}/100  ${labels[i].padEnd(22)} ${tag}`);
});
console.log('  ' + '-'.repeat(62));
console.log(`  ${agg.servers} servers · ${R(`${agg.pct_servers_missing_declaration}%`)} omit a required receipt declaration on a detected dangerous action`);
console.log(`  ${agg.missing_declarations} missing declarations · mean static score ${agg.mean_score}/100`);
console.log('  Runtime enforcement is not assessed.');
console.log(`  by family: ${Object.entries(agg.by_family).map(([k, v]) => `${k}=${v}`).join(' · ') || 'none'}`);
console.log('='.repeat(66));
