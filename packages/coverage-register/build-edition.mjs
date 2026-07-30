#!/usr/bin/env node
/**
 * Build or reproduce a dated edition. Offline: reads a snapshot file, never the
 * network.
 *
 *   node build-edition.mjs --snapshot snapshot.json --out edition.json
 *   node build-edition.mjs --snapshot snapshot.json --reproduce edition.json
 */

import fs from 'node:fs/promises';
import { buildEdition, canonicalJson, reproduce } from './edition.mjs';

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const read = async (p) => JSON.parse(await fs.readFile(p, 'utf8'));

async function main() {
  const snapshotPath = arg('snapshot');
  if (!snapshotPath) throw new Error('--snapshot is required');
  const snapshot = await read(snapshotPath);

  const reproducePath = arg('reproduce');
  if (reproducePath) {
    const published = await read(reproducePath);
    const { reproduced, drift } = reproduce(snapshot, published);
    if (reproduced) {
      console.log(`REPRODUCED: ${reproducePath} re-derives byte-identically from ${snapshotPath}`);
      return;
    }
    console.error(`NOT REPRODUCED (${drift.length} differences):`);
    for (const d of drift.slice(0, 40)) console.error(`  - ${d}`);
    if (drift.length > 40) console.error(`  ... and ${drift.length - 40} more`);
    process.exit(1);
  }

  const edition = buildEdition(snapshot);
  const out = arg('out', 'edition.json');
  await fs.writeFile(out, canonicalJson(edition), 'utf8');

  const c = edition.counts;
  console.log(`edition ${edition.as_of} -> ${out}`);
  console.log(`  targets                     ${c.total}`);
  console.log(`  declares consequential      ${c.DECLARATION_SILENT + c.DECLARED_AUTHORIZATION}`);
  console.log(`  ... states authorization    ${c.DECLARED_AUTHORIZATION}`);
  console.log(`  ... declaration silent     ${c.DECLARATION_SILENT}`);
  console.log(`  no consequential action     ${c.NO_CONSEQUENTIAL_ACTION_DECLARED}`);
  console.log(`  indeterminate               ${c.INDETERMINATE}`);
  console.log(`  edition digest              ${edition.edition_digest}`);
  console.log('\nby category:');
  for (const [id, row] of Object.entries(edition.by_category)) {
    console.log(`  ${id.padEnd(36)} ${String(row.declared).padStart(5)}  ${String(row.pct_of_corpus).padStart(6)}%  auth-declared ${row.declared_with_authorization}`);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
