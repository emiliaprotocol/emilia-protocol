#!/usr/bin/env node
/**
 * Fetch a registry snapshot. THIS IS THE ONLY FILE IN THE PACKAGE THAT TOUCHES
 * THE NETWORK, and it touches exactly one host: the public MCP registry.
 *
 * It does not contact, probe, or invoke any target server. That restriction is
 * not a style preference. Calling a third party's advertised tool to observe
 * whether it refuses would exceed this register's declaration-only scope. The
 * register is built from what targets published about themselves, and it stays
 * that way.
 *
 *   node fetch-snapshot.mjs --out snapshot.json [--limit 200]
 */

import fs from 'node:fs/promises';

const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';
const PAGE = 100;

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

async function main() {
  const out = arg('out', 'snapshot.json');
  const limit = Number(arg('limit', '0')) || Infinity;
  const retrievedAt = new Date().toISOString();
  const asOf = retrievedAt.slice(0, 10);

  const rows = [];
  let cursor = null;
  let pages = 0;

  while (rows.length < limit) {
    const url = new URL(REGISTRY);
    url.searchParams.set('limit', String(PAGE));
    if (cursor) url.searchParams.set('cursor', cursor);

    const res = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) throw new Error('registry redirect refused; snapshot fetch is pinned to one origin');
    if (!res.ok) throw new Error(`registry responded ${res.status} ${res.statusText}`);
    const contentType = res.headers.get('content-type') ?? '';
    if (!contentType.toLowerCase().includes('json')) throw new Error(`registry returned unexpected content type ${contentType || '(missing)'}`);
    const responseText = await res.text();
    if (Buffer.byteLength(responseText, 'utf8') > 5_000_000) throw new Error('registry page exceeded the 5 MB safety limit');
    const body = JSON.parse(responseText);

    const batch = body.servers ?? [];
    if (batch.length === 0) break;
    rows.push(...batch);
    pages += 1;

    cursor = body.metadata?.nextCursor ?? body.metadata?.next_cursor ?? null;
    if (!cursor) break;
    process.stderr.write(`\rfetched ${rows.length} rows across ${pages} pages`);
  }
  process.stderr.write('\n');

  const trimmed = Number.isFinite(limit) ? rows.slice(0, limit) : rows;
  const snapshot = {
    '@version': 'EP-COVERAGE-SNAPSHOT-v1',
    provenance: {
      source: REGISTRY,
      as_of: asOf,
      retrieved_at: retrievedAt,
      rows_fetched: trimmed.length,
      pages_fetched: pages,
      truncated: Number.isFinite(limit) && rows.length >= limit,
      method:
        'Public registry index read over HTTPS with cursor pagination. No target server was contacted, probed, or invoked.',
    },
    rows: trimmed,
  };

  await fs.writeFile(out, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
  console.log(`wrote ${out}: ${trimmed.length} rows, as_of ${asOf}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
