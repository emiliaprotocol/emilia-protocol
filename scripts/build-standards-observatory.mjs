#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const write = args.has('--write');
const check = args.has('--check');
if (write === check) {
  console.error('usage: build-standards-observatory.mjs (--write | --check)');
  process.exit(2);
}

const INPUT_PATHS = {
  catalog: 'standards/observatory/catalog.source.v1.json',
  sourceLock: 'standards/observatory/source-lock.v1.json',
  recon: 'standards/observatory/recon-summary.v1.json',
  generator: 'scripts/build-standards-observatory.mjs',
};
// The full per-artifact recon index is PRIVATE and never published. It lives at a
// gitignored path and is used only for a local integrity cross-check of the committed
// aggregate summary. Public artifacts carry aggregate counts and the corpus digest only.
const PRIVATE_RECON_INDEX = 'docs/strategy-private/observatory/recon-index.v1.json';
const OUTPUT_PATHS = {
  snapshot: 'lib/standards-observatory.snapshot.json',
  publicJson: 'public/.well-known/standards-observatory.json',
  llmsText: 'public/standards-observatory.llms.txt',
  manifest: 'standards/observatory/snapshot-manifest.v1.json',
};

function absolute(relative) {
  return path.join(ROOT, relative);
}

function read(relative) {
  return fs.readFileSync(absolute(relative), 'utf8');
}

function readJson(relative) {
  try {
    return JSON.parse(read(relative));
  } catch (error) {
    throw new Error(`${relative}: ${error.message}`);
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertUnique(values, label) {
  assert(values.length === new Set(values).size, `${label} contains duplicates`);
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function formatDate(value) {
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'long', timeZone: 'UTC' }).format(new Date(value));
}

const catalog = readJson(INPUT_PATHS.catalog);
const sourceLock = readJson(INPUT_PATHS.sourceLock);
const recon = readJson(INPUT_PATHS.recon);

assert(catalog['@version'] === 'EMILIA-STANDARDS-OBSERVATORY-SOURCE-v1', 'unsupported observatory catalog');
assert(sourceLock['@version'] === 'EMILIA-STANDARDS-SOURCE-LOCK-v1', 'unsupported source lock');
assert(recon['@version'] === 'EMILIA-STANDARDS-RECON-SUMMARY-v1', 'unsupported recon summary');
assert(catalog.as_of === sourceLock.retrieved_at, 'catalog and source lock timestamps differ');
assert(catalog.as_of === recon.as_of, 'catalog and recon timestamps differ');
assert(Array.isArray(catalog.dimensions) && catalog.dimensions.length > 0, 'guarantee dimensions are missing');
assert(Array.isArray(catalog.sources) && catalog.sources.length > 0, 'curated sources are missing');
assert(Array.isArray(catalog.events), 'events are missing');
assert(Array.isArray(catalog.frontiers), 'frontiers are missing');

const dimensionIds = catalog.dimensions.map((item) => item.id);
const sourceIds = catalog.sources.map((item) => item.id);
const eventIds = catalog.events.map((item) => item.id);
const frontierIds = catalog.frontiers.map((item) => item.id);
assertUnique(dimensionIds, 'dimension ids');
assertUnique(sourceIds, 'source ids');
assertUnique(eventIds, 'event ids');
assertUnique(frontierIds, 'frontier ids');

const allowedValues = new Set(['yes', 'partial', 'no', 'unknown']);
for (const source of catalog.sources) {
  assert(source.quote?.text && source.quote?.locator, `${source.id}: quote is incomplete`);
  assert(Object.keys(source.guarantees || {}).length === dimensionIds.length, `${source.id}: guarantee count differs from dimensions`);
  for (const dimensionId of dimensionIds) {
    const guarantee = source.guarantees?.[dimensionId];
    assert(guarantee, `${source.id}: missing ${dimensionId}`);
    assert(allowedValues.has(guarantee.value), `${source.id}: invalid ${dimensionId} value`);
    assert(typeof guarantee.rationale === 'string' && guarantee.rationale.length >= 12, `${source.id}: ${dimensionId} rationale is too short`);
  }
}

assert(sourceLock.source_count === catalog.sources.length, 'source lock count differs from catalog');
assert(sourceLock.sources.length === catalog.sources.length, 'source lock records differ from catalog');
assert(sourceLock.lock_sha256 === sha256(Buffer.from(JSON.stringify(sourceLock.sources), 'utf8')), 'source lock digest is invalid');
const locksById = new Map(sourceLock.sources.map((item) => [item.id, item]));
for (const source of catalog.sources) {
  const lock = locksById.get(source.id);
  assert(lock, `${source.id}: no source lock`);
  assert(lock.revision === source.revision, `${source.id}: source revision differs from lock`);
  assert(lock.source_url === source.source_url, `${source.id}: source URL differs from lock`);
  assert(lock.quote?.text === source.quote.text, `${source.id}: quote differs from lock`);
  assert(lock.quote_verified === true, `${source.id}: quote is not verified`);
  assert(/^[0-9a-f]{64}$/.test(lock.sha256), `${source.id}: invalid source digest`);
}

assert(recon['@version'] === 'EMILIA-STANDARDS-RECON-SUMMARY-v1', 'recon must be the aggregate summary, not the raw index');
assert(recon.review_model === 'correlated_agent_assisted_discovery', 'recon must remain labeled as correlated discovery');
assert(recon.metrics.declared_agent_reads === catalog.methodology.declared_agent_reads, 'declared recon count differs from catalog');
assert(recon.metrics.unrecovered_reports === recon.metrics.declared_agent_reads - recon.metrics.recovered_structured_reports, 'unrecovered recon count is invalid');
assert(/^[0-9a-f]{64}$/.test(recon.corpus_sha256), 'recon corpus digest is invalid');
// The summary MUST NOT carry per-artifact records. That data stays private.
assert(!('reports' in recon), 'recon summary must not embed the raw per-artifact index');

// Local-only integrity cross-check: if the private full index is present, confirm the
// committed aggregate summary matches it exactly. Absent in CI and on fresh clones by design.
if (fs.existsSync(absolute(PRIVATE_RECON_INDEX))) {
  const privateIndex = readJson(PRIVATE_RECON_INDEX);
  assert(privateIndex.metrics.recovered_structured_reports === privateIndex.reports.length, 'private recon report count differs from its metrics');
  assert(recon.metrics.recovered_structured_reports === privateIndex.reports.length, 'summary count differs from private index');
  assert(recon.corpus_sha256 === sha256(Buffer.from(JSON.stringify(privateIndex.reports), 'utf8')), 'summary corpus digest differs from private index');
  assertUnique(privateIndex.reports.map((item) => item.id), 'recon report ids');
  for (const report of privateIndex.reports) {
    assert(report.review_state === 'agent_analyzed_unverified', `${report.id}: recon result is overstated`);
  }
}

for (const event of catalog.events) {
  for (const sourceId of event.source_ids || []) assert(sourceIds.includes(sourceId), `${event.id}: unknown source ${sourceId}`);
}
for (const conflict of catalog.operative_conflicts || []) {
  for (const sourceId of conflict.source_ids || []) assert(sourceIds.includes(sourceId), `${conflict.id}: unknown source ${sourceId}`);
}

const agendaRequest = catalog.events.find((item) => item.id === 'wimse-agenda-request-emilia-composition');
assert(agendaRequest?.status === 'pending_public_archive', 'WIMSE agenda request must not be presented as accepted before public confirmation');
assert(/not agenda acceptance/i.test(agendaRequest.truth_boundary), 'WIMSE agenda request needs an explicit acceptance boundary');

const serializedCatalog = JSON.stringify(catalog);
for (const banned of ['zero rivals', 'independent reviewers', 'agenda accepted']) {
  assert(!serializedCatalog.toLowerCase().includes(banned.toLowerCase()), `catalog contains prohibited overclaim: ${banned}`);
}

const sourceLockPublic = new Map(sourceLock.sources.map((item) => [item.id, {
  content_sha256: item.sha256,
  content_bytes: item.bytes,
  quote_sha256: item.quote_sha256,
  quote_verified: item.quote_verified,
}]))
;
const curatedSources = catalog.sources.map((source) => ({ ...source, evidence_lock: sourceLockPublic.get(source.id) }));
const core = {
  '@version': 'EMILIA-STANDARDS-OBSERVATORY-v1',
  title: catalog.title,
  as_of: catalog.as_of,
  scope: 'Revision-aware standards cartography. Curated claims are source-locked; broad recon entries are discovery leads only.',
  methodology: catalog.methodology,
  metrics: {
    primary_sources_verified: curatedSources.length,
    guarantee_dimensions: catalog.dimensions.length,
    movement_events: catalog.events.length,
    open_frontiers: catalog.frontiers.length,
    operative_conflicts: (catalog.operative_conflicts || []).length,
    ...recon.metrics,
  },
  integrity: {
    catalog_sha256: sha256(fs.readFileSync(absolute(INPUT_PATHS.catalog))),
    source_lock_sha256: sourceLock.lock_sha256,
    recon_corpus_sha256: recon.corpus_sha256,
  },
  dimensions: catalog.dimensions,
  sources: curatedSources,
  operative_conflicts: catalog.operative_conflicts || [],
  events: catalog.events,
  frontiers: catalog.frontiers,
  recon: {
    review_model: recon.review_model,
    claim_boundary: recon.claim_boundary,
    metrics: recon.metrics,
    corpus_sha256: recon.corpus_sha256,
  },
};
// Publication boundary: the served snapshot exposes exactly the curated matrix and
// aggregate recon counts. No per-artifact recon record is ever placed in a public output.
assert(!('reports' in core.recon), 'public snapshot must not carry recon reports');
assert(core.sources.length === catalog.sources.length, 'public snapshot source count drifted');
const snapshot = { ...core, snapshot_sha256: sha256(Buffer.from(JSON.stringify(core), 'utf8')) };
const snapshotBody = stableJson(snapshot);

function renderLlmsText() {
  const lines = [
    '# EMILIA Standards Observatory',
    '',
    `Source-locked snapshot as of ${formatDate(catalog.as_of)}. Snapshot sha256:${snapshot.snapshot_sha256}.`,
    '',
    '## Truth Rules',
    '',
    '- Broad agent recon is correlated discovery, not independent review and not evidence that a guarantee is absent.',
    '- Only exact-revision primary sources with verified excerpts drive the guarantee matrix.',
    '- Historical text is never presented as operative when a current artifact is known.',
    '- A submitted agenda request is not an accepted slot, working-group adoption, or IETF endorsement.',
    '- Shared cryptography or a shared digest does not make two protocols semantically equivalent.',
    '',
    '## Current Movement',
    '',
    ...catalog.events.map((event) => `- ${event.date} | ${event.venue} | ${event.title} | status=${event.status}. ${event.truth_boundary || event.description}`),
    '',
    '## Publication-Grade Source Map',
    '',
    ...curatedSources.map((source) => `- ${source.short_name} | ${source.revision} | ${source.operative_status} | ${source.relation} | ${source.source_url} | quote sha256:${source.evidence_lock.quote_sha256}`),
    '',
    '## Open Frontiers',
    '',
    ...catalog.frontiers.map((frontier) => `- ${frontier.priority}. ${frontier.title} | ${frontier.status} | ${frontier.problem}`),
    '',
    '## Broad Recon Boundary',
    '',
    `The discovery sweep declared ${recon.metrics.declared_agent_reads} reads. ${recon.metrics.recovered_structured_reports} structured reports were recovered, ${recon.metrics.unrecovered_reports} were not recovered, and ${recon.metrics.fetch_failures_in_recovered_reports} recovered reports marked a fetch failure. The per-artifact index is held privately and never published; every entry remains unverified until promoted through the source-lock process, at which point the effort is named in the matrix above. Aggregate corpus digest sha256:${recon.corpus_sha256}.`,
    '',
    '## Machine-Readable Forms',
    '',
    '- https://www.emiliaprotocol.ai/.well-known/standards-observatory.json',
    '- https://www.emiliaprotocol.ai/observatory',
    '',
  ];
  return `${lines.join('\n')}\n`;
}

const llmsBody = renderLlmsText();
const outputBodies = new Map([
  [OUTPUT_PATHS.snapshot, snapshotBody],
  [OUTPUT_PATHS.publicJson, snapshotBody],
  [OUTPUT_PATHS.llmsText, llmsBody],
]);

const generatedFrom = Object.values(INPUT_PATHS).map((relative) => {
  const bytes = fs.readFileSync(absolute(relative));
  return { path: relative, bytes: bytes.length, sha256: sha256(bytes) };
});
const manifest = {
  '@version': 'EMILIA-STANDARDS-OBSERVATORY-MANIFEST-v1',
  as_of: catalog.as_of,
  snapshot_sha256: snapshot.snapshot_sha256,
  generated_from: generatedFrom,
  outputs: [...outputBodies].map(([relative, body]) => ({ path: relative, bytes: Buffer.byteLength(body), sha256: sha256(Buffer.from(body)) })),
};
outputBodies.set(OUTPUT_PATHS.manifest, stableJson(manifest));

if (write) {
  for (const [relative, body] of outputBodies) {
    fs.mkdirSync(path.dirname(absolute(relative)), { recursive: true });
    fs.writeFileSync(absolute(relative), body);
  }
  console.log(`STANDARDS OBSERVATORY: WROTE ${outputBodies.size} artifacts (snapshot sha256:${snapshot.snapshot_sha256})`);
} else {
  const stale = [];
  for (const [relative, expected] of outputBodies) {
    if (!fs.existsSync(absolute(relative)) || read(relative) !== expected) stale.push(relative);
  }
  if (stale.length) {
    console.error(`STANDARDS OBSERVATORY: FAIL - stale artifact(s): ${stale.join(', ')}`);
    console.error('Fix: npm run observatory:sync');
    process.exit(1);
  }
  console.log(`STANDARDS OBSERVATORY: PASS (${curatedSources.length} verified sources; ${recon.metrics.recovered_structured_reports}/${recon.metrics.declared_agent_reads} recon reads, aggregate only)`);
}
