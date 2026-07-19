// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/gate — auditor control-testing workpaper tests.
 * Run with `node --test reports/auditor-workpaper.test.js` from packages/gate.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createEvidenceLog } from '../evidence.js';
import {
  AUDIT_WORKPAPER_VERSION,
  AUDIT_WORKPAPER_HONESTY_NOTICE,
  AUDIT_ATTRIBUTES,
  buildAuditWorkpaper,
  renderMarkdown,
} from './auditor-workpaper.js';

function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

let n = 0;
function allowEntry(at, over = {}) {
  return {
    kind: 'decision',
    at,
    action: 'payment.release',
    allow: true,
    status: 200,
    reason: 'allow',
    selector: { protocol: 'mcp', tool: 'release_payment' },
    required_tier: 'class_a',
    receipt_id: `rcpt_${++n}`,
    subject: 'ep:user:alice',
    signer: 'pinned-issuer-key-1',
    have_tier: 'class_a',
    assurance_tier_source: 'cryptographic_verification',
    consumption_mode: 'consume',
    ...over,
  };
}
function denyEntry(at, reason = 'replay_refused', over = {}) {
  return {
    kind: 'decision',
    at,
    action: 'payment.release',
    allow: false,
    status: 428,
    reason,
    selector: { protocol: 'mcp', tool: 'release_payment' },
    required_tier: 'class_a',
    receipt_id: `rcpt_${++n}`,
    subject: 'ep:user:mallory',
    ...over,
  };
}

/** Real hash-chained entries, exactly as the gate's evidence log produces them. */
async function chained(specs) {
  const log = createEvidenceLog();
  for (const s of specs) await log.record(s);
  return log.all();
}

const OPTS = {
  client: 'Example Corp',
  engagement: 'FY26 ITGC — cycle 1',
  controlRef: 'EP-GATE-01',
  periodStart: '2026-01-01T00:00:00.000Z',
  periodEnd: '2026-02-01T00:00:00.000Z',
  sampleSize: 3,
  sampleSeed: 'seed-alpha',
  now: () => Date.parse('2026-02-02T00:00:00.000Z'),
};

function attr(item, id) {
  return item.attributes.find((a) => a.id === id);
}

test('population: guarded decisions in the half-open window; edges inclusive-start / exclusive-end', async () => {
  const entries = await chained([
    allowEntry('2025-12-31T23:59:59.999Z'),          // before start -> out
    allowEntry('2026-01-01T00:00:00.000Z'),          // exactly start -> IN
    allowEntry('2026-01-15T12:00:00.000Z'),          // mid-window -> IN
    denyEntry('2026-01-20T00:00:00.000Z'),           // refusal in window -> IN
    allowEntry('2026-02-01T00:00:00.000Z'),          // exactly end -> OUT (next period)
    allowEntry('2026-01-10T00:00:00.000Z', { reason: 'not_guarded' }), // pass-through -> excluded
    { kind: 'execution', at: '2026-01-16T00:00:00.000Z', outcome: 'executed' }, // not a decision -> excluded
  ]);
  const pack = buildAuditWorkpaper(entries, OPTS);
  assert.equal(pack['@version'], AUDIT_WORKPAPER_VERSION);
  assert.equal(pack.population.size, 3);
  assert.deepEqual(
    pack.population.items.map((i) => i.at),
    ['2026-01-01T00:00:00.000Z', '2026-01-15T12:00:00.000Z', '2026-01-20T00:00:00.000Z'],
  );
  assert.equal(pack.population.excluded.outside_window, 2);
  assert.equal(pack.population.excluded.not_guarded_passthroughs, 1);
  assert.equal(pack.population.excluded.executions, 1);
  assert.equal(pack.completeness.entries_supplied, 7);
  // chain head = hash of the last supplied record
  assert.equal(pack.completeness.chain_head, entries[entries.length - 1].hash);
  assert.equal(pack.completeness.first_population_hash, pack.population.items[0].hash);
  assert.equal(pack.completeness.last_population_hash, pack.population.items[2].hash);
});

test('population_hash pins the population: recomputable, and changes when the population changes', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z'),
    allowEntry('2026-01-03T00:00:00.000Z'),
    denyEntry('2026-01-04T00:00:00.000Z'),
  ]);
  const pack = buildAuditWorkpaper(entries, OPTS);
  const expected = sha256hex(pack.population.items.map((i) => i.hash).sort().join('\n'));
  assert.equal(pack.population.population_hash, expected);

  const smaller = buildAuditWorkpaper(entries.slice(0, 2), OPTS);
  assert.notEqual(smaller.population.population_hash, pack.population.population_hash);
});

test('sampling: same seed twice -> identical selection; auditor can reproduce it from the documented method', async () => {
  const entries = await chained(
    Array.from({ length: 12 }, (_, i) => allowEntry(`2026-01-${String(i + 2).padStart(2, '0')}T00:00:00.000Z`)),
  );
  const a = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 5 });
  const b = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 5 });
  assert.deepEqual(a.sampling.selected, b.sampling.selected);
  assert.equal(a.sampling.selected.length, 5);
  assert.equal(a.sampling.basis, 'attribute sample');
  assert.equal(a.sampling.full_population, false);

  // Independent reproduction: sha256(seed + entry_hash), ascending hex order.
  const expected = a.population.items
    .map((i) => ({ h: i.hash, k: sha256hex('seed-alpha' + i.hash) }))
    .sort((x, y) => (x.k < y.k ? -1 : x.k > y.k ? 1 : (x.h < y.h ? -1 : 1)))
    .slice(0, 5)
    .map((x) => x.h);
  assert.deepEqual(a.sampling.selected, expected);
});

test('sampling: a different seed changes sample membership deterministically', async () => {
  const entries = await chained(
    Array.from({ length: 12 }, (_, i) => allowEntry(`2026-01-${String(i + 2).padStart(2, '0')}T00:00:00.000Z`)),
  );
  const a = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 5, sampleSeed: 'seed-alpha' });
  const b = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 5, sampleSeed: 'seed-beta' });
  assert.notDeepEqual(a.sampling.selected, b.sampling.selected);
  // and each is individually stable
  const b2 = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 5, sampleSeed: 'seed-beta' });
  assert.deepEqual(b.sampling.selected, b2.sampling.selected);
});

test('sampling: sampleSize >= population -> 100% examination', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z'),
    allowEntry('2026-01-03T00:00:00.000Z'),
  ]);
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  assert.equal(pack.sampling.full_population, true);
  assert.equal(pack.sampling.basis, '100% examination');
  assert.equal(pack.sampling.selected_size, 2);
  assert.deepEqual([...pack.sampling.selected].sort(), pack.population.items.map((i) => i.hash).sort());
});

test('attributes: a clean allow passes A1-A6; degraded evidence fails the named attributes into exceptions', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z'), // clean
    allowEntry('2026-01-03T00:00:00.000Z', {
      signer: null,                          // A1 fail
      have_tier: 'software', required_tier: 'quorum', // A2 fail
      consumption_mode: 'none',              // A4 fail
      subject: null,                         // A5 fail
    }),
  ]);
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  const clean = pack.attribute_testing.items.find((i) => i.hash === entries[0].hash);
  const dirty = pack.attribute_testing.items.find((i) => i.hash === entries[1].hash);

  for (const a of AUDIT_ATTRIBUTES) {
    assert.equal(attr(clean, a.id).result, 'pass', `clean ${a.id}`);
  }
  assert.equal(attr(dirty, 'A1').result, 'fail');
  assert.equal(attr(dirty, 'A2').result, 'fail');
  assert.equal(attr(dirty, 'A3').result, 'pass'); // reason allow + receipt_id present
  assert.equal(attr(dirty, 'A4').result, 'fail');
  assert.equal(attr(dirty, 'A5').result, 'fail');
  assert.equal(attr(dirty, 'A6').result, 'pass'); // real chained record

  // Every attribute observation names the evidence field it came from.
  for (const a of dirty.attributes) assert.ok(a.evidence_field.length > 0);

  assert.equal(pack.exceptions.total, 4);
  const named = pack.exceptions.items.map((x) => x.attribute).sort();
  assert.deepEqual(named, ['A1', 'A2', 'A4', 'A5']);
  for (const x of pack.exceptions.items) {
    assert.equal(x.entry_hash, entries[1].hash); // exception carries the entry hash
    assert.ok(x.name && x.evidence_field);
  }
});

test('attributes: unknown required tier fails A2 closed', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z', { required_tier: 'gold' }),
  ]);
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  assert.equal(attr(pack.attribute_testing.items[0], 'A2').result, 'fail');
});

test('denials are NOT exceptions: A1-A5 not_applicable, A6 still tested, zero exceptions — and the pack states it', async () => {
  const entries = await chained([
    denyEntry('2026-01-05T00:00:00.000Z', 'replay_refused'),
    denyEntry('2026-01-06T00:00:00.000Z', 'receipt_rejected:signature_invalid'),
  ]);
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  assert.equal(pack.population.size, 2); // refusals ARE population (the control firing)
  for (const item of pack.attribute_testing.items) {
    assert.equal(item.verdict, 'refusal');
    for (const id of ['A1', 'A2', 'A3', 'A4', 'A5']) {
      assert.equal(attr(item, id).result, 'not_applicable');
    }
    assert.equal(attr(item, 'A6').result, 'pass'); // the refusal was durably logged
  }
  assert.equal(pack.exceptions.total, 0);
  assert.match(pack.exceptions.refusals_are_not_exceptions, /NOT control exceptions/);
  assert.match(pack.attribute_testing.refusal_treatment, /operating as designed/);
});

test('malformed entries -> integrity_warnings, never sampled', async () => {
  const good = await chained([allowEntry('2026-01-02T00:00:00.000Z')]);
  const entries = [
    ...good,
    42,                                                                       // not_an_object
    { kind: 'decision', at: 'not-a-date', allow: true, reason: 'allow', hash: 'a'.repeat(64) }, // unparseable at
    { kind: 'decision', at: '2026-01-03T00:00:00.000Z', allow: true, reason: 'allow' },         // missing hash
    { kind: 'mystery', at: '2026-01-04T00:00:00.000Z', hash: 'b'.repeat(64) },                  // unknown kind
    { kind: 'decision', at: '2026-01-05T00:00:00.000Z', hash: 'c'.repeat(64), reason: 'allow' }, // allow missing
  ];
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  assert.equal(pack.population.size, 1);
  assert.equal(pack.integrity_warnings.length, 5);
  assert.deepEqual(
    pack.integrity_warnings.map((w) => w.problem),
    ['not_an_object', 'missing_or_unparseable_at', 'missing_hash', 'unknown_kind', 'decision_missing_allow'],
  );
  // none of the warned entries appear in population or sample
  const popHashes = new Set(pack.population.items.map((i) => i.hash));
  assert.equal(popHashes.has('a'.repeat(64)), false);
  assert.equal(popHashes.has('c'.repeat(64)), false);
});

test('deterministic: same inputs + pinned now -> byte-identical JSON', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z'),
    denyEntry('2026-01-03T00:00:00.000Z'),
    allowEntry('2026-01-04T00:00:00.000Z'),
  ]);
  const a = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 2 });
  const b = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 2 });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('fail closed: missing/invalid options are errors, not guesses', async () => {
  const entries = await chained([allowEntry('2026-01-02T00:00:00.000Z')]);
  assert.throws(() => buildAuditWorkpaper('nope', OPTS), /entries must be an array/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, client: undefined }), /client is required/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, engagement: '' }), /engagement is required/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, controlRef: null }), /controlRef is required/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, periodStart: 'garbage' }), /ISO timestamps or epoch ms/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, periodEnd: undefined }), /ISO timestamps or epoch ms/);
  assert.throws(
    () => buildAuditWorkpaper(entries, { ...OPTS, periodStart: OPTS.periodEnd, periodEnd: OPTS.periodStart }),
    /empty or inverted period/,
  );
  assert.throws(
    () => buildAuditWorkpaper(entries, { ...OPTS, periodStart: OPTS.periodEnd }),
    /empty or inverted period/,
  );
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 0 }), /positive integer/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 2.5 }), /positive integer/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, sampleSize: undefined }), /positive integer/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, sampleSeed: '' }), /sampleSeed is required/);
  assert.throws(() => buildAuditWorkpaper(entries, { ...OPTS, sampleSeed: undefined }), /sampleSeed is required/);
});

test('conclusion fields are ALWAYS null — the module never concludes', async () => {
  const entries = await chained([allowEntry('2026-01-02T00:00:00.000Z')]);
  const pack = buildAuditWorkpaper(entries, OPTS);
  assert.deepEqual(pack.conclusion, { tested_by: null, reviewed_by: null, conclusion: null });
});

test('empty population is a valid (boring) workpaper, not an error', () => {
  const pack = buildAuditWorkpaper([], OPTS);
  assert.equal(pack.population.size, 0);
  assert.equal(pack.sampling.selected_size, 0);
  assert.equal(pack.exceptions.total, 0);
  assert.equal(pack.population.population_hash, sha256hex(''));
  const md = renderMarkdown(pack);
  assert.match(md, /zero-activity population is a valid/);
});

test('renderMarkdown: renders the honesty header, sampling seed, results, and blank sign-off', async () => {
  const entries = await chained([
    allowEntry('2026-01-02T00:00:00.000Z'),
    denyEntry('2026-01-03T00:00:00.000Z'),
  ]);
  const pack = buildAuditWorkpaper(entries, { ...OPTS, sampleSize: 10 });
  const md = renderMarkdown(pack);
  assert.ok(md.includes(AUDIT_WORKPAPER_HONESTY_NOTICE));
  assert.ok(md.includes(AUDIT_WORKPAPER_VERSION));
  assert.ok(md.includes('100% examination'));
  assert.ok(md.includes('seed-alpha'));
  assert.ok(md.includes('Sign-off (auditor completes)'));
  assert.match(md, /Tested by \/ date \| `_+`/);
  assert.match(md, /Reviewed by \/ date \| `_+`/);
  assert.match(md, /Conclusion \| `_+`/);
  assert.match(md, /NOT control exceptions/);
});

test('renderMarkdown fails closed: wrong @version, altered honesty notice, or machine-filled sign-off', async () => {
  const entries = await chained([allowEntry('2026-01-02T00:00:00.000Z')]);
  const pack = buildAuditWorkpaper(entries, OPTS);

  assert.throws(() => renderMarkdown(null), /requires an EP-GATE-AUDIT-WORKPAPER-v1/);
  assert.throws(
    () => renderMarkdown({ ...pack, '@version': 'EP-GATE-AUDIT-WORKPAPER-v2' }),
    /requires an EP-GATE-AUDIT-WORKPAPER-v1/,
  );
  assert.throws(
    () => renderMarkdown({ ...pack, notice: pack.notice.replace('not an audit opinion', 'an audit opinion') }),
    /honesty notice was altered or removed/,
  );
  assert.throws(() => renderMarkdown({ ...pack, notice: undefined }), /honesty notice was altered or removed/);
  assert.throws(
    () => renderMarkdown({ ...pack, conclusion: { tested_by: 'machine', reviewed_by: null, conclusion: null } }),
    /sign-off fields must be null/,
  );
  assert.throws(
    () => renderMarkdown({ ...pack, conclusion: { tested_by: null, reviewed_by: null, conclusion: 'effective' } }),
    /sign-off fields must be null/,
  );
});
