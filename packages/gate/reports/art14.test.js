/**
 * @emilia-protocol/gate — Article 14 evidence pack tests. Run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEvidenceLog } from '../evidence.js';
import {
  ART14_PACK_VERSION,
  ART14_HONESTY_NOTICE,
  buildArt14EvidencePack,
  renderMarkdown,
  failingPredicate,
} from './art14.js';

const START = '2026-01-01T00:00:00.000Z';
const END = '2026-02-01T00:00:00.000Z';
const NOW = Date.parse('2026-02-02T00:00:00.000Z');
const at = (min) => new Date(Date.parse(START) + min * 60000).toISOString();
const OPTS = { organization: 'ACME Corp', system: 'payments-agent-gate', periodStart: START, periodEnd: END, now: NOW };

// Field shapes mirror the entries the gate's decide()/recordExecution() append.
function decision(when, over = {}) {
  return {
    kind: 'decision', at: when, action: 'payment.release', allow: true, status: 200,
    reason: 'allow', selector: { protocol: 'mcp', tool: 'release_payment' },
    required_tier: 'class_a', receipt_id: 'rcpt_1', subject: 'ep:user:alice',
    have_tier: 'class_a', ...over,
  };
}
function denial(when, reason, over = {}) {
  return decision(when, { allow: false, status: 428, reason, have_tier: 'software', ...over });
}
async function chained(list) {
  const log = createEvidenceLog();
  for (const e of list) await log.record(e);
  return log.all();
}

test('pack carries version, verbatim honesty notice, and period metadata', async () => {
  const pack = buildArt14EvidencePack(await chained([decision(at(1))]), OPTS);
  assert.equal(pack['@version'], ART14_PACK_VERSION);
  assert.equal(pack.notice, ART14_HONESTY_NOTICE);
  assert.equal(pack.organization, 'ACME Corp');
  assert.equal(pack.system, 'payments-agent-gate');
  assert.equal(pack.period.start, START);
  assert.equal(pack.period.end, END);
  assert.equal(pack.generated_at, new Date(NOW).toISOString());
});

test('oversight table aggregates principal x action_type x tier with counts', async () => {
  const entries = await chained([
    decision(at(1)),
    decision(at(2)),
    decision(at(3), { subject: 'ep:user:bob', action: 'wire.transfer', have_tier: 'quorum', receipt_id: 'rcpt_9' }),
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.deepEqual(pack.oversight_exercised, [
    { principal: 'ep:user:alice', action_type: 'payment.release', assurance_tier: 'class_a', count: 2 },
    { principal: 'ep:user:bob', action_type: 'wire.transfer', assurance_tier: 'quorum', count: 1 },
  ]);
});

test('interventions carry the named failing predicate per refusal reason', async () => {
  const entries = await chained([
    denial(at(1), 'receipt_required'),
    denial(at(2), 'assurance_too_low'),
    denial(at(3), 'receipt_rejected:bad_signature'),
    denial(at(4), 'unknown_required_tier'),
    denial(at(5), 'some_future_reason'),
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.interventions.total, 5);
  const predicates = pack.interventions.entries.map((e) => e.failing_predicate);
  assert.deepEqual(predicates, [
    'authorization_receipt_present',
    'assurance_tier_sufficient',
    'receipt_valid:bad_signature',
    'assurance_tier_sufficient',
    'unmapped:some_future_reason', // never silently genericized
  ]);
  assert.deepEqual(pack.interventions.by_predicate, {
    assurance_tier_sufficient: 2,
    authorization_receipt_present: 1,
    'receipt_valid:bad_signature': 1,
    'unmapped:some_future_reason': 1,
  });
});

test('replay and tamper refusals are counted as blocked attempts', async () => {
  const entries = await chained([
    denial(at(1), 'replay_refused'),
    denial(at(2), 'receipt_rejected:bad_signature'),
    denial(at(3), 'execution_binding_failed'),
    denial(at(4), 'receipt_required'), // neither replay nor tamper
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.replay_tamper.replay_blocked, 1);
  assert.equal(pack.replay_tamper.tamper_blocked, 2);
  assert.equal(pack.replay_tamper.entries.length, 3);
  assert.equal(pack.interventions.total, 4); // still full interventions elsewhere
});

test('not_guarded pass-throughs are uncontrolled-action exceptions, not oversight', async () => {
  const entries = await chained([
    decision(at(1)),
    decision(at(2), { reason: 'not_guarded', action: 'read.balance', receipt_id: null, subject: null, have_tier: undefined }),
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.uncontrolled_action_exceptions.total, 1);
  assert.equal(pack.uncontrolled_action_exceptions.entries[0].action, 'read.balance');
  assert.equal(pack.oversight_exercised.length, 1); // only the guarded allow
});

test('coverage ratio = guarded decisions / all decisions', async () => {
  const entries = await chained([
    decision(at(1)),
    denial(at(2), 'replay_refused'), // refusals ARE guarded decisions
    decision(at(3), { reason: 'not_guarded' }),
    decision(at(4)),
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.coverage.decisions_total, 4);
  assert.equal(pack.coverage.decisions_guarded, 3);
  assert.equal(pack.coverage.ratio, 0.75);
});

test('entries outside the window are excluded; boundary is [start, end)', async () => {
  const entries = await chained([
    decision('2025-12-31T23:59:59.000Z'), // before start
    decision(START),                       // exactly at start: included
    decision(at(10)),
    decision(END),                         // exactly at end: next period
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.evidence.entries_in_window, 2);
  assert.equal(pack.evidence.excluded_outside_window, 2);
  assert.equal(pack.coverage.decisions_total, 2);
  assert.equal(pack.integrity_warnings.length, 0); // out-of-window is not malformed
});

test('period with no entries yields zero counts and an INDETERMINATE ratio (null, not 1)', async () => {
  const pack = buildArt14EvidencePack([], OPTS);
  assert.equal(pack.notice, ART14_HONESTY_NOTICE);
  assert.equal(pack.oversight_exercised.length, 0);
  assert.equal(pack.interventions.total, 0);
  assert.equal(pack.coverage.ratio, null);
  assert.equal(pack.evidence.head, null);
  const mdView = renderMarkdown(pack);
  assert.match(mdView, /indeterminate/);
});

test('empty or inverted period is refused', async () => {
  const entries = await chained([decision(at(1))]);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, periodEnd: START }), /empty or inverted/);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, periodStart: END, periodEnd: START }), /empty or inverted/);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, periodStart: 'not-a-date' }), /periodStart and periodEnd/);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, periodEnd: undefined }), /periodStart and periodEnd/);
});

test('missing organization/system/entries fail closed', async () => {
  const entries = await chained([decision(at(1))]);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, organization: undefined }), /organization/);
  assert.throws(() => buildArt14EvidencePack(entries, { ...OPTS, system: '' }), /system/);
  assert.throws(() => buildArt14EvidencePack('nope', OPTS), /entries must be an array/);
});

test('malformed entries land in integrity_warnings — never silently dropped', async () => {
  const good = await chained([decision(at(1))]);
  const entries = [
    good[0],
    null,                                              // not an object
    { kind: 'decision', action: 'x' },                 // no timestamp
    { kind: 'mystery', at: at(2), hash: 'h2' },        // unknown kind
    { kind: 'decision', at: at(3), reason: 'allow' },  // allow verdict missing
    { kind: 'decision', at: at(4), allow: false },     // reason missing
  ];
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.integrity_warnings.length, 5);
  assert.deepEqual(pack.integrity_warnings.map((w) => w.problem), [
    'not_an_object',
    'missing_or_unparseable_at',
    'unknown_kind',
    'malformed_decision',
    'malformed_decision',
  ]);
  // Malformed entries never leak into the tables or counts.
  assert.equal(pack.coverage.decisions_total, 1);
  assert.equal(pack.evidence.entries_in_window, 1);
  assert.equal(pack.evidence.entries_total, 6);
});

test('executions in window are counted and advance the evidence head', async () => {
  const entries = await chained([
    decision(at(1)),
    { kind: 'execution', at: at(2), authorizes_decision: 'h1', action: 'payment.release', receipt_id: 'rcpt_1', outcome: 'executed' },
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  assert.equal(pack.evidence.executions, 1);
  assert.equal(pack.evidence.head, entries[1].hash);
});

test('renderMarkdown includes the honesty notice and the report tables', async () => {
  const entries = await chained([
    decision(at(1)),
    denial(at(2), 'replay_refused'),
    decision(at(3), { reason: 'not_guarded', action: 'read.balance' }),
  ]);
  const pack = buildArt14EvidencePack(entries, OPTS);
  const mdView = renderMarkdown(pack);
  assert.ok(mdView.includes(ART14_HONESTY_NOTICE));
  assert.match(mdView, /\| ep:user:alice \| payment\.release \| class_a \| 1 \|/);
  assert.match(mdView, /one_time_consumption/);
  assert.match(mdView, /Replay attempts blocked: \*\*1\*\*/);
  assert.match(mdView, /read\.balance/);
  assert.match(mdView, /2 of 3 decision\(s\)/);
});

test('renderMarkdown fails closed on wrong version or a stripped/edited notice', async () => {
  const pack = buildArt14EvidencePack(await chained([decision(at(1))]), OPTS);
  assert.throws(() => renderMarkdown(null), /requires an EP-GATE-ART14-PACK-v1/);
  assert.throws(() => renderMarkdown({ ...pack, '@version': 'EP-GATE-ART14-PACK-v2' }), /requires an EP-GATE-ART14-PACK-v1/);
  assert.throws(() => renderMarkdown({ ...pack, notice: undefined }), /honesty notice/);
  assert.throws(() => renderMarkdown({ ...pack, notice: pack.notice + ' (certified compliant)' }), /honesty notice/);
});

test('pack is deterministic for identical inputs', async () => {
  const entries = await chained([
    decision(at(1)),
    denial(at(2), 'assurance_too_low'),
    decision(at(3), { subject: 'ep:user:bob', have_tier: 'quorum' }),
  ]);
  const a = buildArt14EvidencePack(entries, OPTS);
  const b = buildArt14EvidencePack(entries, OPTS);
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.equal(renderMarkdown(a), renderMarkdown(b));
});

test('failingPredicate maps every gate refusal family', () => {
  assert.equal(failingPredicate('receipt_required'), 'authorization_receipt_present');
  assert.equal(failingPredicate('replay_refused'), 'one_time_consumption');
  assert.equal(failingPredicate('consumption_store_lacks_reserve'), 'one_time_consumption');
  assert.equal(failingPredicate('assurance_too_low'), 'assurance_tier_sufficient');
  assert.equal(failingPredicate('unknown_required_tier'), 'assurance_tier_sufficient');
  assert.equal(failingPredicate('execution_binding_failed'), 'execution_binding_intact');
  assert.equal(failingPredicate('evidence_log_failed'), 'evidence_durably_recorded');
  assert.equal(failingPredicate('receipt_rejected:expired'), 'receipt_valid:expired');
  assert.equal(failingPredicate('brand_new_reason'), 'unmapped:brand_new_reason');
});
