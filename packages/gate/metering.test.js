// Generated from metering.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate metering tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { meterUsage, buildUsageStatement, USAGE_VERSION } from './metering.js';
const START = '2026-06-01T00:00:00.000Z';
const END = '2026-07-01T00:00:00.000Z';
const PERIOD = { periodStart: START, periodEnd: END };
// A gate decision record as decide() in index.js writes it (fields we consume).
function decision(over = {}) {
    return {
        kind: 'decision', at: '2026-06-15T12:00:00.000Z', action: 'payment.release',
        allow: true, status: 200, reason: 'allow', required_tier: 'class_a',
        receipt_id: 'rcpt_1', hash: 'h1', ...over,
    };
}
test('counts protected actions, allows, denies, replays over the period', () => {
    const u = meterUsage([
        decision(),
        decision({ allow: false, status: 428, reason: 'assurance_too_low' }),
        decision({ allow: false, status: 428, reason: 'replay_refused' }),
    ], PERIOD);
    assert.equal(u.protected_actions, 3);
    assert.equal(u.allows, 1);
    assert.equal(u.denies, 2);
    assert.equal(u.replays_blocked, 1);
    assert.deepEqual(u.integrity_warnings, []);
});
test('breaks down by action type and required tier', () => {
    const u = meterUsage([
        decision(),
        decision({ action: 'db.drop_table', required_tier: 'quorum' }),
        decision({ action: 'db.drop_table', required_tier: 'quorum' }),
        decision({ action: null, required_tier: undefined }),
    ], PERIOD);
    assert.deepEqual(u.by_action_type, { 'db.drop_table': 2, 'payment.release': 1, unknown: 1 });
    assert.deepEqual(u.by_tier, { class_a: 1, quorum: 2, unknown: 1 });
});
test('not_guarded pass-throughs are never billed', () => {
    const u = meterUsage([decision({ reason: 'not_guarded', status: 200 })], PERIOD);
    assert.equal(u.protected_actions, 0);
    assert.equal(u.receipt_years, 0);
});
test('execution records are provenance, not billable decisions', () => {
    const u = meterUsage([
        { kind: 'execution', at: '2026-06-15T12:00:00.000Z', outcome: 'executed', hash: 'h2' },
    ], PERIOD);
    assert.equal(u.protected_actions, 0);
    assert.deepEqual(u.integrity_warnings, []);
});
test('period start is inclusive', () => {
    const u = meterUsage([decision({ at: START })], PERIOD);
    assert.equal(u.protected_actions, 1);
});
test('period end is exclusive — boundary entry belongs to the NEXT period', () => {
    const u = meterUsage([decision({ at: END })], PERIOD);
    assert.equal(u.protected_actions, 0);
    const next = meterUsage([decision({ at: END })], { periodStart: END, periodEnd: '2026-08-01T00:00:00.000Z' });
    assert.equal(next.protected_actions, 1);
});
test('out-of-period entries are excluded without warnings', () => {
    const u = meterUsage([
        decision({ at: '2026-05-31T23:59:59.999Z' }),
        decision({ at: '2026-07-02T00:00:00.000Z' }),
    ], PERIOD);
    assert.equal(u.protected_actions, 0);
    assert.deepEqual(u.integrity_warnings, []);
});
test('empty period (start === end) is valid and meters zero', () => {
    const u = meterUsage([decision({ at: START })], { periodStart: START, periodEnd: START });
    assert.equal(u.protected_actions, 0);
    assert.equal(u.receipt_years, 0);
    assert.equal(u.period.start, u.period.end);
});
test('receipt_years applies the default when retention is unstated', () => {
    const u = meterUsage([decision(), decision({ hash: 'h2' })], PERIOD);
    assert.equal(u.receipt_years, 12); // 2 x default 6y (2190d, matching retention.js cold horizon)
    assert.equal(u.retention_years_default, 6);
});
test('receipt_years honors stated retention_years and retention_days', () => {
    const u = meterUsage([
        decision({ retention_years: 10 }),
        decision({ retention_days: 730 }), // 2y
        decision(), // default 6y
    ], { ...PERIOD, retentionYearsDefault: 6 });
    assert.equal(u.receipt_years, 18);
});
test('invalid stated retention falls back to the default WITH an integrity warning', () => {
    const u = meterUsage([decision({ retention_years: -1 })], PERIOD);
    assert.equal(u.protected_actions, 1);
    assert.equal(u.receipt_years, 6); // never silently shrinks the metered total
    assert.deepEqual(u.integrity_warnings, [{ index: 0, reason: 'invalid_stated_retention' }]);
});
test('malformed entries go to integrity_warnings and are never counted', () => {
    const u = meterUsage([
        null,
        'not-an-entry',
        decision({ at: 'garbage' }),
        { at: '2026-06-15T12:00:00.000Z', allow: true }, // no kind
        decision(),
    ], PERIOD);
    assert.equal(u.protected_actions, 1);
    assert.deepEqual(u.integrity_warnings, [
        { index: 0, reason: 'not_an_object' },
        { index: 1, reason: 'not_an_object' },
        { index: 2, reason: 'unparseable_at' },
        { index: 3, reason: 'missing_kind' },
    ]);
});
test('fail closed: a non-boolean allow flag counts as a deny', () => {
    const u = meterUsage([decision({ allow: 'true' }), decision({ allow: 1 })], PERIOD);
    assert.equal(u.allows, 0);
    assert.equal(u.denies, 2);
});
test('missing, unparseable, or reversed period is refused', () => {
    assert.throws(() => meterUsage([], {}), /periodStart and periodEnd are required/);
    assert.throws(() => meterUsage([], { periodStart: 'nope', periodEnd: END }), /required/);
    assert.throws(() => meterUsage([], { periodStart: END, periodEnd: START }), /periodEnd must be >= periodStart/);
    assert.throws(() => meterUsage([], { ...PERIOD, retentionYearsDefault: -6 }), /retentionYearsDefault/);
    assert.throws(() => meterUsage([], { ...PERIOD, retentionYearsDefault: NaN }), /retentionYearsDefault/);
});
test('statement is deterministic: entry order never changes the content hash', () => {
    const entries = [
        decision(),
        decision({ action: 'db.drop_table', required_tier: 'quorum', hash: 'h2' }),
        decision({ allow: false, status: 428, reason: 'replay_refused', hash: 'h3' }),
    ];
    const a = buildUsageStatement(meterUsage(entries, PERIOD), { org: 'ep:org:acme' });
    const b = buildUsageStatement(meterUsage([...entries].reverse(), PERIOD), { org: 'ep:org:acme' });
    assert.deepEqual(a, b);
    assert.equal(a.content_hash, b.content_hash);
    assert.match(a.content_hash, /^[0-9a-f]{64}$/);
});
test('statement carries the format version, org, period, and counts', () => {
    const u = meterUsage([decision()], PERIOD);
    const s = buildUsageStatement(u, { org: 'ep:org:acme' });
    assert.equal(s['@version'], USAGE_VERSION);
    assert.equal(s.kind, 'usage_statement');
    assert.equal(s.org, 'ep:org:acme');
    assert.equal(s.period.start, START);
    assert.equal(s.period.end, END);
    assert.equal(s.period.bounds, 'inclusive_start_exclusive_end');
    assert.equal(s.protected_actions, 1);
    assert.equal(s.receipt_years, 6);
    assert.equal(s.complete, true);
    assert.equal(s.integrity_warning_count, 0);
});
test('statement over a warned log is flagged incomplete, never silently clean', () => {
    const u = meterUsage([null, decision()], PERIOD);
    const s = buildUsageStatement(u, { org: 'ep:org:acme' });
    assert.equal(s.complete, false);
    assert.equal(s.integrity_warning_count, 1);
});
test('statement refuses a missing org and foreign or malformed usage', () => {
    const u = meterUsage([decision()], PERIOD);
    assert.throws(() => buildUsageStatement(u, {}), /org is required/);
    assert.throws(() => buildUsageStatement(u), /org is required/);
    assert.throws(() => buildUsageStatement(null, { org: 'ep:org:acme' }), /must be a EP-GATE-USAGE-v1/);
    assert.throws(() => buildUsageStatement({ '@version': 'EP-GATE-RETENTION-EXPORT-v1' }, { org: 'ep:org:acme' }), /must be a EP-GATE-USAGE-v1/);
    assert.throws(() => buildUsageStatement({ ...u, protected_actions: NaN }, { org: 'ep:org:acme' }), /protected_actions/);
    assert.throws(() => buildUsageStatement({ ...u, period: null }, { org: 'ep:org:acme' }), /period/);
});
test('tampering with a metered count changes the content hash', () => {
    const u = meterUsage([decision()], PERIOD);
    const honest = buildUsageStatement(u, { org: 'ep:org:acme' });
    const inflated = buildUsageStatement({ ...u, protected_actions: 2 }, { org: 'ep:org:acme' });
    assert.notEqual(honest.content_hash, inflated.content_hash);
});
