// SPDX-License-Identifier: Apache-2.0
//
// EP-CURRENCY-v1 test. Asserts the two-valued verification result:
// authentic_as_of_commit is passed through, and currency_at_T is the COMPUTED
// value offline verification cannot supply. Covers all four status outcomes:
//   - 'unknown' — no fresh head (the honest, fail-safe offline default)
//   - 'fresh'   — a recent, non-revoking head within the policy staleness bound
//   - 'stale'   — head older than the policy bound
//   - 'stale'   (revoked) — head shows this receipt revoked
// Plus the fail-safe branches: required-but-absent head, missing policy bound,
// unparseable now, malformed head, and offline-false pass-through.
import { test } from 'node:test';
import assert from 'node:assert';
import { evaluateCurrency, CURRENCY_STATUS, CURRENCY_REASON, CURRENCY_VERSION } from './currency.js';

const NOW = '2026-07-05T12:00:00.000Z';
const ACTION_HASH = 'sha256:' + 'a'.repeat(64);
const OTHER_HASH = 'sha256:' + 'b'.repeat(64);
const receipt = { action_hash: ACTION_HASH };

// A head observed `sec` seconds before NOW.
function headAt(sec, extra = {}) {
  const observed_at = new Date(Date.parse(NOW) - sec * 1000).toISOString();
  return { observed_at, ...extra };
}

test('enum and version are the honest two-valued shape', () => {
  assert.deepStrictEqual([...CURRENCY_STATUS].sort(), ['fresh', 'stale', 'unknown']);
  assert.strictEqual(CURRENCY_VERSION, 'EP-CURRENCY-v1');
});

// ── status: 'unknown' — the fail-safe offline default ────────────────────────
test("no freshHead => 'unknown' (offline cannot prove currency, never 'fresh')", () => {
  const r = evaluateCurrency({ receipt, authentic_as_of_commit: true, now: NOW });
  assert.strictEqual(r.authentic_as_of_commit, true);
  assert.strictEqual(r.currency_at_T.status, 'unknown');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.offline_only_no_fresh_head);
  assert.strictEqual(r.currency_at_T.evaluated_at, NOW);
  // The core honesty invariant: an offline-only check must NEVER report 'fresh'.
  assert.notStrictEqual(r.currency_at_T.status, 'fresh');
});

test("null freshHead is the same fail-safe 'unknown' as absent", () => {
  const r = evaluateCurrency({ receipt, authentic_as_of_commit: true, now: NOW, freshHead: null });
  assert.strictEqual(r.currency_at_T.status, 'unknown');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.offline_only_no_fresh_head);
});

// ── status: 'fresh' — recent, non-revoking head within policy bound ──────────
test("recent non-revoking head within maxStalenessSeconds => 'fresh'", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(60), // 60s old, bound is 300s
  });
  assert.strictEqual(r.currency_at_T.status, 'fresh');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.fresh_head_within_window);
  assert.strictEqual(r.currency_at_T.evaluated_at, NOW);
});

test("'fresh' does not depend on authenticity — currency is a separate axis", () => {
  // authentic_as_of_commit passes through independently of currency.
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: false,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(10),
  });
  assert.strictEqual(r.authentic_as_of_commit, false);
  assert.strictEqual(r.currency_at_T.status, 'fresh');
});

// ── status: 'stale' — head older than the policy bound ───────────────────────
test("head older than maxStalenessSeconds => 'stale'", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(600), // 600s old, bound is 300s
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.fresh_head_stale);
});

test("future-dated status head => 'stale', never 'fresh'", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(-60),
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.fresh_head_in_future);
});

// ── status: 'stale' — head shows revocation ──────────────────────────────────
test("head with scalar revoked:true => 'stale' (revoked), even if recent", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(5, { revoked: true }),
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.revoked_by_fresh_head);
});

test("head status-list revoking this receipt's action_hash => 'stale' (revoked)", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(5, { revoked_target_hashes: [ACTION_HASH] }),
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.revoked_by_fresh_head);
});

test("status-list that revokes a DIFFERENT target does not revoke this receipt", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: headAt(5, { revoked_target_hashes: [OTHER_HASH] }),
  });
  assert.strictEqual(r.currency_at_T.status, 'fresh');
});

// ── fail-safe branches ───────────────────────────────────────────────────────
test("policy requires a fresh head but none supplied => 'stale' (required-but-absent)", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    freshHeadRequired: true,
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.fresh_head_required_but_absent);
});

test("freshHead supplied but no policy bound => 'stale' (cannot certify freshness)", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    freshHead: headAt(1), // recent, but no maxStalenessSeconds to measure against
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.max_staleness_invalid);
});

test("negative maxStalenessSeconds is not a valid bound => 'stale'", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: -1,
    freshHead: headAt(1),
  });
  assert.strictEqual(r.currency_at_T.status, 'stale');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.max_staleness_invalid);
});

test("non-finite maxStalenessSeconds is not a valid bound => 'stale'", () => {
  for (const bound of [Number.NaN, Number.POSITIVE_INFINITY]) {
    const r = evaluateCurrency({
      receipt,
      authentic_as_of_commit: true,
      now: NOW,
      maxStalenessSeconds: bound,
      freshHead: headAt(1),
    });
    assert.strictEqual(r.currency_at_T.status, 'stale');
    assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.max_staleness_invalid);
  }
});

test("unparseable now => 'unknown' (won't measure age against a bad clock)", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: 'not-a-time',
    maxStalenessSeconds: 300,
    freshHead: headAt(1),
  });
  assert.strictEqual(r.currency_at_T.status, 'unknown');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.now_invalid);
  assert.strictEqual(r.currency_at_T.evaluated_at, null);
});

test("malformed head (no observation instant) => 'unknown', never 'fresh'", () => {
  const r = evaluateCurrency({
    receipt,
    authentic_as_of_commit: true,
    now: NOW,
    maxStalenessSeconds: 300,
    freshHead: { revoked: false }, // no observed_at / issued_at
  });
  assert.strictEqual(r.currency_at_T.status, 'unknown');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.fresh_head_malformed);
});

test('authentic_as_of_commit passes through and fail-safes non-true to false', () => {
  const r1 = evaluateCurrency({ receipt, authentic_as_of_commit: 'yes', now: NOW });
  assert.strictEqual(r1.authentic_as_of_commit, false);
  const r2 = evaluateCurrency({ receipt, now: NOW }); // omitted
  assert.strictEqual(r2.authentic_as_of_commit, false);
});

test('empty args object does not throw and yields the fail-safe unknown default', () => {
  const r = evaluateCurrency();
  assert.strictEqual(r.authentic_as_of_commit, false);
  assert.strictEqual(r.currency_at_T.status, 'unknown');
  assert.strictEqual(r.currency_at_T.reason, CURRENCY_REASON.offline_only_no_fresh_head);
});
