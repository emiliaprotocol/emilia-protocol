// SPDX-License-Identifier: Apache-2.0
/**
 * EP-CURRENCY-v1 — mechanize the two-valued verification result EP's prose
 * already requires.
 *
 * There are TWO different questions about a receipt, and conflating them is a
 * security defect:
 *
 *   1. AUTHENTIC-AS-OF-COMMIT — "was this authorization genuinely issued and
 *      does its offline cryptography verify?" This is what the offline verifier
 *      (verifyTrustReceipt / verifyReceipt) answers from the artifact alone. It
 *      is a statement about the PAST: the receipt is authentic as of the commit
 *      that produced it.
 *
 *   2. CURRENCY-AT-T — "is this authorization STILL valid right now (at time
 *      T)?" An offline package CANNOT answer this. Currency depends on state
 *      that lives OUTSIDE the artifact and changes AFTER issuance: a fresh
 *      signed log/directory head, a status-list entry, or a revocation feed.
 *      Absence of a revocation in your hand is NOT proof of not-revoked.
 *
 * This module makes that boundary a COMPUTED value, not just prose. Offline
 * verification alone yields currency status 'unknown' — the honest, fail-safe
 * default. A caller earns 'fresh' ONLY by supplying a `freshHead`: a signed,
 * recent head/status entry whose age is within the action policy's staleness
 * bound AND which does not revoke this receipt. Anything short of that is
 * 'unknown' or 'stale', never 'fresh'.
 *
 * WHY THIS MATTERS (honesty is a security property): marketing 'fresh' — i.e.
 * reporting current validity — from an offline-only check would be a security
 * defect. It would let a relying party act on a revoked or superseded
 * authorization because the paper still cryptographically verifies. This module
 * refuses to let the offline default masquerade as currency.
 *
 * SCOPE / HONEST BOUNDARY: evaluateCurrency does NOT itself verify the receipt's
 * offline cryptography (the caller passes in the already-computed
 * authentic_as_of_commit). It does NOT prove your `freshHead` is the log's
 * globally-latest head, and it does NOT detect split-view equivocation (a log
 * showing different heads to different verifiers) — that needs independent
 * witnesses/gossip (see docs/security/TRANSPARENCY-LAYER-DESIGN.md). A
 * `freshHead` bounds RECENCY and can carry a revocation signal; it is not a
 * global-latest oracle.
 */

// Validate to a well-formed 64-char SHA-256; malformed -> '' so comparisons
// fail closed (never match a real digest) and stay cross-language consistent.
const hexOf = (h) => {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
};
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function instantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s, , oh, om] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) return NaN;
  if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59)) return NaN;
  return Date.parse(value);
}

function referenceTimeMs(value) {
  if (value === undefined) return Date.now();
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  return instantMs(value);
}

/** The two-valued currency status. 'fresh' is the ONLY value that asserts
 * current validity, and it is reachable ONLY with a policy-satisfying
 * `freshHead`. 'unknown' is the honest offline default; 'stale' means the head
 * is too old, was required but absent, or shows revocation. */
export const CURRENCY_VERSION = 'EP-CURRENCY-v1';
export const CURRENCY_STATUS = Object.freeze(['fresh', 'stale', 'unknown']);

// Exact reason strings surfaced on currency_at_T.reason. Stable identifiers so
// callers and cross-language ports can branch on them.
export const CURRENCY_REASON = Object.freeze({
  // status: 'unknown'
  offline_only_no_fresh_head: 'offline_only_no_fresh_head',
  fresh_head_malformed: 'fresh_head_malformed',
  now_invalid: 'now_invalid',
  // status: 'stale'
  fresh_head_stale: 'fresh_head_stale',
  fresh_head_in_future: 'fresh_head_in_future',
  fresh_head_required_but_absent: 'fresh_head_required_but_absent',
  revoked_by_fresh_head: 'revoked_by_fresh_head',
  max_staleness_invalid: 'max_staleness_invalid',
  // status: 'fresh'
  fresh_head_within_window: 'fresh_head_within_window',
});

/**
 * Does this signed head revoke the given receipt? A `freshHead` MAY carry a
 * status-list / revocation signal in one of two shapes:
 *
 *   - freshHead.revoked === true                          (a scalar signal), or
 *   - freshHead.revoked_target_hashes: string[] of SHA-256 digests, matched
 *     against the receipt's action_hash (and/or an explicit
 *     freshHead.target_hash the caller resolved for this receipt).
 *
 * Fail-safe: any malformed/ambiguous revocation field is treated as
 * NON-revoking here (we do not fabricate a revocation), but note that a truly
 * unusable head is separately rejected as malformed by evaluateCurrency, so a
 * head cannot both be trusted for freshness AND have its revocation signal
 * silently dropped.
 */
function headRevokesReceipt(freshHead, receipt) {
  if (freshHead && freshHead.revoked === true) return true;
  const list = freshHead && freshHead.revoked_target_hashes;
  if (Array.isArray(list) && list.length > 0) {
    const targets = new Set(list.map(hexOf).filter(Boolean));
    if (targets.size === 0) return false;
    const receiptActionHash = hexOf(receipt?.action_hash);
    const explicitTarget = hexOf(freshHead?.target_hash);
    if (receiptActionHash && targets.has(receiptActionHash)) return true;
    if (explicitTarget && targets.has(explicitTarget)) return true;
  }
  return false;
}

/**
 * Compute the two-valued verification result: authenticity-as-of-commit (from
 * the offline check the caller already ran) and currency-at-T (which offline
 * CANNOT establish and which is therefore 'unknown' by default).
 *
 * @param {object} args
 * @param {object} [args.receipt]  the receipt being evaluated. Used only to match
 *   a `freshHead` revocation signal to this authorization; its offline
 *   cryptography is NOT re-checked here.
 * @param {boolean} [args.authentic_as_of_commit]  the boolean the caller already
 *   computed from offline verification (e.g. verifyTrustReceipt(...).valid).
 *   Passed through verbatim. Fail-safe: anything not strictly `true` is
 *   recorded as false.
 * @param {number|string|Date} [args.now]  reference instant T. Defaults to the
 *   current wall clock. If unparseable, currency is 'unknown' (we will not
 *   compute an age against a bad clock).
 * @param {number} [args.maxStalenessSeconds]  the maximum age (seconds) a
 *   `freshHead` may have and still count as fresh. THIS IS AN ACTION-POLICY
 *   FIELD: it belongs in the per-action-class policy (higher-consequence,
 *   irreversible actions demand a tighter bound; low-stakes reads may tolerate
 *   a looser one), NOT a global constant baked into the verifier. Fail-safe:
 *   when a `freshHead` is supplied but this bound is missing or not a finite
 *   non-negative number, currency is 'stale' (we refuse to certify freshness
 *   without a policy bound to measure it against).
 * @param {object} [args.freshHead]  a SIGNED, recent directory/log head or
 *   status-list entry the caller obtained ONLINE and (by contract) already
 *   verified the signature of. Shape:
 *     { observed_at: '<RFC 3339>',        // when this head was observed/issued
 *       // OR issued_at: '<RFC 3339>'
 *       revoked?: boolean,                // scalar revocation signal, and/or
 *       revoked_target_hashes?: string[], // status-list of revoked digests
 *       target_hash?: string }            // this receipt's status-list target
 *   Supplying a `freshHead` is the ONLY way to reach 'fresh'.
 * @param {boolean} [args.freshHeadRequired]  policy flag: this action class
 *   REQUIRES a fresh head to act. When true and no `freshHead` is supplied,
 *   currency is 'stale' (required-but-absent) rather than 'unknown' — the
 *   policy has declared that offline-only is not good enough to proceed.
 * @returns {{
 *   authentic_as_of_commit: boolean,
 *   currency_at_T: { status: 'fresh'|'stale'|'unknown', evaluated_at: string|null, reason: string }
 * }}
 */
export function evaluateCurrency(args = {}) {
  const {
    receipt,
    authentic_as_of_commit,
    now,
    maxStalenessSeconds,
    freshHead,
    freshHeadRequired,
  } = (args && typeof args === 'object') ? args : {};

  // Pass the offline result through verbatim, fail-safe to false.
  const authentic = authentic_as_of_commit === true;

  // Resolve reference time T. A bad clock must NOT silently become "now": an
  // unparseable `now` yields 'unknown' (we will not measure age against it).
  const nowMs = referenceTimeMs(now);
  const evaluated_at = Number.isFinite(nowMs) ? new Date(nowMs).toISOString() : null;

  const result = (status, reason) => ({
    authentic_as_of_commit: authentic,
    currency_at_T: { status, evaluated_at, reason },
  });

  // No fresh head: offline CANNOT prove currency. This is the fail-safe path.
  if (freshHead === undefined || freshHead === null) {
    // Policy may declare offline-only insufficient for this action class.
    if (freshHeadRequired === true) {
      return result('stale', CURRENCY_REASON.fresh_head_required_but_absent);
    }
    return result('unknown', CURRENCY_REASON.offline_only_no_fresh_head);
  }

  // A fresh head was supplied. If T is unusable, we cannot compute the head's
  // age, so we cannot certify freshness — fall back to the honest 'unknown'.
  if (!Number.isFinite(nowMs)) {
    return result('unknown', CURRENCY_REASON.now_invalid);
  }

  // The head must be a usable object carrying a well-formed observation instant.
  // A malformed head cannot certify freshness -> 'unknown' (we do not know), not
  // 'fresh'. (It is not 'stale' because staleness is a claim about age, which we
  // cannot compute from an unparseable timestamp.)
  if (typeof freshHead !== 'object') {
    return result('unknown', CURRENCY_REASON.fresh_head_malformed);
  }
  let headMs = instantMs(freshHead.observed_at);
  if (!Number.isFinite(headMs)) headMs = instantMs(freshHead.issued_at);
  if (!Number.isFinite(headMs)) {
    return result('unknown', CURRENCY_REASON.fresh_head_malformed);
  }

  // maxStalenessSeconds is the action-policy bound. Without a valid bound we
  // refuse to certify freshness: fail-safe to 'stale'.
  if (typeof maxStalenessSeconds !== 'number'
      || !Number.isFinite(maxStalenessSeconds)
      || maxStalenessSeconds < 0) {
    return result('stale', CURRENCY_REASON.max_staleness_invalid);
  }

  // A future-dated head cannot certify current status. Clock-skew tolerance, if
  // any, is a relying-party policy and must be explicit rather than implicit.
  const ageSeconds = (nowMs - headMs) / 1000;
  if (ageSeconds < 0) {
    return result('stale', CURRENCY_REASON.fresh_head_in_future);
  }

  // Revocation shown by the head dominates: a revoked authorization is not
  // current regardless of how recent the head is.
  if (headRevokesReceipt(freshHead, receipt)) {
    return result('stale', CURRENCY_REASON.revoked_by_fresh_head);
  }

  // Age gate.
  if (ageSeconds > maxStalenessSeconds) {
    return result('stale', CURRENCY_REASON.fresh_head_stale);
  }

  // Recent, signed (by caller contract), non-revoking head within the policy
  // window: this is the ONLY path to 'fresh'.
  return result('fresh', CURRENCY_REASON.fresh_head_within_window);
}
