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
/** The two-valued currency status. 'fresh' is the ONLY value that asserts
 * current validity, and it is reachable ONLY with a policy-satisfying
 * `freshHead`. 'unknown' is the honest offline default; 'stale' means the head
 * is too old, was required but absent, or shows revocation. */
export declare const CURRENCY_VERSION = "EP-CURRENCY-v1";
export declare const CURRENCY_STATUS: readonly string[];
export declare const CURRENCY_REASON: Readonly<{
    offline_only_no_fresh_head: "offline_only_no_fresh_head";
    fresh_head_malformed: "fresh_head_malformed";
    now_invalid: "now_invalid";
    fresh_head_stale: "fresh_head_stale";
    fresh_head_in_future: "fresh_head_in_future";
    fresh_head_required_but_absent: "fresh_head_required_but_absent";
    revoked_by_fresh_head: "revoked_by_fresh_head";
    max_staleness_invalid: "max_staleness_invalid";
    fresh_head_within_window: "fresh_head_within_window";
}>;
export type CurrencyStatus = 'fresh' | 'stale' | 'unknown';
export interface CurrencyArgs {
    receipt?: Record<string, unknown> | null;
    authentic_as_of_commit?: boolean;
    now?: number | string | Date;
    maxStalenessSeconds?: number;
    freshHead?: Record<string, unknown> | null;
    freshHeadRequired?: boolean;
}
export interface CurrencyResult {
    authentic_as_of_commit: boolean;
    currency_at_T: {
        status: CurrencyStatus;
        evaluated_at: string | null;
        reason: string;
    };
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
export declare function evaluateCurrency(args?: CurrencyArgs): CurrencyResult;
//# sourceMappingURL=currency.d.ts.map