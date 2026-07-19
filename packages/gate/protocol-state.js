/**
 * EP Protocol-State — brand-typed handshake lifecycle (GAP-4).
 *
 * Purpose: make an ILLEGAL protocol-state transition a COMPILE error, not a
 * runtime failure. Each lifecycle state is a distinct nominal (branded) type,
 * and every transition is a function whose parameter type admits ONLY its legal
 * predecessor state(s) and whose return type is exactly its legal successor.
 * Passing the wrong state to a transition (e.g. `consume(initiated)` — consuming
 * before verification) is rejected by `tsc` before the code ever runs.
 *
 * ── Source of truth ─────────────────────────────────────────────────────────
 * The state graph mirrors the formally-verified model, not a toy:
 *   formal/ep_handshake.tla   — abstract lifecycle + transition guards
 *   lib/handshake/invariants.js (HANDSHAKE_STATUSES) — the 6 persisted statuses
 *   lib/handshake/create.js    — status:'initiated'          (T1 Initiate)
 *   lib/handshake/present.js   — initiated → pending_verification (T2 Present)
 *   lib/handshake/verify.js    — outcome accepted/rejected/expired (T3/T4/T7)
 *   lib/handshake/consume.js   — verified → consumed            (T5 Consume)
 *   lib/handshake/finalize.js  — → revoked                       (T6 Revoke)
 *
 * ── States (TLA `state` domain) ─────────────────────────────────────────────
 *   none | initiated | pending_verification | verified
 *   | rejected | expired | revoked | consumed
 *
 * Two of these are ABSTRACT lifecycle states, not DB status values:
 *   - `none`     : pre-initiation. There is no persisted row yet.
 *   - `consumed` : a verified handshake that has an entry in the
 *                  `handshake_consumptions` table. Consumption does NOT rewrite
 *                  `handshakes.status` (it stays 'verified'); it is recorded
 *                  atomically in a side table by `consume_handshake_atomic`.
 *                  The TLA model abstracts (status='verified' ∧ h∈consumptions)
 *                  as the distinct terminal state `consumed`. This module keeps
 *                  that abstraction so "consume-once" and "no-verify-after-consume"
 *                  are expressible in the type system.
 *
 * The other six are exactly `HANDSHAKE_STATUSES` from invariants.js and carry a
 * `dbStatus` field equal to the persisted `handshakes.status` value.
 *
 * ── Legal transition graph (the ONLY edges; everything else is a type error) ─
 *   genesis()                                        -> None
 *   initiate(None)                                   -> Initiated
 *   present(Initiated)                               -> PendingVerification
 *   verifyAccept(PendingVerification)                -> Verified
 *   verifyReject(PendingVerification)                -> Rejected      (terminal)
 *   consume(Verified)                                -> Consumed      (terminal)
 *   revoke(Initiated|PendingVerification|Verified)   -> Revoked       (terminal)
 *   expire(Initiated|PendingVerification|Verified)   -> Expired       (terminal)
 *
 * Terminal states (Rejected, Expired, Revoked, Consumed) are accepted by NO
 * transition function, so any move out of a terminal state is a compile error.
 *
 * Branding note: each state is nominally distinguished by a private, readonly
 * string-literal `tag`. Distinct tags make each state a distinct type, so no
 * legal predecessor of one transition is accidentally assignable to another.
 * The runtime value literally is `{ tag, dbStatus }`; there is no phantom-only
 * field, so no casts are needed and the runtime and the types cannot drift.
 *
 * This module is intentionally free of I/O. It is the compile-time spine that
 * the runtime state machine (verify.js / consume.js / finalize.js) is expected
 * to obey; it does not replace those code paths' own DB-level guards.
 *
 * @license Apache-2.0
 */

/**
 * The six persisted `handshakes.status` values (single source: invariants.js
 * HANDSHAKE_STATUSES). `none` and `consumed` are abstract and have no row status.
 * @typedef {'initiated'|'pending_verification'|'verified'|'rejected'|'expired'|'revoked'} DbHandshakeStatus
 */

/**
 * Pre-initiation. No persisted handshake exists yet.
 * @typedef {{ readonly tag: 'none', readonly dbStatus: null }} None
 */
/**
 * A handshake row was created (T1). DB status 'initiated'.
 * @typedef {{ readonly tag: 'initiated', readonly dbStatus: 'initiated' }} Initiated
 */
/**
 * A presentation was added and verification is pending (T2). DB 'pending_verification'.
 * @typedef {{ readonly tag: 'pending_verification', readonly dbStatus: 'pending_verification' }} PendingVerification
 */
/**
 * Verification accepted (T3). DB 'verified'. Only state from which consume is legal.
 * @typedef {{ readonly tag: 'verified', readonly dbStatus: 'verified' }} Verified
 */
/**
 * Verification rejected (T4). Terminal. DB 'rejected'.
 * @typedef {{ readonly tag: 'rejected', readonly dbStatus: 'rejected' }} Rejected
 */
/**
 * Binding expired (T7). Terminal. DB 'expired'.
 * @typedef {{ readonly tag: 'expired', readonly dbStatus: 'expired' }} Expired
 */
/**
 * Revoked by a party (T6). Terminal. DB 'revoked'.
 * @typedef {{ readonly tag: 'revoked', readonly dbStatus: 'revoked' }} Revoked
 */
/**
 * Consumed exactly once (T5). Terminal abstract state; the row keeps DB status
 * 'verified' and gains a `handshake_consumptions` record.
 * @typedef {{ readonly tag: 'consumed', readonly dbStatus: 'verified' }} Consumed
 */

/**
 * Any state in the lifecycle.
 * @typedef {None|Initiated|PendingVerification|Verified|Rejected|Expired|Revoked|Consumed} ProtocolState
 */
/**
 * States a still-active handshake can be revoked or expired from (T6/T7 domain).
 * @typedef {Initiated|PendingVerification|Verified} Active
 */

/**
 * T0: genesis — the empty pre-initiation state.
 * @returns {None}
 */
export function genesis() {
  return { tag: 'none', dbStatus: null };
}

/**
 * T1 Initiate: none -> initiated. Maps to create.js status:'initiated'.
 * @param {None} _s
 * @returns {Initiated}
 */
export function initiate(_s) {
  return { tag: 'initiated', dbStatus: 'initiated' };
}

/**
 * T2 Present: initiated -> pending_verification. Maps to present.js.
 * @param {Initiated} _s
 * @returns {PendingVerification}
 */
export function present(_s) {
  return { tag: 'pending_verification', dbStatus: 'pending_verification' };
}

/**
 * T3 VerifyAccept: pending_verification -> verified. verify.js outcome='accepted'.
 * @param {PendingVerification} _s
 * @returns {Verified}
 */
export function verifyAccept(_s) {
  return { tag: 'verified', dbStatus: 'verified' };
}

/**
 * T4 VerifyReject: pending_verification -> rejected (terminal). verify.js outcome='rejected'.
 * @param {PendingVerification} _s
 * @returns {Rejected}
 */
export function verifyReject(_s) {
  return { tag: 'rejected', dbStatus: 'rejected' };
}

/**
 * T5 Consume: verified -> consumed (terminal). consume.js requires 'verified' state
 * and enforces consume-once at the DB level.
 * @param {Verified} _s
 * @returns {Consumed}
 */
export function consume(_s) {
  return { tag: 'consumed', dbStatus: 'verified' };
}

/**
 * T6 Revoke: {initiated|pending_verification|verified} -> revoked (terminal).
 * finalize.js. Legal only from an active (pre-terminal) state.
 * @param {Active} _s
 * @returns {Revoked}
 */
export function revoke(_s) {
  return { tag: 'revoked', dbStatus: 'revoked' };
}

/**
 * T7 Expire: {initiated|pending_verification|verified} -> expired (terminal).
 * verify.js outcome='expired'. Legal only from an active (pre-terminal) state.
 * @param {Active} _s
 * @returns {Expired}
 */
export function expire(_s) {
  return { tag: 'expired', dbStatus: 'expired' };
}
