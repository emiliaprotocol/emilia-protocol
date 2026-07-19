/**
 * EP Protocol-State — TYPE-LEVEL conformance test (GAP-4).
 *
 * This file is checked by `tsc` under tsconfig.core.json, not run as a unit
 * test. It asserts, at compile time, that the ONLY legal transitions of the
 * handshake lifecycle are the ones the formal model permits:
 *
 *   - The "legal sequences" section MUST type-check with no errors.
 *   - Every `// @ts-expect-error` line guards a transition that MUST be illegal.
 *     If any such transition ever becomes legal (a regression in the brand
 *     types), tsc reports the `@ts-expect-error` as UNUSED and the type-gate
 *     fails. This is the tripwire.
 *
 * These are type-only assertions; the functions are pure and the file is safe
 * to load, but nothing here is intended to run.
 *
 * @license Apache-2.0
 */

import {
  genesis, initiate, present, verifyAccept, verifyReject, consume, revoke, expire,
} from './protocol-state.js';

/* eslint-disable no-unused-vars */

// ── LEGAL SEQUENCES (must compile) ──────────────────────────────────────────

// Full happy path: none → initiated → pending_verification → verified → consumed
const _consumed = consume(verifyAccept(present(initiate(genesis()))));

// Reject branch: … → pending_verification → rejected
const _rejected = verifyReject(present(initiate(genesis())));

// Revoke is legal from every active (pre-terminal) state:
const _revokedFromInitiated = revoke(initiate(genesis()));
const _revokedFromPending = revoke(present(initiate(genesis())));
const _revokedFromVerified = revoke(verifyAccept(present(initiate(genesis()))));

// Expire is legal from every active (pre-terminal) state:
const _expiredFromInitiated = expire(initiate(genesis()));
const _expiredFromPending = expire(present(initiate(genesis())));
const _expiredFromVerified = expire(verifyAccept(present(initiate(genesis()))));

// Convenience handles to well-typed states for the illegal section below.
const none = genesis();
const initiated = initiate(none);
const pending = present(initiated);
const verified = verifyAccept(pending);
const consumedState = consume(verified);
const revokedState = revoke(initiated);
const rejectedState = verifyReject(pending);
const expiredState = expire(initiated);

// ── ILLEGAL TRANSITIONS (each MUST be a type error) ─────────────────────────

// Consume before verification — the canonical GAP-4 violation.
// @ts-expect-error consume requires Verified, not None
consume(none);
// @ts-expect-error consume requires Verified, not Initiated
consume(initiated);
// @ts-expect-error consume requires Verified, not PendingVerification
consume(pending);

// Skipping the presentation step (initiated → verified directly).
// @ts-expect-error verifyAccept requires PendingVerification, not Initiated
verifyAccept(initiated);
// @ts-expect-error verifyReject requires PendingVerification, not Initiated
verifyReject(initiated);

// Presenting after the handshake already left the initiated state.
// @ts-expect-error present requires Initiated, not PendingVerification
present(pending);
// @ts-expect-error present requires Initiated, not Verified
present(verified);

// Re-initiating something that already exists.
// @ts-expect-error initiate requires None, not Verified
initiate(verified);

// No transition may leave a TERMINAL state (consumed/revoked/rejected/expired).
// @ts-expect-error cannot consume a Consumed handshake (consume-once)
consume(consumedState);
// @ts-expect-error cannot revoke a Consumed handshake
revoke(consumedState);
// @ts-expect-error cannot expire a Consumed handshake
expire(consumedState);
// @ts-expect-error cannot verify a Revoked handshake
verifyAccept(revokedState);
// @ts-expect-error cannot revoke an already-Revoked handshake
revoke(revokedState);
// @ts-expect-error cannot consume a Rejected handshake
consume(rejectedState);
// @ts-expect-error cannot revoke an Expired handshake
revoke(expiredState);
