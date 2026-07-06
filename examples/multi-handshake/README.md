# Multi-handshake quorum composer (EP-QUORUM reference composer)

A runnable, offline reference composer for EP-QUORUM-v1
(`standards/posted/draft-schrock-ep-quorum-02.txt`). It assembles a 2-of-3
ordered composition of member handshakes over one canonical action, refuses
every non-conforming handshake at the incremental admission rule (spec
Section 6) before it can enter the trail, then hands the composed quorum
document to the real verifier (`verifyQuorum` in `packages/verify`, the same
entry point the conformance runner calls on
`conformance/vectors/quorum.v1.json`) and prints its verdict.

## Run

```
node examples/multi-handshake/compose-and-verify.mjs
```

Node 18+, zero dependencies beyond `node:crypto` and the in-repo
`packages/verify`. The script is itself a test: it exits non-zero if the
expected acceptance fails or any expected refusal unexpectedly passes, so CI
can run exactly that one command.

## What it demonstrates

| # | Scenario | Stage | Reason |
|---|----------|-------|--------|
| accept | 2-of-3 ordered composition | verify | real verifier returns `valid: true`, all nine checks pass |
| 1 | out-of-order signature (slot 2 signs before slot 1) | admission | `out_of_order` |
| 2 | initiator self-approval | admission | `self_approval` |
| 3 | replayed member handshake (reused one-time nonce), plus the stale-challenge variant | admission | `challenge_reused`, `stale_challenge` |
| 4 | off-roster key (valid-looking assertion, not the enrolled device key) | admission | `invalid_signature` |
| 5 | off-roster member forced past admission | verify | `valid: false`, `roles_admitted: false` |

Each member handshake is an unmodified EP signoff: a Class-A-shaped WebAuthn
assertion (ECDSA P-256, `rpIdHash`, UP and UV flags, DER signature) whose
challenge is `b64u(SHA-256(canonical(context)))`, exactly the wire shape of
the conformance vectors. The composer issues each member a fresh challenge
with a one-time 128-bit nonce and a bounded validity window, binds it to the
exact action hash, and embeds an ordering commitment over the prior trail
(`prev_context_hash`, the SHA-256 of the predecessor's canonical context)
inside every signed context after the first.

## Admission-time vs verify-time enforcement

Admission time (spec Section 6, `canAccept`): the composer evaluates the
incremental admission rule before recording each new signoff, so a
wrong-action, wrong-role, duplicate, out-of-order, stale, replayed, or
invalid handshake never becomes part of the trail. Challenge one-time
consumption and staleness live here: they are composer-side state, and
offline verification cannot re-establish them, so replay and staleness are
admission-time refusals by construction.

Verify time (spec Section 5, the quorum gate): a Verifying Executor
re-evaluates the full fail-closed predicate over the assembled trail before
performing the action, because the executor does not trust the composer to
have applied admission honestly. Demonstration 5 shows this: an off-roster
member forced into the trail past admission still causes the real verifier
to return `valid: false`.

## Wire-shape note (honest)

The JS reference verifier's ordered wire mode requires every roster slot to
sign (a full-roster escalation chain). A 2-of-3 composition that stops at
the threshold is therefore expressed on the wire as a threshold policy
(`mode: "threshold"`, `required: 2`, three roster slots): the declared
roster order is enforced by the composer at admission time (`out_of_order`),
and the ordering commitment is carried inside each signed context via
`prev_context_hash`. The verifier and the conformance vectors are ground
truth for the wire shape; this example never modifies either.

## Honest scope

- This is a reference composer. The production composer lives in the
  application layer; this demo exists so a third party can reproduce the
  composition semantics against the real verifier with one command.
- `valid: true` from `verifyQuorum` means the members are internally
  consistent with the policy and keys the function was handed. The policy is
  an input, not a trust anchor: a deployment must source the policy and each
  enrolled approver key out of band from trusted material, never from the
  document's creator (see the header of `packages/verify/quorum.js`).
- Offline verification does not establish current validity: nonce
  consumption, revocation, and enrollment state are server-side facts. The
  demo models them inside the composer, which is exactly where the spec
  places them.
- The device keys here are freshly generated P-256 keys simulating WebAuthn
  authenticators; no real authenticator hardware is involved.
