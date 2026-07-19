# Delegation Integrity — refusing authority laundering and chain poisoning

A signed EMILIA delegation is a promise with one direction: **a child may only narrow
what its parent conferred, never broaden it.** Authority starts at a human root signoff
and can only shrink on the way down — in scope, in value cap, in lifetime. This demo
proves the verifier holds that line, offline, against two classic attacks on delegation
chains.

Every vector carries a **real** Class-A (human, WebAuthn-shaped) or Class-B (software)
receipt and a **real** Ed25519 delegation proof signed over the link's canonical bytes.
The negatives are genuine forgery attempts, not JSON that would have failed for some
unrelated reason.

## Run it

```
node examples/delegation-integrity/demo.mjs
```

Prints a green `ACCEPT` for each valid chain and a red `REFUSE` — with the verifier's
own reason string — for each attack. Exit code is non-zero if any attack is not refused.

Fully offline. No dependencies beyond `node:fs` and the repo verifier
(`packages/verify/provenance.js`).

## What it demonstrates

### Positive controls (ACCEPT)
A signed, human-rooted chain that narrows `payment.*` down to `payment.release`
verifies — including a legitimate wildcard child that stays inside its parent's
wildcard, and a two-hop chain where each hop is contained by the one above it.

### 1. Authority laundering (REFUSE)
A child delegation claims authority its ancestor chain never granted — broadening,
not narrowing:

- **scope broadening** — child names a scope (`treasury.wire`) outside the root's grant;
- **wildcard widening** — root confers only the concrete `payment.release`, and the
  child uses `payment.*` to widen beyond it;
- **value-cap broadening** — a lower hop raises the dollar cap above the cap it was
  handed.

Each fails the `scope_containment` check. A child scope must be contained by **every**
ancestor; a wildcard is a narrowing device, never a broadening one.

### 2. Delegation chain poisoning (REFUSE)
A link is tampered, mis-keyed, or spliced into the chain:

- **unsigned link** — a link with no proof (`delegations_signed`, fail-closed);
- **tampered fields** — a validly-signed link whose scope/cap were widened after
  signing, so the proof no longer covers the visible bytes (`delegations_signed`);
- **wrong key** — a proof self-consistent under a key that is not the one pinned to the
  delegator (`proof_key_bound`);
- **spliced / reordered** — an inserted hop whose `delegator`/`parent_ref` do not bind
  to the prior hop's `delegatee` (`chain_links_bound`);
- **unanchored head** — a chain head that names no approver on the root signoff
  (`chain_anchored`).

Each trips a distinct integrity check with its own reason. Because the chain is ordered
by `sequence` and each hop must bind to the previous `delegatee` by identity, a genuine
reorder breaks the same binding a splice does.

### Root authority (REFUSE)
Authority cannot come from nothing:

- a root receipt signed only by a Class-B (software) key carries no human signoff
  (`root_human_signoff`);
- a stripped root signoff leaves nothing to derive authority from
  (`root_receipt_valid`).

## Provenance of the vectors

The vectors live in
[`conformance/vectors/delegation-integrity.v1.json`](../../conformance/vectors/delegation-integrity.v1.json)
(`EP-DELEGATION-INTEGRITY-v1`) and are exercised by
[`tests/delegation-integrity.test.js`](../../tests/delegation-integrity.test.js), which
asserts each verdict, the specific check that must fail, the human-readable reason, and
that re-running yields byte-identical results (determinism).

```
npx vitest run tests/delegation-integrity.test.js
```
