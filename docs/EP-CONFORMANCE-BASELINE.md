<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-CONFORMANCE-BASELINE — a shared conformance & negative-vector baseline for agent-authorization receipts

**Status:** Proposal (community-facing). Offers EP's existing, public,
cross-language conformance suite as a candidate baseline the whole
agent-authorization receipt cluster can adopt, so "verifiable" is testable rather
than asserted.

## The problem it addresses

The receipt cluster (delegation, policy-permit, decision/compliance, route
authorization, human authorization) has converged on shared primitives —
JCS [RFC8785] canonicalization, an action digest, detached signatures,
fail-closed denial — but there is **no shared way to test that two
implementations actually agree**, and most efforts ship no public negative
vectors at all. "Independently verifiable" is the central claim of every one of
these drafts, yet it is rarely independently verified. A common conformance
baseline turns the shared claim into a shared, checkable artifact.

## What EP already has (and offers as the seed)

EP maintains a public, executable conformance suite spanning **21 suites and
329 vectors**. JavaScript, Python, and Go reference verifiers maintained by the
same project must agree on every result; this is cross-language consistency
evidence, not three independent implementations. Separately, CI rebuilds an
externally authored Rust verifier from an immutable public commit and tree. It
passes the pinned 16-suite/164-vector clean-room bundle and a pinned 359-case hostility campaign. The checked-in
construction statement is implementer-signed and predates the current source
pin, so the aggregate case records strict independently attested clean-room
acceptance as zero. That precise, executable baseline is a natural seed for a
shared cluster-wide suite.

## The proposed baseline

A minimal, format-agnostic set of **positive and negative vectors** every
authorization-receipt format SHOULD pass, organized by the primitives the cluster
already shares:

1. **Canonicalization determinism** — given an object in the I-JSON profile
   (strings/booleans/null/safe-integers), every implementation MUST produce
   byte-identical canonical output and digest. Negative vectors: out-of-profile
   non-integer reals (MUST be rejected, not silently re-serialized), key-order
   permutations (MUST normalize), non-ASCII strings (MUST agree).
2. **Action binding** — a receipt whose action is altered after signing MUST
   fail. Negative vectors: one-byte mutation of any action field; digest/object
   mismatch.
3. **Signature validity** — wrong key, truncated signature, algorithm
   substitution MUST all fail closed.
4. **Anti-replay / freshness** — replayed nonce, expired window, stale status
   MUST fail per the format's rules.
5. **Composition (where applicable)** — heterogeneous receipts that bind
   DIFFERENT actions MUST NOT compose into one ALLOW (the cross-binding vector
   from [draft-schrock-ep-authorization-evidence-chain]).
6. **Fail-closed default** — missing, malformed, unknown, or unverifiable
   evidence MUST yield DENY, never a default-allow.

Each vector is a JSON document with `{input, expect}` and a one-line rationale,
so any implementation in any language can run it.

## How to adopt

EP offers its suite layout, its negative vectors, and its cross-language runner
as a starting contribution — not as "EP's tests win," but as a neutral baseline
the cluster co-owns and extends. Other efforts contribute the vectors specific to
their primitive (a delegation-chain depth vector, a policy-epoch rollback vector,
etc.). The goal is one place where "did these two implementations agree?" has a
yes/no answer.

## Why EP proposes it

EP already pays the cost of cross-language agreement and public negative vectors;
offering them as the baseline both raises the floor for everyone and positions
EP as the conformance reference for the cluster — the same convergence posture as
[draft-schrock-ep-authorization-evidence-chain]. Owning the test bar is quieter
than owning a format, and harder to displace.

Reference suite: `conformance/` in
https://github.com/emiliaprotocol/emilia-protocol
