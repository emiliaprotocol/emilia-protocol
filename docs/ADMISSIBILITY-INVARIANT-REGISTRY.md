<!-- SPDX-License-Identifier: Apache-2.0 -->
# Admissibility Invariant Registry

A single place where every claim EMILIA makes about a piece of evidence is bound
to the code, the negative test, the cross-language parity, and the acceptance
rule that make the claim true. If a claim is not in this registry with all five
backings present and checkable, EMILIA does not make it.

## The doctrine

Three lines, in order. Each is a gate the one before it does not satisfy.

1. **Signed is not trusted.** A valid signature proves a key produced the bytes.
   It does not prove the key belongs to whom the reader assumes, or that the
   signer was a present human, or that the signer was entitled to sign.
2. **Verified is not accepted.** Verification is unconditional and runs on
   general infrastructure: the math checks out. Acceptance is conditional on a
   pinned authority the relying party supplied out of band.
3. **Accepted requires pinned policy.** A relying party accepts evidence for
   reliance only against roots it pinned itself: the issuer key, the approver
   directory, the org quorum template, the TSA key, the admissibility profile
   hash. EMILIA never authors the bar and is never in the trust path.

A verifier that collapses any two of these into one boolean is a defect. The
registry exists so that collapse cannot happen silently: each claim states, as
data, exactly where its verified/accepted line sits and what must be pinned to
cross it.

## The five invariants

Every registered claim carries all five. A missing or unresolvable field is a
build failure, not a warning.

| Invariant | What it fixes | Field |
|---|---|---|
| **Pinned authority** | Names the exact root the relying party must pin out of band before acceptance. No pin, no acceptance. | `pinned_authority` |
| **Verifier behavior** | Points at the real function that computes the check, as `file` + `symbol`. The checker confirms both exist. | `verifier_behavior` |
| **Negative vector** | Names the conformance case that proves the verifier REFUSES the abuse, not just accepts the happy path. | `negative_vector` |
| **All-language parity** | Lists the verifier languages that agree on this claim (`js`, `py`, `go`). Fewer than all three requires a stated `parity_exception`. | `parity` |
| **Acceptance semantics** | States, in one sentence, what VERIFIED yields and what additionally makes it ACCEPTED. This is where the doctrine is made concrete per claim. | `acceptance_semantics` |

## Why negative vectors, specifically

A conformance suite that only shows the verifier accepting valid evidence proves
nothing about admissibility. The property that matters for reliance is refusal:
that a downgraded Class-A signoff, a self-approved quorum, a stale revocation, or
an unpinned timestamp is REJECTED, in every language, and stays rejected. The
`negative_vector` field is therefore mandatory and must name a case whose
expected result is refusal. A claim with no negative vector is a claim with no
evidence that its guarantee holds under attack.

## How a claim enters the registry

1. Write the verifier behavior and its negative conformance vector first.
2. Achieve cross-language parity (or record a `parity_exception` with a reason).
3. Add the entry to `admissibility/registry.json` with all five fields.
4. `node scripts/check-admissibility-registry.mjs` must pass: it resolves every
   `verifier_behavior.file`+`symbol` against the tree, every `negative_vector`
   against `conformance/vectors/`, and refuses any entry missing a field or a
   `parity_exception` where parity is partial.
5. Only claims that pass the checker may appear in public material. Run the
   checker in CI (`npm run check:admissibility`) so a public claim can never
   drift ahead of its evidence.

This is the mechanized form of the project rule that every external statement
about verifier behavior traces to code that was read, not remembered.

---

*Registry data: [`admissibility/registry.json`](../admissibility/registry.json).
Checker: [`scripts/check-admissibility-registry.mjs`](../scripts/check-admissibility-registry.mjs).*
