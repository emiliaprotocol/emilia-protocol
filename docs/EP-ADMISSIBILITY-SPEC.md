<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-ADMISSIBILITY — is this evidence *enough* to rely on?

> Receipts prove facts. Admissibility decides **which facts are enough** to
> trust, settle, reverse, insure, or prosecute an action — for **this** reliance
> purpose. It is the classified verdict over a heterogeneous evidence bundle.

Identity (WIMSE/SPIFFE), delegation (OAuth/GNAP), call context (transaction
tokens), attestation (RATS/EAT), a policy permit (CAN), a named-human/quorum
authorization (EMILIA — WHO), an execution attestation, a SCITT inclusion
receipt, a recourse reference — each proves its own fact. **None of them define
the cross-artifact rule: "this packet is sufficient evidence for this reliance
purpose."** That rule is the hole. This is EMILIA's answer to it.

The verifier runs a deterministic evidence policy and returns a narrow answer:

```
admissible | missing_evidence | stale | conflicted | unverifiable
```

- Spec surface: [`lib/evidence/admissibility.js`](../lib/evidence/admissibility.js) (`evaluateAdmissibility`)
- Runnable vector: [`examples/admissibility/admissibility-vector.mjs`](../examples/admissibility/admissibility-vector.mjs) (`node examples/admissibility/admissibility-vector.mjs --emit`) · CI: `tests/admissibility.test.js`
- Sharpens **EP-AEC** ([`draft-schrock-ep-authorization-evidence-chain`](../standards/)) — see "Relationship to EP-AEC" below.

## Why this is a distinct primitive, not another receipt

SCITT gives the transparent-log substrate (RFC 9943) but is deliberately
content-agnostic: it never says whether a statement is *sufficient*. The
SCITT-adjacent AI drafts (pre-execution permits, agent action records, agent
action receipts) each disclaim the strong claim — correctness, legality,
completeness, policy replay. WIMSE, OAuth/GNAP, transaction tokens, and RATS/EAT
each carry one fact and stop. **The sufficiency decision across all of them is
unowned.** EMILIA already produces the load-bearing WHO leg and already composes
legs by digest in EP-AEC; admissibility is the classified, purpose-parameterized,
replayable *decision* over that composition.

## The three things it adds over a binary allow/deny

1. **A classified verdict.** Not `allow`/`deny` but *why*: a relying party that
   gets `missing_evidence` goes and fetches a leg; `stale` refreshes one;
   `conflicted` stops and investigates; `unverifiable` fails closed; only
   `admissible` proceeds. The verdict is actionable, not a boolean.

2. **The policy is supplied by the RELYING PARTY — never read from the bundle.**
   Sufficiency is not a property a presenter may assert about its own evidence.
   If the party presenting the bundle also chose the bar, it would always choose
   a bar it clears — the same trust-boundary failure as reading a quorum policy
   out of the document it authorizes. `evaluateAdmissibility(bundle, policy)`
   takes the policy as a separate argument from the party doing the relying; a
   bundle with no relying-party policy is `unverifiable`, full stop.

3. **Deterministic replay.** `replay_digest = SHA-256(JCS(policy, normalized
   component facts, as_of))`. Same inputs → same verdict → same digest. An
   auditor, insurer, or court can reproduce the sufficiency decision months
   later from the recorded policy and facts. This is *policy replay for agent
   actions* — the primitive the AI-agent-receipt drafts make a non-goal.

## The evidence policy (relying-party object)

| field | meaning |
|---|---|
| `policy_id` | stable id of this sufficiency policy, for replay + citation |
| `reliance_purpose` | `money_movement` / `audit` / `insurance_claim` / `reversal` / … — sufficiency is **relative to this** |
| `requirement` | boolean expression over required component **types**, e.g. `authorization_receipt AND policy_permit AND recourse_reference` |
| `freshness_sec` | optional max age per component type; an older leg is `stale`, not accepted |
| `revocation_required` | component types whose live `revoked` state must be false |
| `require_action_agreement` | all present legs must bind the same action (default true) |

The same bundle is `admissible` under a light `audit` policy and
`missing_evidence` under a strict `money_movement` policy — **the bundle did not
change; the reliance purpose did.** That is the whole point.

## Verdict semantics (precedence: unverifiable > conflicted > stale > missing > admissible)

| verdict | when |
|---|---|
| `unverifiable` | a present required leg fails its own type verifier, or **no relying-party policy was supplied** |
| `conflicted` | verified legs contradict — they bind different actions, or one is a **denial/refusal** (the bundle contains a "no", not an authorization) |
| `stale` | the requirement is met by present evidence, but a required leg is older than `freshness_sec` or is `revoked` — the evidence *exists* but is not live |
| `missing_evidence` | nothing present is broken, but the requirement is not satisfied — a required type is absent |
| `admissible` | requirement satisfied by verified, fresh, non-revoked, action-agreeing legs |

Per-type cryptographic verification is **delegated** to the real type verifiers
(EP-RECEIPT verify, the recourse verifier, permit/attestation verifiers). This
module is the pure policy layer over their results — the novel part is the
classified, purpose-parameterized, replayable decision, not re-doing crypto.

## Relationship to EP-AEC

EP-AEC (`verifyAuthorizationChain`) already binds heterogeneous legs to one
action digest and evaluates a boolean requirement — it *is* the composition seam.
Admissibility sharpens it in exactly three ways, and one was a security fix that
has now ALSO been applied to AEC itself: an AEC document's `requirement` is
**presenter-supplied** — a claim of what the bundle satisfies, never the relying
party's bar — so the verifier accepts a relying-party-pinned requirement
(`opts.requirement` in JS, `requirement=` in Python, trailing argument in Go)
that takes precedence, with `requirement_source` recorded; conformance vectors in
`conformance/vectors/aec.json` pin this in all three languages. Admissibility
goes further: it takes the whole sufficiency policy as a relying-party argument
and refuses to proceed without one. AEC returns binary `allow`; admissibility
returns the five-state verdict. AEC has no freshness/replay; admissibility adds
both.

The two compose directly: **`evaluateChainAdmissibility(aec, policy, opts)`**
runs the AEC composition verifier with the relying party's requirement pinned,
then classifies the result — AEC remains the wire object that carries the legs;
admissibility is the decision a relying party runs over them.

## Honest boundary

Admissibility decides whether the evidence is **sufficient for a stated reliance
purpose under a stated policy**. It does not decide **correctness** (that the
action was a good idea), **legality**, or **real-world outcome** — only that the
evidence a relying party said it needs is present, verified, fresh, consistent,
and action-bound. It is advisory decision support, not an adjudication and not a
control: the relying party still owns the policy, the purpose, and the
consequences of proceeding. Its contribution is that the sufficiency question now
has one deterministic, replayable, relying-party-governed answer instead of a
per-vendor guess — which is precisely what an auditor, insurer, regulator,
merchant, bank, or court needs before it lets an agent action stand.

## Composition

Admissibility is the verdict *over* the SCITT four-leg picture plus the optional
recourse leg: *permit (CAN) → EMILIA (WHO) → Capsule (WHAT) → GAR (audit) →
recourse (WHO'S ON THE HOOK)* — evaluated against a relying-party evidence policy
for a named reliance purpose. It composes by digest, embeds nothing, and adds no
new cryptography.
