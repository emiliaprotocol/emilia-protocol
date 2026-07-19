<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-ADMISSIBILITY-PROFILE: naming the bar

> [`EP-ADMISSIBILITY`](EP-ADMISSIBILITY-SPEC.md) answers "is this evidence bundle
> *enough* to rely on, for this reliance purpose?" and takes the sufficiency
> policy as a relying-party argument. This spec adds the missing ergonomics: a
> **named**, content-addressed bar a relying party can cite by id and pin by
> hash, instead of hand-assembling freshness and requirement knobs at every call
> site. The verdict machinery does not change. Only how the policy is named,
> shared, and pinned does.

- Schema: [`public/schemas/ep-admissibility-profile.schema.json`](../public/schemas/ep-admissibility-profile.schema.json)
- Reference examples: [`public/.well-known/ep-admissibility-profiles.json`](../public/.well-known/ep-admissibility-profiles.json)
- Evaluator (closed precedence, requirement grammar): [`lib/evidence/admissibility.js`](../lib/evidence/admissibility.js)
- Object shape: [`lib/evidence/admissibility-profiles.js`](../lib/evidence/admissibility-profiles.js)
- Adoptable starting points as flat policies: [`lib/evidence/policy-packs.js`](../lib/evidence/policy-packs.js)

## Motivation

Buyers do not want knobs. A head of engineering does not want to write
"freshness 300 seconds on the authorization leg, 600 on the permit, revocation
checked on the receipt, `high` assurance minimum, this boolean requirement
expression" at every gate. They want to write one line in a policy: **"for
agentic payments above $X, require `ep:admissibility:money-movement:v1`."**

A named admissibility profile is that one line. It packages a reliance purpose,
the required evidence legs with their assurance and freshness bounds, the live
checks each leg must pass, and the requirement expression into a single object
with a stable id and a content hash. The relying party cites the id in its rule
and pins the hash as its trust anchor. Two systems that pin the same hash are
provably evaluating the same bar. That is the interoperability this layer buys:
a named, comparable, auditable bar instead of a per-call-site pile of knobs, and
a per-vendor guess about what "enough" meant.

This is the same move the [`policy-packs`](../lib/evidence/policy-packs.js)
already make for flat policies (pick the pack for your action class, pin issuer
keys, done). A profile is the content-addressed, citable form of that idea: the
pack is a starting point you copy, the profile is a bar you can name and pin.

## The object

A profile is a small JSON object. Field names and types mirror
[`lib/evidence/admissibility-profiles.js`](../lib/evidence/admissibility-profiles.js)
(`defineAdmissibilityProfile`); the schema enumerates and constrains them. The
**hashed** object is exactly `{ id, version, authored_by, requires, verdicts }`;
human-facing annotations (`reliance_purpose`, `description`, `action_family`)
are carried alongside the profile, never inside it, so they cannot perturb the
hash.

| field | meaning |
|---|---|
| `id` | stable name a relying party cites, e.g. `ep:admissibility:money-movement:v1`. A name, not an authority claim. |
| `version` | profile content version, an integer (defaults to 1); bump when the bar changes so the cited version and the pinned hash move together |
| `authored_by` | WHO authored the bar. Advisory provenance only; acceptance is by pinned hash, never by this field. Required, and never EMILIA for a relying party's own bar |
| `requires[]` | the evidence requirements (below). Non-optional entries gate; `optional:true` entries strengthen but do not gate |
| `verdicts[]` | the closed verdict set this profile is evaluated under, stamped from `ADMISSIBILITY_VERDICTS`; the precedence is fixed by the evaluator, not the profile |
| `profile_hash` | `sha256:` over the canonical bytes of the profile with this field excluded. The pinned trust anchor |

The relying-party **requirement expression** is not a stored field: the profile
evaluator derives it as the conjunction of every non-optional `requires[].evidence`
type and hands that to `lib/evidence/admissibility.js`. Optional legs never enter
the expression (their absence must not downgrade), but a present-but-invalid
optional leg still enters the fact set and is caught by the unverifiable /
conflicted precedence.

Each entry in `requires[]` is a requirement:

| requirement field | meaning |
|---|---|
| `evidence` | the component type token, e.g. `authorization_receipt`, `policy_permit`, `workload_identity`, `witness_quorum`, `delegation`, `transparency`, `recourse_reference`. Not a closed enum: a relying party may define its own types |
| `min_assurance` | minimum assurance class, ordered `self_asserted` < `basic` < `verified` < `high` < `very_high`. A leg below the floor, or naming an unknown class, does not count (fail closed) |
| `max_staleness_sec` | maximum accepted age; an older-but-valid leg is `stale`, never accepted |
| `checks[]` | live/state checks the leg must pass. `revocation_checked` is special (live revoked state must be false AND known); any other named check is looked up in the leg's own `checks` map and must be true. An unrecognized or absent check fails closed |
| `optional` | when true, the leg is credited and evaluated when present but its absence alone is not `missing_evidence` |
| `params` | requirement-specific parameters hashed into the profile but not interpreted by the profile layer, e.g. `{ "k": 2 }` for a `witness_quorum` threshold |

### profile_hash construction

The `profile_hash` is computed exactly the way EP hashes everything else. Take
the profile object, remove the `profile_hash` field, canonicalize the remainder
with RFC-8785 / JCS canonicalization (the shared
[`canonicalize`](../lib/canonical-json.js) helper: object keys sorted at every
depth, arrays in order, an I-JSON subset with no floats), SHA-256 the canonical
bytes, and prefix `sha256:`.

```
profile_hash = "sha256:" || hex( SHA-256( JCS( profile \ {profile_hash} ) ) )
```

Only `{ id, version, authored_by, requires, verdicts }` is part of the hashed
object. Same helper, same algorithm, same digest prefix as receipts, capsules,
and the evidence graph. `computeProfileHash` and `defineAdmissibilityProfile` in
[`lib/evidence/admissibility-profiles.js`](../lib/evidence/admissibility-profiles.js)
compute it; the reference examples in the `.well-known` file carry hashes
produced by that exact helper, so a fork that recomputes with the same helper
after editing gets a matching hash. The relying party pins the resulting value
out of band. The name is convenience; the pinned hash is the commitment.

## The evaluator contract and the closed verdicts

A profile does not evaluate anything. `evaluateAdmissibilityProfile` in
[`lib/evidence/admissibility-profiles.js`](../lib/evidence/admissibility-profiles.js)
resolves each requirement into a fact, derives the relying-party requirement
(the conjunction of the mandatory `requires[].evidence` types), maps each
`max_staleness_sec` into a freshness bound and each `revocation_checked` into the
revocation-required set, and delegates the classified verdict to the existing
evaluator in [`lib/evidence/admissibility.js`](../lib/evidence/admissibility.js).
The profile layer only decides which facts to hand down; it does not reimplement
the precedence. The evaluator then returns one verdict from the closed set, under
fixed precedence:

```
unverifiable > conflicted > stale > missing_evidence > admissible
```

- `unverifiable`: a present required leg fails its own type verifier, or no
  relying-party policy (here, no pinned profile) was supplied.
- `conflicted`: verified legs contradict, binding different actions, or a leg is
  a denial or refusal (a "no", not an authorization).
- `stale`: the requirement is met by present evidence, but a required leg is
  older than its `max_staleness_sec` or is revoked. The evidence exists but is
  not live.
- `missing_evidence`: nothing present is broken, but a required leg is absent.
- `admissible`: the requirement is satisfied by verified, fresh, non-revoked,
  action-agreeing legs.

Per-leg cryptographic verification is delegated to the real type verifiers. The
profile layer adds no cryptography; it names the bar the evaluator already
knows how to apply.

### Fail closed, always

A default is the weakest outcome, never `admissible`. Concretely:

- A recomputed profile hash that does not equal the pinned `profile_hash` yields
  a non-admissible verdict or a refusal. A relying party that pinned one bar and
  was handed a different one has not agreed to the substituted bar.
- An unrecognized profile id, an unrecognized `checks[]` entry, or a malformed
  `requirement` expression fails closed.
- Missing, invalid, or unverifiable evidence yields `unverifiable`,
  `missing_evidence`, or `stale`, never `admissible`.
- No pinned profile at all is `unverifiable`: sufficiency is never read from the
  presented bundle. A presenter must not choose its own bar.

## Deterministic replay_digest: the standard-of-care property

The evaluator returns a `replay_digest`:

```
replay_digest = "sha256:" || hex( SHA-256( JCS( policy, normalized component facts, as_of ) ) )
```

Same inputs, same verdict, same digest. When the policy is a named profile, the
pinned `profile_hash` is part of that policy, so the replay digest binds the
verdict to the exact named bar that produced it. This is the auditor-,
insurer-, and court-reproducibility property: months later, from the recorded
profile (identified and integrity-checked by its hash) and the recorded
component facts, the same verdict is recomputed byte for byte, offline. That
reproducibility is the standard-of-care evidence: not "a vendor said it was
fine" but "here is the named bar that was in force, here is the evidence that
cleared it, and anyone can rerun the decision and get the same answer." Policy
replay for agent actions is precisely the property the adjacent agent-receipt
drafts make a non-goal.

## Neutrality: EMILIA is not the authority on the bar

This is the load-bearing commitment, and it holds here exactly as it does across
EP (see [`NEUTRALITY-COVENANT.md`](NEUTRALITY-COVENANT.md)).

- The **relying party authors** its admissibility profile and **pins** its own
  `profile_hash`. The bar belongs to whoever bears the risk of relying.
- The verdict is computed **offline and deterministically** against the pinned
  profile. No EMILIA server is in the trust path, and none adjudicates.
- EMILIA publishes exactly two things: the interoperable **schema**, and
  clearly-labeled **reference / example profiles** a relying party may fork.
  Both are published on identical terms to everyone, including competitors, the
  same way the conformance vectors are. This is a public good, not a registry
  EMILIA controls.
- The `.well-known` file says so in band, prominently, at the top: it is
  reference examples, not an authoritative registry; relying parties author and
  pin their own; EMILIA does not adjudicate and is not in the trust path.

If any wording ever makes EMILIA the definer of the bar, that is a defect to
fix, not a feature. The reference profiles exist to save a relying party an
afternoon, not to centralize the decision. Fork one, rename it into your own
namespace, tune the bounds to your risk appetite, recompute and pin your hash.
Acceptance is by your pinned hash, never by EMILIA's name or by that file.

## Relationship to the challenge loop and reliance packets

A named profile is the shared vocabulary that makes the surrounding loop legible.

- **Challenge loop** ([`lib/negotiate/evidence-challenge.js`](../lib/negotiate/evidence-challenge.js)).
  When a presentation does not clear the bar, the relying party returns a
  machine-readable challenge (the evidence-negotiation generalization of RFC 9470
  OAuth step-up, the natural HTTP-428 "precondition required" shape) that names
  exactly the missing or stale legs. With a named profile, that challenge can
  cite the profile id and hash: "you presented against
  `ep:admissibility:money-movement:v1` and are missing a fresh `policy_permit`."
  The agent knows what to go get because the bar has a name and the verdict named
  the gap. The challenge remains single-use and expiring, the server keeps
  computing the action digest, and satisfying a challenge yields a verdict, never
  a promise to execute.
- **Reliance packets** ([`packages/gate/reliance-packet.js`](../packages/gate/reliance-packet.js)).
  The auditor- and insurer-facing packet a Gate decision emits can record which
  named profile was in force by id and hash, alongside the verdict and its
  `replay_digest`. The reader then has the whole chain: the named bar, the
  evidence that cleared it, and a reproducible decision, with the packet's own
  honest limitations intact (it proves the gate enforced its configured policy,
  not that the human decided wisely).

## Honest limits

An `admissible` verdict means one thing and only one thing: **this evidence
bundle clears the bar this relying party pinned.** It does not mean the action
is correct, safe, wise, legal, or currently valid beyond the freshness bounds
that were evaluated. Offline verification never establishes current validity; it
establishes that, as of the recorded `as_of`, the pinned bar was cleared. Live
state (revocation, later invalidation) is a server-state question the evaluated
freshness and revocation checks bound but do not eliminate. The relying party
still owns the profile, the purpose, and the consequences of proceeding. This
layer's contribution is narrow and real: the sufficiency question now has one
named, deterministic, replayable, relying-party-governed answer instead of a
per-vendor guess.

## Standardization note

This profile object and its `profile_hash` are a candidate to fold into the
AEG / recourse Internet-Draft as an "Admissibility Profile" section in a future
revision, giving the wire a named, content-addressed way to reference a
relying-party bar. It is not filed as such today. Until it is, this spec, the
schema, and the reference examples are the definition, and the neutrality stance
above is a precondition of any such folding: the draft would standardize the
schema and the hashing, never an authoritative EMILIA registry of bars.
