# Tamarin model: EP core receipt lemma (`ep_receipt_core.spthy`)

This is the first EP model in which "the signature verifies" is a derived fact,
not an axiom. The existing TLA+ model (`formal/ep_handshake.tla`) and Alloy
models (`formal/ep_relations.als`, `formal/ep_federation.als`) verify state
machine and relational invariants while treating signature validity as an
assumption. Here, signatures are terms in Tamarin's standard `signing`
equational theory (`verify(sign(m, k), m, pk(k)) = true`), and the adversary
is the standard Dolev-Yao network attacker: full control of the network, sees
every message, can apply all function symbols, and can additionally request
the honest human to sign arbitrary actions of the attacker's choice.

## What is modeled

Maps to `standards/posted/draft-schrock-ep-authorization-receipts-04.txt`:

- A human approver with a device-bound signing key (Section 5.1, Class A).
  The public key is published, so the attacker always knows it.
- A user-verification (UV) event that MUST precede every human signature.
  UV gating is modeled structurally: the signing rule can only consume a
  linear `UVDone` fact that only the UV rule produces, so no trace contains
  a human signature without a prior UV event over exactly that action and
  nonce.
- The signed message is the Authorization Context abstracted as
  `<'ep_signoff_v2', h(action), policy, initiator, audience, nonce,
  validity, approver-slot>`. The theorem events carry the same fields, so the
  statement and the signed term cannot drift apart.
- The relying party pins the human's public key out of band (abstracting the
  Approver Directory) and accepts a receipt only if the signature verifies
  under the pinned key over the exact action term received.
- Key compromise is a modeled event (`RevealLtk`), so each lemma states
  explicitly that its guarantee is conditional on the device key not having
  leaked.
- One-time consumption (Section 6, guarantee G3) is modeled as two accept
  rules. `Request_Signoff` creates one linear `AdmissionAvailable` fact for
  the fresh context; the checked accept rule consumes it and no rule recreates
  it. The comparison rule omits that input. There is no uniqueness restriction
  that assumes the result to be proved.

## Machine-checked result

Verbatim `summary of summaries` from the extended run on 2026-08-15
(tamarin-prover 1.10.0, Maude 3.4, all wellformedness checks successful):

```
summary of summaries:

analyzed: ep_receipt_core.spthy

  executable_honest_receipt (exists-trace): verified (9 steps)
  core_authenticity_uv_gated (all-traces): verified (11 steps)
  acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)
  no_replay_across_actions (all-traces): verified (11 steps)
  injective_acceptance_with_consumption (all-traces): verified (11 steps)
  unchecked_acceptance_is_injective (all-traces): falsified - found trace (11 steps)
```

What each result means:

| Lemma | Result | Meaning |
|---|---|---|
| `executable_honest_receipt` | verified | Sanity trace exists: an honest UV-gated receipt is accepted with no key compromise. The model is not vacuous. |
| `core_authenticity_uv_gated` | verified | If a relying party accepts a receipt under an uncompromised key, a prior UV event and signature exist over the exact action, policy, initiator, audience, nonce, validity token, and approver slot. |
| `acceptance_prefix_integrity_after_later_reveal` | verified | If acceptance occurs without any prior reveal and the key is revealed later, prior UV and signing events over the exact accepted context remain in the acceptance prefix. This is not an offline anti-backdating claim. |
| `no_replay_across_actions` | verified | Honest signatures harvested over other contexts cannot be transplanted onto a different accepted context. |
| `injective_acceptance_with_consumption` | verified | Each checked acceptance has a preceding honest signature and no second checked acceptance of the same complete context exists; this follows from consuming the linear `AdmissionAvailable` fact. |
| `unchecked_acceptance_is_injective` | falsified | Expected and kept deliberately, see below. |

## The falsified lemma is a demonstrated replay, not a hidden defect

`unchecked_acceptance_is_injective` asserts that even WITHOUT a consumption
check, the same complete signed context is never accepted twice. Tamarin falsified it and
produced the counterexample trace: the attacker takes the one honest receipt
broadcast by `Human_Sign_Receipt` and delivers it to an accept point twice
(in the found trace, once through the consumption-checked rule and once
through the unchecked rule). No forgery and no key reveal occur in the trace.

Why the counterexample is necessarily a same-receipt replay and not
something worse: the verified `core_authenticity_uv_gated` lemma forces every
acceptance to be backed by a Signed event over the complete context, and the model
admits at most one Signed event per nonce (the nonce is `Fr`-fresh, so only
one sign request carries it, and the linear `UVDone` fact allows exactly one
signature per request). So any double acceptance is the single honest receipt
accepted twice. (This uniqueness argument is structural, from `Fr` freshness
and fact linearity in the model semantics; it is not itself a separate
machine-checked lemma.)

This is precisely the failure mode the spec's one-time consumption record
(Section 6, G3) exists to prevent. The checked rule restores injectivity by
consuming protocol state, not by excluding replay traces with a restriction
(`injective_acceptance_with_consumption`, verified).

The later-reveal lemma is intentionally limited to trace-prefix integrity. The
model orders a real acceptance before a later key reveal and proves that the
matching UV-gated signature occurred before that acceptance. It does not let an
offline verifier distinguish a genuinely pre-reveal receipt from one minted and
backdated after compromise. That stronger property requires an independently
ordered witness, an append-only checkpoint, or forward-secure signatures.

## Out of scope (honest boundary)

This model checks the core receipt lemma only. It does NOT model, and
therefore proves nothing about:

- The Approver Directory, Merkle receipt log, checkpoints, or inclusion
  proofs. Key pinning is a single out-of-band step; the directory protocol
  and its trust root are the next model's job.
- WebAuthn attestation internals, authenticator hardware, or clientDataJSON
  parsing. UV is an atomic gating event: the model ASSUMES the authenticator
  enforces user verification before releasing a signature (the spec's MUST
  for Class A credentials). It does not prove WebAuthn itself.
- Policy evaluation, m-of-n quorum, separation of duties, or expiry and
  wall-clock time. These are covered at the state-machine level by the
  TLA+/Alloy models in `formal/`, not here.
- JCS canonicalization. The symbolic model assumes message encoding is
  injective, which is the standard symbolic assumption. Canonicalization
  robustness is exercised by the EP-CANONICALIZATION-v1 vector suite.
- Algorithm-specific or computational properties. `sign` is the abstract
  Dolev-Yao signature with perfect cryptography. No claim is made about
  ES256, Ed25519, or ML-DSA as algorithms, and no computational reduction
  exists here.

Symbolic verification also does not prove current validity of any real
receipt; it proves properties of the protocol design under the stated
abstraction.

## How to re-run

There was no official Tamarin image at `tamarin-prover/tamarin-prover` or
`tamarinprover/tamarin-prover` on Docker Hub as of 2026-07-05 (both pulls
fail with "repository does not exist"). The run above used a third-party
image that packages the stock tamarin-prover 1.10.0 binary with Maude 3.4:

```
docker run --rm \
  -v /path/to/emilia-protocol/formal/tamarin:/work -w /work \
  lmandrelli/tamarin-prover-and-batch:latest \
  tamarin-prover --prove ep_receipt_core.spthy
```

The proof completes in under a second. Any result differing from the summary
quoted above should be treated as a regression and investigated before
claiming verification. Alternatively, install Tamarin 1.10.0 natively per
https://tamarin-prover.com/manual/master/book/002_installation.html and run
`tamarin-prover --prove ep_receipt_core.spthy` from this directory.

---

# Tamarin model: EP quorum lemma (`ep_quorum_core.spthy`)

This is the second EP symbolic model. It layers m-of-n quorum, in the smallest
non-trivial instance (2-of-2), on top of the same UV-gated signature machinery
proven in `ep_receipt_core.spthy`. It does NOT re-prove the single-signature
core lemma; it assumes the per-signature guarantees already machine-checked in
`ep_receipt_core.spthy` and asks the next question: given two distinct enrolled
approver keys and a 2-of-2 policy, does a satisfied quorum necessarily consist
of two distinct UV-gated signatures over the same action and authorization
instance, and can the initiator of that action count toward its own quorum?

Signatures are again terms in Tamarin's standard `signing` equational theory,
and the adversary is the standard Dolev-Yao network attacker: full network
control, sees every message, may apply all function symbols, may request either
honest human to sign arbitrary actions of its choice, and additionally chooses
which action is put up for quorum and which identity is named as the initiator.

## What is modeled

Maps to `standards/posted/draft-schrock-ep-authorization-receipts-06.txt`:

- TWO distinct human approver identities, each with its own device-bound key
  (Section 5.1, Class A). Distinctness of enrolled identities is enforced
  structurally (restriction `TwoDistinctApprovers`), so one name cannot be
  enrolled twice.
- An INITIATOR identity that proposes the action (Section 2, Section 3: the
  initiator is identified but never trusted). The initiator is bound INTO the
  signed Authorization Context, `<'ep_signoff_v1', h(action), initiator,
  authorization_instance, nonce>` (Section 3), so an approver signature commits
  to a specific initiator and approval ceremony.
- A user-verification (UV) event that MUST precede every approver signature,
  gated structurally the same way as in the core model (a linear `UVDone` fact
  that only the UV rule produces and only the signing rule consumes).
- One request rule creates a fresh shared authorization instance and two
  per-approver fresh nonces. Each approver signs its own context carrying that
  same authorization instance and its own nonce. The shared signed value rules
  out cross-ceremony signoff splicing; the distinct nonce binds the individual
  context.
- Commitment (the executor's accept) fires only when TWO signatures that verify
  under TWO DISTINCT pinned approver keys over the SAME action, initiator, AND
  authorization instance are presented, and neither approver is the initiator (Section 6
  SelfApprovalImpossible, G4, Section 7 "k valid, distinct signoffs"). There is
  no accept rule that fires on a single signature: partial approval commits
  nothing.
- Key compromise is a modeled event (`RevealLtk`), so each quorum lemma states
  explicitly which guarantee is conditional on an approver key not having
  leaked.

## Machine-checked result

Verbatim `summary of summaries` from the repaired run on 2026-08-09
(tamarin-prover 1.10.0, Maude 3.4, all wellformedness checks successful):

```
summary of summaries:

analyzed: ep_quorum_core.spthy

  executable_quorum (exists-trace): verified (13 steps)
  quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)
  initiator_cannot_self_approve (all-traces): verified (4 steps)
  no_single_signer_fills_quorum (all-traces): verified (4 steps)
  commit_requires_signature_over_that_action (all-traces): verified (8 steps)
```

| Lemma | Result | Meaning |
|---|---|---|
| `executable_quorum` | verified | Sanity trace exists: a 2-of-2 quorum commits with two distinct honest approvers, both UV-gated, neither the initiator, no key compromise. The model is not vacuous, so the distinctness/self-approval restrictions do not make `Commit` unreachable. |
| `quorum_requires_two_distinct_uv_gated_signatures` | verified | Whenever the executor commits action a and authorization instance q citing approvers H1 and H2, and neither key was compromised, H1 and H2 are distinct and each performed UV then signed exactly (a, q) before commit. A single signature, one identity, a different action, or a different ceremony cannot fill the quorum. |
| `initiator_cannot_self_approve` | verified | No trace commits an action with the initiator itself appearing as either quorum approver (Section 6 SelfApprovalImpossible, G4). The initiator identity is attacker-chosen, so this also rules out an attacker naming a compliant approver as initiator to have it count against itself. |
| `no_single_signer_fills_quorum` | verified | The two committing approvers are never the same identity (distinct pinned keys entail distinct fresh keys entail distinct enrolled identities). This is the "no key fills two slots" property at the identity level. |
| `commit_requires_signature_over_that_action` | verified | No trace commits (a, q) while an uncompromised named approver never signed exactly (a, q). This rules out transplanting a signature from another action or authorization instance. |

## An earlier revision of this model was FALSIFIED, and why

Honest record, because it changed the model. In the first revision the signed
Authorization Context was `<'ep_signoff_v1', h(action), nonce>`, i.e. it did NOT
bind the initiator identity. Under that revision Tamarin FALSIFIED both
`quorum_requires_two_distinct_uv_gated_signatures` and
`commit_requires_signature_over_that_action`: two honest approvers signed action
a while requested under one initiator label, and the executor committed the same
a under a DIFFERENT initiator label, because nothing tied the approver signatures
to the committing initiator. The initiator label floated, so separation of duties
was only an executor-local check rather than a property of the signatures.

The fix is spec-faithful, not a lemma weakening: the initiator identity is now
bound inside the signed context (`<'ep_signoff_v1', h(action), initiator,
authorization_instance, nonce>`). The repaired model also binds one fresh
authorization instance into both quorum signoffs, matching the -11 wire rule.
With
the initiator bound into what each approver signs, all five lemmas verify. This
is the same kind of result the core model records for one-time consumption: the
falsification identified a load-bearing binding, and the model now shows that
binding is what carries the property.

## Out of scope (honest boundary)

This model checks quorum composition (Section 7 / G4) only, on top of the
core model's per-signature guarantees. It does NOT model, and therefore proves
nothing about:

- COLLUSION, one-human-many-identities, and COERCION. Section 11.7 is explicit:
  separation of duties defeats UNILATERAL self-approval and guarantees pairwise-
  distinct signing IDENTITIES; it does NOT defeat two distinct enrolled humans
  who choose to collude, one operator who controls two enrolled credentials (an
  enrollment control, not a receipt control), or a coerced approver. This model
  proves the distinct-identity / no-self-approval property and NOTHING about
  whether the two identities are two independent wills. The enrollment binding
  (one human to one identity) is the Approver Directory's job (Section 5.2),
  which is out of scope here exactly as in `ep_receipt_core.spthy`.
- The Approver Directory, Merkle receipt log, checkpoints, or inclusion proofs.
  Approver-key pinning is a single out-of-band step; the directory protocol and
  its trust root are a later model's job.
- WebAuthn attestation internals and authenticator hardware. UV is an atomic
  gating event: the model ASSUMES the authenticator enforces user verification
  before releasing a signature (the spec's MUST). It does not prove WebAuthn.
- General m-of-n for arbitrary m and n. This model fixes the 2-of-2 instance
  (two enrolled approver rules; an accept rule that consumes exactly two
  distinct-key signatures). It does not prove the parametric k-of-n statement.
  2-of-2 is the smallest case that exhibits distinctness and self-approval and
  is what terminates in under a second.
- Expiry / wall-clock (`expires_at`), policy-hash evaluation, and one-time
  consumption of the committed quorum. Consumption/replay is the subject of
  `ep_receipt_core.spthy` (guarantee G3); this model is about quorum
  composition (G4 / Section 7) and deliberately does not restate the
  consumption lemma.
- JCS canonicalization (assumed injective encoding) and any algorithm-specific
  or computational claim. `sign` is the abstract Dolev-Yao signature with
  perfect cryptography.

## Composition boundary

`ep_receipt_core.spthy` and `ep_quorum_core.spthy` remain useful focused models.
`ep_reliance_composed.spthy` v2 below re-derives the abstract 2-of-2 quorum and
consumption properties while composing CAID, authority, registry-view,
revocation, issuer pinning, and execution. It still does not model WebAuthn
internals, directory publication, Merkle-log mechanics, arbitrary k-of-n, or
wall-clock semantics. A single model of every EP subsystem is not claimed.

## How to re-run

Same third-party image as the core model (stock tamarin-prover 1.10.0 + Maude
3.4; no official Tamarin image on Docker Hub as of 2026-07):

```
docker run --rm \
  -v /path/to/emilia-protocol/formal/tamarin:/work -w /work \
  lmandrelli/tamarin-prover-and-batch:latest \
  tamarin-prover --prove ep_quorum_core.spthy
```

The proof completes in under a second. Any result differing from the summary
quoted above should be treated as a regression and investigated before claiming
verification.

---

# Tamarin model: composed reliance path (`ep_reliance_composed.spthy`)

This model closes the prior composition gap for the high-assurance acceptance
path. It carries a computed CAID, profile, audience, initiator, and fresh
challenge nonce through a signed relying-party challenge, two distinct UV-gated
human approvals, scoped authority bound to an exact registry epoch/head, fresh
revocation state, and a pinned receipt issuer. The verifier enforces initiator
exclusion and distinct keys, consumes the challenge once, and only then emits
`Executed`.

Machine-checked on 2026-07-10 with Tamarin 1.10.0 and Maude 3.4. The focused
six-claim companion model described below was checked on 2026-07-24 with the
same pinned image. Exact model and runner hashes are in
`results/ep_reliance_composed.summary.txt`.

```
executable_composed_reliance (exists-trace): verified (19 steps)
execution_requires_full_composition (all-traces): verified (97 steps)
caid_binds_family_and_material (all-traces): verified (2 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (2 steps)
no_issuer_laundering (all-traces): verified (781 steps)
strict_registry_view_is_exact (all-traces): verified (25 steps)
no_cross_action_profile_or_audience_replay (all-traces): verified (37 steps)
execution_has_honest_approvals_or_prior_compromise (all-traces): verified (170 steps)
injective_execution_with_consumption (all-traces): verified (2 steps)
unchecked_composition_is_injective (all-traces): falsified - found trace (31 steps)
unchecked_registry_view_is_current (all-traces): falsified - found trace (20 steps)
```

The two falsifications are deliberate. One omits `Consume`, and Tamarin finds a
same-receipt double execution. The other accepts a signed authority artifact
without joining its epoch/head to the verifier-pinned checkpoint, and Tamarin
finds a stale/equivocating-view execution. Both strict paths verify.

**Scope boundary:** signatures are perfect Dolev-Yao primitives; WebAuthn and
canonical parsers are not modeled. CAID construction is symbolic and injective;
authority scope and profile are opaque terms, so the proof establishes exact
binding and required presence, not amount arithmetic or policy authorship.
Revocation freshness is an authenticated `current` assertion, not a clock model.
The model proves use of the exact pinned registry checkpoint but not that the
external checkpoint is complete or honestly selected. Root provisioning,
directory transparency, collusion, and downstream business-system idempotency
remain external assumptions.

## Focused six-claim companion (`ep_six_claim_composed.spthy`)

The companion theory gives six partial claims dedicated symbolic obligations
without inflating their scope:

```
class_a_downgrade_refused (all-traces): verified (22 steps)
signed_denial_cannot_authorize (all-traces): verified (2 steps)
scoped_authority_is_pinned (all-traces): verified (49 steps)
reliance_requires_pinned_profile (all-traces): verified (12 steps)
evidence_challenge_is_registered_and_consumed (all-traces): verified (41 steps)
aec_execution_is_action_keyed_and_fleet_fail_closed (all-traces): verified (13 steps)
```

The theory also verifies an executable strict trace, authentic signed-denial
evidence, fresh challenge uniqueness, and fail-closed reservation failure. Six
unsafe variants are deliberately falsified: trusting a presenter-declared key
class, ignoring the signed decision, accepting unpinned authority scope or
registry coordinates, trusting a presented profile, accepting an unregistered
challenge, and deriving an execution key from presenter material.

These results do **not** make the six full implementation claims formally
verified. Class A and UV are symbolic protocol states, not WebAuthn proofs.
Scope fields are exact terms; amount inequalities, policy authorship, and clock
evaluation remain external. Linear challenge state and the action-key
uniqueness restriction assume an atomic shared backend; they do not prove
durability, owner-token fencing, restart behavior, or database semantics.
Action-key injectivity does not prove downstream business-effect exactly-once
behavior. The claim metadata should therefore use `status: "partial"` and
`method: "symbolic_protocol_analysis"` with claim-specific covered and
unmodeled statements.

Re-run:

```
cd /path/to/emilia-protocol/formal/tamarin
sh ./run-composed.sh
```
