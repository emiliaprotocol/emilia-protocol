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
  `<'ep_signoff_v1', h(action), nonce>` (Section 4: signature over the hash
  of the canonical context containing the action hash and a fresh unique
  nonce).
- The relying party pins the human's public key out of band (abstracting the
  Approver Directory) and accepts a receipt only if the signature verifies
  under the pinned key over the exact action term received.
- Key compromise is a modeled event (`RevealLtk`), so each lemma states
  explicitly that its guarantee is conditional on the device key not having
  leaked.
- One-time consumption (Section 6, guarantee G3) is modeled as two accept
  rules: one without any consumption check, and one with a one-per-(human,
  nonce) consumption restriction abstracting the consumption record.

## Machine-checked result

Verbatim `summary of summaries` from the run on 2026-07-05
(tamarin-prover 1.10.0, Maude 3.4, all wellformedness checks successful):

```
summary of summaries:

analyzed: ep_receipt_core.spthy

  processing time: 0.39s

  executable_honest_receipt (exists-trace): verified (8 steps)
  core_authenticity_uv_gated (all-traces): verified (12 steps)
  no_replay_across_actions (all-traces): verified (12 steps)
  injective_acceptance_with_consumption (all-traces): verified (6 steps)
  unchecked_acceptance_is_injective (all-traces): falsified - found trace (10 steps)
```

What each result means:

| Lemma | Result | Meaning |
|---|---|---|
| `executable_honest_receipt` | verified | Sanity trace exists: an honest UV-gated receipt is accepted with no key compromise. The model is not vacuous. |
| `core_authenticity_uv_gated` | verified | If any relying party accepts a receipt naming human H for action a with nonce n, and H's key was not compromised before acceptance, then H performed a UV event and then a signature over exactly (a, n), in that order, before the acceptance. |
| `no_replay_across_actions` | verified | No trace exists where a receipt for action a is accepted while the uncompromised human never signed exactly (a, n). The attacker holds honest signatures over arbitrary other actions of its choice and still cannot transplant any of them onto a different action. |
| `injective_acceptance_with_consumption` | verified | With the one-time consumption check, each consumption-checked acceptance corresponds to a preceding honest signature and no second consumption-checked acceptance of the same (H, a, n) exists anywhere. (The lemma quantifies over `AcceptChecked` events only; an unchecked accept path, if deployed, is exactly what the falsified lemma below shows to be replayable.) |
| `unchecked_acceptance_is_injective` | falsified | Expected and kept deliberately, see below. |

## The falsified lemma is a demonstrated replay, not a hidden defect

`unchecked_acceptance_is_injective` asserts that even WITHOUT a consumption
check, the same (H, a, n) is never accepted twice. Tamarin falsified it and
produced the counterexample trace: the attacker takes the one honest receipt
broadcast by `Human_Sign_Receipt` and delivers it to an accept point twice
(in the found trace, once through the consumption-checked rule and once
through the unchecked rule). No forgery and no key reveal occur in the trace.

Why the counterexample is necessarily a same-receipt replay and not
something worse: the verified `core_authenticity_uv_gated` lemma forces every
acceptance to be backed by a Signed event over exactly (a, n), and the model
admits at most one Signed event per nonce (the nonce is `Fr`-fresh, so only
one sign request carries it, and the linear `UVDone` fact allows exactly one
signature per request). So any double acceptance is the single honest receipt
accepted twice. (This uniqueness argument is structural, from `Fr` freshness
and fact linearity in the model semantics; it is not itself a separate
machine-checked lemma.)

This is precisely the failure mode the spec's one-time consumption record
(Section 6, G3) exists to prevent, and the model shows that adding the
consumption check (the `ConsumeOnce` restriction) restores injectivity
(`injective_acceptance_with_consumption`, verified).

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
