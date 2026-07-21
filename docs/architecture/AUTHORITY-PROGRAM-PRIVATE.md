# EP Authority Program — Private Architecture Note

Status: private, pre-publication design and reference implementation. Do not
publish, submit, deploy, or describe this file as an adopted standard.

## Purpose

`EP-AUTHORITY-PROGRAM-v1` is a signed description of how separately verified
authority stages compose for one root action. It is intentionally a pure
verification format. It does not schedule work, store state, advance stages,
evaluate a general policy language, revoke an artifact, execute an action, or
reconcile an outcome.

The relying party pins the exact digest of the signed program and the program
signer's organization, key identifier, and Ed25519 public key out of band. A
presented program cannot introduce or replace its own trust root.

## Wire contracts

The signed program is a closed object containing:

- `@version = EP-AUTHORITY-PROGRAM-v1`
- a bounded `program_id`
- one root CAID and one root canonical-action digest
- one recursive series/parallel expression
- one Ed25519 proof made by the RP-pinned program signer

The expression grammar has exactly three node forms:

```text
stage(stage_id, authority, AEC requirement, AOM requirement,
      capability requirement)
sequence(child, child, ...)
parallel(parallel_id, authoritative allocation requirement/proof,
         branch, branch, ...)
```

There are no edge lists or `depends_on` fields. Consequently an arbitrary DAG,
including a non-series-parallel N-shaped graph, is unrepresentable. Stage and
parallel identifiers are unique, depth is bounded, and unknown fields fail.

Each immutable `EP-AUTHORITY-STAGE-RECEIPT-v1` binds:

- the exact signed program digest;
- the root CAID and root action digest;
- the stage identifier and issuing organization/key;
- the exact, canonical predecessor stage-receipt digest set;
- the exact AEC requirement and verified result digests;
- the exact AOM requirement and verified result digests; and
- the capability requirement plus input and output digests.

Each stage receipt is signed by that stage's organization-specific key. The
relying party supplies the organization/key directory; neither the program nor
the receipt can inject a trusted key.

## AEC and AOM are distinct

AEC means an EP Authorization Evidence Chain requirement/result. The native AEC
verifier decides whether its heterogeneous authorization evidence is valid.

AOM means an **EP Action Outcome Manifest** requirement/result: an explicit
manifest of the outcome evidence a stage requires and the verified result that
satisfied it. This private contract does not silently alias AOM to
`EP-OUTCOME-BINDING`, an outcome attestation, or any other existing artifact.
The relying party must inject an AOM verifier that understands the pinned AOM
profile. The authority-program verifier checks only that its closed result binds
the exact requirement and result digests signed into the stage receipt.

## Predecessor derivation

Predecessors are derived from the expression, never asserted by a scheduler.
For:

```text
sequence(A, parallel(B, C), D)
```

the exact immediate predecessor sets are:

```text
A = []
B = [A]
C = [A]
D = [B, C]
```

The verifier replaces those stage identifiers with the digests of the actual
signed receipts and requires the receipt's digest array to match exactly in
canonical order. Missing, extra, reordered, or substituted digests fail.

## Native verifier boundary

The RP injects pure adapters for AEC, AOM, capability narrowing, and parallel
allocation. Every adapter returns a closed result. The authority-program
verifier rejects extra result fields, callback errors, false results, or any
digest mismatch.

Capability verification must return `narrowed: true` and bind the exact signed
requirement/input/output digests. This verifier does not infer scope or budget
narrowing from labels.

Per-stage narrowing does **not** prove that parallel siblings collectively stay
within a parent's budget. Every parallel node therefore pins an authoritative
allocation requirement and proof digest. A relying-party-owned allocation
verifier must return an exact, authoritative result. If that verifier or proof
is absent, the whole authority program fails with
`parallel_allocation_unproven`; the implementation never downgrades that fact to
a warning.

## Result and consequence boundary

The closed `EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1` result reports the exact
program/root bindings, verified stage-receipt digests, parallel-allocation
status, and one reason. It always reports `execution_proven: false`.

A valid result means only that the signed authority program and immutable joins
verify under the relying party's pins and native verifier results. Existing
Gate/AEC/Receipt Program components separately decide authorization, reserve or
consume capability, execute, and record outcome. This module cannot perform or
authorize those consequence-bearing operations by itself.

## Security invariants exercised

The hostile package and private conformance suites cover:

- unsigned, wrongly signed, wrong-signer, and wrong-program-pin rejection;
- arbitrary DAG vocabulary and unknown-field rejection;
- nested sequence/parallel predecessor derivation;
- missing, extra, and reordered predecessor receipt digests;
- wrong organization/key and duplicate stage/receipt replay;
- replay under another program, root CAID, root action, stage, or authority;
- wrong AEC and explicit AOM requirement/result joins;
- closed callback-result enforcement;
- capability broadening; and
- missing or self-asserted parallel allocation proof.

The deterministic vector at
`conformance/vectors/authority-program.v1.json` uses test-only keys and is not an
independent implementation claim.
