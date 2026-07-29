<!-- SPDX-License-Identifier: Apache-2.0 -->
# Exact-Action Refusal Statement v1

**Artifact:** `EP-ACTION-REFUSAL-STATEMENT-v1`  
**Status:** implemented public experimental profile with a TypeScript signer,
verifier, replay-checked acceptance helper, tests, and deterministic synthetic
vector; not an Internet-Draft, standard, legal instrument, adverse-benefit
notice, or independent-interoperability claim

## 1. Scope

An Exact-Action Refusal Statement records one issuer's technical refusal to
admit one exact CAID/action under one relying party's version-pinned Reliance
Program. It binds what failed and the evidence/challenges considered so that a
different action, program revision, source, or challenge cannot be substituted.

The statement proves only the explicit signed claim after the verifier accepts
the pinned issuer key. It does **not** create or establish:

- legal enforceability, liability, solvency, payment, coverage, or causation;
- a legal denial or an adverse-benefit determination or notice;
- authorization to perform the action, an execution attempt, provider receipt,
  an external effect, or business correctness;
- delivery or custody merely because the issuer signed the statement;
- a Sabey probe-run transparency result; or
- a Kamimura content-refusal event.

Those are different artifacts, events, or legal processes. An implementation
must not relabel this technical refusal to imply one of them.

## 2. Signed object

The signed body is a closed object containing:

- `@version`: `EP-ACTION-REFUSAL-STATEMENT-v1`;
- `refusal_id`: issuer-scoped identifier for this statement;
- `relying_party_id`;
- `caid` and `action_digest` for the refused exact action;
- `program`: `program_id`, positive integer `version`, `source_digest`, and
  compiled `program_digest`;
- nonempty, unique, bytewise-sorted `failed_requirement_ids`;
- unique, bytewise-sorted `evidence_digests` and nonempty
  `challenge_digests`;
- replay `nonce`, `refused_at`, and exclusive `expires_at`;
- bounded `refusal_class` and the four independent `semantics` axes;
- `delivery`, `custody`, and `transparency_anchor`, each nullable;
- `claim_boundary`:
  `technical_refusal_not_legal_or_benefit_determination`; and
- signed `issuer.id` and `issuer.key_id` fields added by the signing primitive.

Unknown fields, duplicate set entries, unsorted set entries, malformed digests,
invalid time windows, inconsistent semantic axes, non-Ed25519 keys, malformed
signatures, untrusted issuer identities, and signature or digest mismatches fail
closed.

`refusal_class` is one of:

- `verification_failed`;
- `action_mismatch`;
- `evidence_unsatisfied`;
- `authorization_refused`;
- `replay_detected`;
- `expired`; or
- `indeterminate`.

The class and semantic axes must agree. For example,
`evidence_unsatisfied` requires `satisfaction: NOT_SATISFIED`, while
`action_mismatch` requires `match: MISMATCH`.

## 3. Semantic separation

The `semantics` object keeps four propositions separate:

| Axis | Values | Meaning |
| --- | --- | --- |
| `verification` | `VERIFIED`, `NOT_VERIFIED`, `INDETERMINATE` | Whether the relevant artifact verification completed successfully. |
| `match` | `MATCH`, `MISMATCH`, `INDETERMINATE` | Whether the evaluated material binds the exact CAID/action. |
| `satisfaction` | `SATISFIED`, `NOT_SATISFIED`, `INDETERMINATE` | Whether named Reliance Program requirements were satisfied. |
| `authorization` | `AUTHORIZED`, `NOT_AUTHORIZED`, `NOT_EVALUATED`, `INDETERMINATE` | The separate local authorization proposition. |

This refusal profile requires at least one failed requirement and therefore
does not accept `satisfaction: SATISFIED`. In particular, `VERIFIED + MATCH`
does not imply `SATISFIED`, and no combination short of an independently valid
authorization decision implies `AUTHORIZED`. A refusal never grants authority.

## 4. Signature and digest

The implementation uses the repository's risk-artifact primitive:

1. add the signed `issuer` identity and key identifier;
2. canonicalize the complete body using RFC 8785/JCS behavior provided by the
   existing Gate canonicalizer;
3. sign `UTF8("EP-ACTION-REFUSAL-STATEMENT-v1" || 0x00 || JCS(body))` with
   Ed25519; and
4. attach `proof.algorithm`, `proof.key_id`, `proof.body_digest`, and
   `proof.signature_b64u`.

`proof.body_digest` is the SHA-256 digest of the canonical signed body.
`actionRefusalStatementDigest()` computes the SHA-256 canonical digest of the
complete statement, including its proof envelope. A verifier accepts an issuer
identity only when the relying party's out-of-band key pin binds the same
`key_id`, `issuer_id`, and Ed25519 public key.

## 5. Verification, freshness, and replay

`verifyActionRefusalStatement()` is side-effect free. It verifies the closed
shape, body digest, Ed25519 signature, pinned issuer identity, refusal time
window, optional future-skew ceiling, and every expected binding supplied by
the relying party. The complete expected tuple is:

`caid + action_digest + relying_party_id + program_id + program_version +
source_digest + program_digest + nonce`.

Its `accepted: true` result means only that this technical refusal evidence is
cryptographically verified, current, trusted, and matches the supplied
expectations. It is not action authorization and does not itself consume the
nonce.

`acceptActionRefusalStatement()` additionally requires the complete expected
tuple and an atomic replay store. It consumes the nonce in the relying-party
namespace and distinguishes an exact `statement_replay` from
`nonce_equivocation`. The bundled memory store is non-durable and is permitted
only with the explicit test/development opt-in. Production acceptance must use
a durable atomic implementation; a missing or unavailable store fails closed.
`createPostgresActionRefusalReplayStore()` is the deployment-bound reference
adapter. It calls one `SECURITY DEFINER` database function under the
authenticated PostgreSQL session principal. The migration stores the exact
`tenant + gate + relying party + nonce` key immutably, distinguishes replay
from equivocation, forces row-level security, and grants the runtime role no
direct table access. Operators grant the runtime login the dedicated
`action-refusal` evidence scope before enabling acceptance.

Expiry is exclusive: verification at or after `expires_at` returns
`refusal_expired`.

## 6. Delivery, custody, and transparency references

`delivery: null` and `custody: null` are valid and are reported as
`NOT_EVIDENCED`. They must never be interpreted as delivered, received, or
acknowledged.

A non-null `delivery` binds a channel, recipient, delivery time, and external
evidence digest. A non-null `custody` requires delivery and binds a custodian,
acknowledgement time, and external evidence digest. The verifier reports these
only as `REFERENCED`; it does not verify the external systems or the truth of
delivery/custody.

A non-null `transparency_anchor` binds an external method and evidence digest.
The verifier reports `REFERENCED_NOT_EXTERNALLY_VERIFIED`. The reference does
not transform a probe run, content-policy refusal, or transparency-log entry
into an exact-action Gate refusal, and the refusal does not prove the external
anchor.

`verifyActionRefusalExternalEvidence()` closes the optional external-proof
step without pretending that a digest is proof. The relying party pins a
separate adapter for each required leg. Each adapter must return a closed
`VERIFIED`, `NOT_VERIFIED`, or `INDETERMINATE` result and the exact evidence
digest it checked. Missing adapters, adapter outages, malformed outputs, and
digest substitution fail closed whenever the leg is required. When configured
on `acceptActionRefusalStatement()`, this verification runs before nonce
consumption so an unverifiable external reference cannot burn a valid refusal.

## 7. Runtime emission

`createRelianceKernel({ refusal: ... })` connects the reliance decision to the
signed statement. A deployment-supplied context function must provide the
compiled program identity, exact CAID/action digest, actual failed requirement
identifiers, evaluated evidence/challenge digests, nonce, and validity window.
The bridge does not infer any of them. For each non-allow verdict the kernel
signs the statement, records its digest as governed evidence, and carries the
statement and digest in the HTTP 428 challenge. If context, signing, or evidence
recording fails, the action remains refused and the response reports
`signed_refusal_unavailable`; no unsigned object is mislabeled as a signed
statement. An allow path can never emit this artifact.

## 8. Conformance vector

[`conformance/vectors/action-refusal-statement.v1.json`](../../conformance/vectors/action-refusal-statement.v1.json)
contains a deterministic synthetic, PHI-free Ed25519/JCS statement, its fixed
seed and public-key pin, expected full binding, exact statement digest, hostile
mutations, and replay expectation. Passing the vector establishes only the
behaviors encoded there; it is not an independent implementation result,
cross-vendor interoperability claim, legal determination, payer-live result,
or production deployment claim.
