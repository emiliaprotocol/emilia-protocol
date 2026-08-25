<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RECEIPT-SCITT-PROFILE-v1 — an EMILIA authorization receipt as a SCITT Signed Statement

**Status:** working profile for SCITT WG engagement. Maps the EMILIA authorization receipt onto
**RFC 9943** (SCITT Architecture), **RFC 9942** (COSE Receipts), and
`draft-ietf-scitt-scrapi-11` (in the RFC Editor queue as of 2026-08-04). Shared with the SCITT WG
list 2026-06-30. This repository implements the issuer-side Signed Statement envelope, the complete
201/202/204/200 SCRAPI client flow, and a relying-party-pinned RFC 9942 `vds` dispatch boundary.
Native RFC9162, CCF, or MMR proof verification remains the job of the configured profile verifier.

## What this profile does (and does not) claim

SCITT is **agnostic about who authorized a statement** — its Transparency Service registers signed
statements in an append-only log and returns an inclusion **Receipt** (proof a statement was logged).
EMILIA supplies the **authorization** SCITT leaves open: *a named human approved this exact action.*
This profile carries an EMILIA authorization receipt **as a SCITT Signed Statement**, so the two
compose without either claiming the other's job.

> Vocabulary, kept strict throughout: **authorization receipt** = EMILIA (who approved what);
> **transparency / inclusion receipt** = SCITT (proof it was logged). They are different artifacts.

## 1. The Signed Statement

A SCITT Signed Statement is a `COSE_Sign1` (RFC 9052) over an Issuer's assertion about an Artifact.

| COSE_Sign1 element | EP-RECEIPT-SCITT-PROFILE-v1 value |
|---|---|
| **payload** | RFC 8785 (JCS) canonical bytes of the complete EMILIA receipt document. The inner receipt signature separately covers its `payload` object. |
| protected `alg` (label 1) | `EdDSA` (-8); Ed25519 per RFC 8037 / RFC 8032 |
| protected `content type` (label 3) | `application/emilia-receipt+json` |
| protected `kid` (label 4) | the SCITT statement issuer key id |
| protected `CWT Claims` (label 15) | `iss` (claim 1) = the SCITT statement issuer; `sub` (claim 2) = the receipt action's CAID, recomputed from the carried receipt |
| signature | Ed25519 over the COSE `Sig_structure` (`["Signature1", protected, ext_aad="", payload]`, RFC 9052 §4.4) |

The SCITT statement signer and the EP receipt issuer are separate trust legs.
The statement signature proves which pinned SCITT issuer emitted the envelope.
The inner receipt signature supplies the authorization evidence. Trust in the
first key does not imply trust in the second.

### Identity layers

This profile exposes three digests and does not permit substitution between
them:

| Digest | Meaning |
| --- | --- |
| `statement_entry_digest = SHA-256(exact COSE_Sign1 bytes)` | one exact envelope or registration entry |
| `signing_input_digest = SHA-256(Sig_structure)` | the protected header and payload presented to the signature algorithm |
| `authorization_payload_digest = SHA-256(JCS(receipt.payload))` | the EP authorization claim, evaluated with separately pinned issuer and profile checks |

Two valid signatures over the same signing input can have different exact
envelope digests. The authorization reference therefore uses
`authorization_payload_digest`. A transparency reference may carry
`statement_entry_digest` separately to locate the logged envelope. The
runnable
[`EP-SCITT-STATEMENT-IDENTITY-v0.1`](../conformance/composition/scitt-statement-identity-v0.1/README.md)
profile proves the separation with two deliberately distinct fixtures: an RFC
9943-shaped ES256 high-S/low-S ECDSA pair verified at the algorithm layer, and
an Ed25519 EP statement accepted by the local EP verifier. The EP verifier
correctly refuses the generic ES256 pair as outside this profile. Enforcing
canonical low-S at an ingress rejects the high-S form there; it does not
collapse exact-envelope, signing-input, and application-claim identity into one
protocol concept.

## 2. Registration (SCRAPI)

Register the Signed Statement with any conforming Transparency Service:

```
POST /entries                       (draft-ietf-scitt-scrapi)
Content-Type: application/scitt-statement+cose
<COSE_Sign1 bytes>
```

The Transparency Service returns a **SCITT Receipt** (a COSE inclusion proof, RFC 9942). It can
return the Receipt directly with `201`, or return `202 + Location`; the client then polls that
resource, honoring `Retry-After`, until `200` returns the Receipt (`204` means still running).
Signed Statement + Receipt = a **Transparent Statement**: the
authorization is now both *attributable to a named human* (EMILIA) and *tamper-evidently logged*
(SCITT). EMILIA does not run the log; it produces the statement the log ingests.

## 3. Execution lineage (multi-hop)

The lineage chain is **EMILIA/COSA content, not a SCITT feature.** Each hop is its own Signed
Statement whose payload carries a `prev` field = the SHA-256 of the prior hop's canonical receipt
(EMILIA evidence-chain / AEC). Registering each hop yields external log transparency and inclusion
for every EP-linked hop:

```
hop₀ (receipt, prev=∅)  ─register→  Receipt₀
hop₁ (receipt, prev=H(hop₀)) ─register→ Receipt₁
hop₂ (receipt, prev=H(hop₁)) ─register→ Receipt₂
```

EMILIA defines and verifies the lineage link; SCITT proves each linked statement was logged in a
tamper-evident Transparency Service. Neither needs a monolithic lifecycle protocol — this is two
narrow profiles on accepted work.

## 4. Verification

1. Verify the `COSE_Sign1` signature against the pinned SCITT statement issuer
   key. This verifies the envelope, not the authorization.
2. Parse the canonical `EP-RECEIPT-v1` document and independently verify its
   inner signature against the pinned receipt issuer key. Recompute the action
   CAID and authorization payload digest from the carried receipt.
3. Confirm that the bound action matches the action about to execute.
4. If a SCITT Receipt is present, read protected header `vds` (label 395) and dispatch only to the
   relying-party-pinned native verifier for that Verifiable Data Structure. The current identifiers
   are RFC9162_SHA256 = 1, CCF = 2, and MMR = 3. Unknown `vds` is `INDETERMINATE`; a malformed or
   missing protected `vds` fails.
5. Accept the transparency leg only if that native verifier validates both the VDS proof and the
   Transparency Service signature against pinned service parameters.

Steps 1 to 3 are the local envelope and EMILIA authorization checks and need no
network. Steps 4 and 5 are the SCITT
transparency check. A verified transparency leg is evidence; it is not AEB satisfaction, Gate
authorization, execution, or outcome. Keep those decisions separate.

For a large or sensitive receipt payload, RFC 9995 COSE Hash Envelope can carry a digest and payload
location instead of exposing the full receipt to the log. That optional privacy shape is not emitted
by the reference harness in this repository.

## 5. Freshness ("decay")

Staleness/replay control is **freshness**, not a new mechanism: EMILIA's validity window +
observed-evidence freshness, plus one-time consumption, plus the Transparency Service's
non-equivocation (a re-registered/forked statement is detectable in the append-only log). State it in
those terms — not as "decay physics."

## 6. Registration order and attested effect order

A transparency receipt establishes registration of a statement. Its timestamp
or sequence position does not, by itself, establish when the event described by
that statement occurred. In particular, registering statement A before
statement B proves registration order, even when one service sequences both;
an emitter can delay statement A until after the event it describes.

A `PENDING_BEFORE_EFFECT` statement closes the absence-at-entry gap by proving
that the statement was registered before its own attempted effect. Two such
entries still do not establish completion order because their effects can
complete in the opposite order.

This profile therefore recognizes four cases:

1. One sequencer, with an authenticated, exact-operation terminal record that
   carries independently verified `EFFECT_CONFIRMED` evidence for operation A,
   ordered before the authenticated pre-effect entry for operation B:
   A-before-B order is established for those attested effect claims.
2. One sequencer without that terminal-before-entry relation: registration
   order only; effect order remains unproved. A terminal outcome of
   `INDETERMINATE` does not establish physical effect order.
3. Related logs: order only where an independently verified cross-log
   relationship binds the exact record digests and establishes that A's
   terminal record precedes B's entry.
4. Independent or unrelated logs: the records can be correlated, but their
   relative effect order is not established.

The obligation to emit an entry before provider effect belongs to the emitter
or executor profile. A Transparency Service can verify the bytes and their log
position; it cannot unilaterally verify that the emitter registered before
effect. These ordering rules do not extend BCR conservation beyond one
authoritative atomic state domain.

This classification establishes order between authenticated claims under the
configured trust policy. A signed or transparent statement does not, by itself,
prove that its account of a physical event is true or complete. The executable
classifier consumes already verified adapter results; it does not verify log
receipts, signatures, emitter truthfulness, or cross-log cryptography.

Executable cases are in
`examples/scitt/registration-event-order.test.mjs`.

## 7. Status

- **EMILIA** — `draft-schrock-ep-authorization-receipts` (individual I-D, Apache-2.0). Reference
  verifiers JS/Python/Go; JWS profile shipped (`EP-RECEIPT-JWS-PROFILE-v1`).
- **SCITT** — architecture is **RFC 9943** and COSE Receipts is **RFC 9942**.
  `draft-ietf-scitt-scrapi-11` is WG work in the RFC Editor queue. The CCF Receipt profile is a SCITT
  WG draft; the MMR Receipt profile is still an individual Internet-Draft under adoption review.
  **Not** an endorsement by the SCITT WG; this is a complement profile.
- **COSE / Ed25519** — RFC 9052 / RFC 9053 / RFC 8032 (published).

Runnable examples (zero-dependency, signature-correct) are in `examples/scitt/`.

Local profile conformance harness:

```
node examples/scitt/ep-receipt-scitt-conformance.mjs
```

End-to-end reproducible CI harness:

```
node examples/scitt/ep-receipt-scitt-end-to-end.mjs
```

That path builds the EP receipt, wraps it as a `COSE_Sign1` Signed Statement, registers it through
the SCRAPI `/entries` shape against an in-process mock Transparency Service, returns a mock
transparency receipt, and verifies the receipt signature + statement hash + Merkle inclusion path.
The mock exists so the demo can run green forever in CI; it is deliberately **not** a SCITT WG
Receipt format claim.

Optional external SCRAPI registration target:

```
SCITT_URL=https://<transparency-service> node examples/scitt/ep-receipt-scitt-end-to-end.mjs
```

External mode completes synchronous or asynchronous SCRAPI registration. It returns success only
when a caller also configures the native RFC 9942 profile verifier selected by protected `vds` and
that verifier accepts the proof under pinned service parameters. Registration alone does not pass.

Receipt-profile dispatch and its fail-closed negatives:

```
npx vitest run tests/scitt-receipt-dispatch.test.ts
```

The dispatch harness exercises RFC9162_SHA256 (1), CCF (2), MMR (3), unknown-profile abstention,
and missing-`vds` refusal. It tests dispatch and result preservation; it does not claim that the
three injected test adapters are implementations of those native proof algorithms.

Candidate CPB → CAID → AEB cross-vector:

```
node examples/scitt/cpb-caid-aeb-cross-vector.mjs
```

The vector resolves a CPB typed digest reference under an EMILIA-owned candidate
`caid-action-object` registry entry, recomputes the CAID over the exact material action, and keeps AEB
evidence satisfaction separate from executor authorization. Equal digest text under a different or
missing digest context is `INDETERMINATE`; action substitution is `UNSATISFIED`. The candidate entry
is not part of the CPB draft's initial registry and is not claimed as adopted by its authors.

HTTP mock server, when a socket-level SCRAPI-shaped endpoint is useful:

```
node examples/scitt/mock-scrapi-transparency-service.mjs
```

Historical/community emulator target:

- `scitt-community/scitt-api-emulator` exists and may be useful as an interoperability target, but it
  is archived; do not call it the current IETF reference emulator unless the SCITT WG says so.
- The current primary standards target is the `draft-ietf-scitt-scrapi` specification and WG repo.

Legacy live smoke-test alias:

```
SCITT_TS_URL=https://<transparency-service> node examples/scitt/ep-receipt-scitt-conformance.mjs
```

The conformance harness completes the SCRAPI resolution flow and reports the returned bytes. It does
**not** claim full SCITT Receipt verification until the returned transparency / inclusion Receipt is
verified by a configured native profile verifier against that service's parameters.
