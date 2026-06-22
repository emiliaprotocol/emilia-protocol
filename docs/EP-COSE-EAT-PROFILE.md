<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-COSE-EAT-PROFILE — a COSE/EAT serialization of EP authorization receipts

**Status:** Profile (spec-level). EXPERIMENTAL. Defines an OPTIONAL CBOR/COSE
serialization so EP human-authorization evidence composes natively with the
RATS/EAT and SCITT ecosystems. Not a wire-format mandate; the canonical EP
artifact remains the JSON form in [draft-schrock-ep-authorization-receipts].

## Why this exists

EP's native form is JSON over JCS [RFC8785] with detached signatures — the
dialect the agent-authorization receipt cluster (DRP, Permit Receipts, ACTA,
AgentROA) speaks. The *attestation* world next door — RATS Entity Attestation
Tokens (EAT) [RFC9711], CWT [RFC8392], COSE [RFC9052], and SCITT
[I-D.ietf-scitt-architecture] — speaks CBOR/COSE. To compose with that world (so
an EP human-authorization receipt can ride inside an EAT **detached bundle**
alongside device/TEE attestation, or be registered as a SCITT signed statement
for transparency), EP needs a faithful COSE/CWT encoding. This profile defines
it without changing EP semantics.

## The mapping

An EP authorization receipt becomes a **CWT Claims-Set** carried in a COSE_Sign1
(or COSE_Sign for quorum). Proposed claims (final CBOR keys to be registered if
the work advances):

| EP JSON field | CWT/EAT claim | Notes |
|---|---|---|
| issuer / operator id | `iss` (1) | RFC 8392 |
| `committed_at` | `iat` (6) | issued-at |
| `action_hash` | EP private claim `ep-action-digest` | hex of JCS(action) |
| `action` (object) | EP private claim `ep-action` | the canonical Action Object |
| `quorum` / signoffs | EAT **submodules** (one per approver) | each a nested token with the approver's own key — exactly EAT's distinct-attesting-environment model |
| approver device assertion | submodule signature (COSE_Sign1) | the WebAuthn/Class-A signoff re-expressed as a COSE signature |
| revocation/status | `status` via SCITT receipt or CT-style proof | composes with EP-REVOCATION-v1 |

The two-person quorum maps cleanly onto EAT's **detached submodule** mechanism:
each distinct human's signoff is a submodule with keys distinct from the issuer,
which is precisely the case EAT submodules were designed for. The action-digest
binding is preserved: every submodule's `ep-action-digest` MUST equal the
surrounding token's.

## What it buys

* **EAT detached bundles** — an EP human-authorization token can be one detached
  submodule alongside hardware/TEE attestation in a single EAT, so "the device
  was sound AND a named human approved this action" is one verifiable bundle.
* **SCITT transparency** — the COSE form is a registrable SCITT signed
  statement; an EP receipt can then carry an inclusion-proof Receipt, giving
  append-only transparency on top of offline verifiability.
* **Credibility** — speaking COSE/CWT meets the RATS/SCITT reviewers in their own
  dialect rather than asking them to adopt a JSON island.

## What it does not change

Semantics are identical: same action binding, same fail-closed predicate, same
distinct-human quorum rules. The JSON form remains canonical and normative; this
is an alternate serialization for interop, selected by media type. Round-tripping
JSON↔COSE MUST preserve the canonical action digest.

## Status / next steps

Spec-level only. A reference encoder/decoder (JSON↔COSE_Sign1, EAT submodule
emission) is the implementation increment; it would live alongside the existing
verifiers and be covered by the cross-language conformance suite.

[draft-schrock-ep-authorization-receipts]: https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/
[I-D.ietf-scitt-architecture]: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
