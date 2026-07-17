<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Conformance and Certification Scheme (EP-CERT-v1)

**Status:** scheme design, spec-level. Defines how conformance to the open EMILIA
specification is demonstrated, who may attest it, and what a conformance mark does and does
not assert. It builds on the [Neutrality Covenant](NEUTRALITY-COVENANT.md), the
[Auditor Control Catalog](AUDITOR-CONTROL-CATALOG.md), and the public conformance vector
suites. The spec and all vectors stay Apache-2.0; this scheme adds an attestation layer on
top of them, it does not close them.

## What this is, and the line it must not cross

Owning the conformance suite and the mark is the durable position: the vectors are the
gate every conforming verifier must pass, and the mark is the thing a buyer, an auditor, or
a regulator can point at. But the whole value depends on the mark meaning exactly one thing
and never more.

**A conformance mark asserts:** this named implementation, at this version, correctly
verifies the EMILIA conformance vector suites (accept the valid, refuse the invalid) and
correctly refuses the published adversarial corpus. Nothing else.

**A conformance mark never asserts:** that the marked party's *deployment* is secure, that
its human-approval ceremony is real, that any specific action was authorized, that an
organization's controls are designed or operating effectively, or that anything is
"EMILIA-certified" as an outcome. EMILIA is not an auditor and issues no opinion on any
organization. Conflating "the verifier conforms" with "the deployment is trustworthy" is
the exact error the covenant and the auditor catalog refuse.

## The three assets, and why they are hard to route around

### 1. The conformance suite (the gate)

The public vector suites (accept/refuse per receipt, quorum, revocation, evidence chain,
timestamp, admissibility, plus the differential hostility corpus) are the bar every
implementation must clear. An
implementation earns a conformance record by running the versioned suite and producing a
signed result matching the expected verdicts byte for byte. Because the suite is public and
Apache-2.0, anyone can self-test; because the *record* is signed and versioned, a third
party can rely on it. A Big-4 firm or a GRC platform can reproduce the run, but they cannot
define the bar, because the bar is the spec's own vectors.

### 2. The assessor registry (who may attest)

A signed, versioned, publicly readable registry of accredited assessors, each entry
carrying `{assessor_id, public_key, accreditation_scope, valid_from, valid_to, revoked_at}`.
An assessor is any party (an implementer self-attesting, an independent lab, or an audit
firm) whose conformance records the registry will resolve. Self-attestation is a first-class
tier and is labeled as such; independent-lab and accredited-firm tiers carry higher weight.
The registry is a signed snapshot verified offline against a pinned steward key, the same
shape as the EP authority registry, so a relying party checks an assessor the way it checks
any other authority: active, in-window, not revoked, in scope.

### 3. The conformance mark (what a buyer cites)

`EP-CONFORMANT` is a claim object, not a logo: `{implementation, version, suite_version,
suite_result_digest, assessor_id, assessor_tier, issued_at, expires_at, signature}`. It is
itself an EMILIA-shaped signed statement, so verifying the mark is the same offline check as
verifying a receipt. A deployment cites the mark of the *verifier it runs*; the mark travels
with the software, not with the organization.

## How it rides existing assurance instead of replacing it

The scheme is deliberately an **addendum control**, not a new audit category, so it consumes
spend that already flows rather than asking a buyer to fund a new line.

| Existing regime | Where EP-CERT rides | What the mark supplies |
|---|---|---|
| SOC 2 (Security / Processing Integrity) | a control in the RCM ([Auditor Control Catalog](AUDITOR-CONTROL-CATALOG.md)) whose design is "high-risk actions are gated by an offline-verifiable human-authorization receipt" | the assessor's conformance record is the evidence that the verifier the control relies on actually behaves as claimed |
| ISO/IEC 42001 (AI management system) | a control objective for human oversight of high-risk automated actions | machine-checkable evidence that the oversight artifact is real and re-verifiable, not asserted |
| EU AI Act Article 14 (human oversight) | one technical measure a provider may include in its human-oversight design | an independently verifiable per-action authorization artifact; not a complete Article 14 assessment |
| NIST AI RMF (MEASURE / MANAGE) | mapped subcategories ([NIST-AI-RMF-MAPPING](compliance/NIST-AI-RMF-MAPPING.md)) | the conformance record turns a mapped claim into a tested one |

The auditor still tests the deployment; the mark only removes the question of whether the
verifier itself is sound, which the auditor would otherwise have to take on faith or
re-derive.

## The business boundary (why this is a franchise, not a toll)

Per the [Neutrality Covenant](NEUTRALITY-COVENANT.md), the spec, the reference verifiers,
and every conformance vector are Apache-2.0 forever, and the offline verifier never calls
back to EMILIA. So there is no per-receipt metering point and there will never be a receipt
fee. The paid surface is the attestation layer, never the protocol:

- **Accreditation** of independent labs and audit firms into the assessor registry (charge
  the assessor, in the PCI-SSC / QSA shape, never the deploying merchant).
- **Conformance testing and reperformance** as a service for parties who want a record
  without standing up the harness.
- **A steward-run registry and reliance decisioning** layer for parties who want the
  authority/assessor snapshots maintained and the acceptance decision run for them.

The mark's credibility is the asset. Charging to *issue* it to the wrong party, or letting
it drift toward meaning "trustworthy deployment," destroys the asset. The scheme is built to
make that drift impossible: the mark's own text carries its scope, and the honest-boundary
row travels with every control.

## What must exist before this is real (open work, stated honestly)

1. A signed, versioned conformance-record format and a `conformance:record` command in the
   verifier that emits it.
2. The assessor registry object, schema, and offline resolver (reuse the authority-registry
   machinery).
3. The `EP-CONFORMANT` mark object and its verifier.
4. At least one independent assessor other than the steward, so the registry is not a
   single-party list.

None of these is built yet; this document is the design they implement against, not a claim
that the scheme is operating.
