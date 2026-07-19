<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Conformance and Certification Scheme (EP-CERT-v1)

**Status:** the evidence and re-performance machinery is operational; the
certification scheme described here is not. EMILIA currently supports
non-accredited conformance testing, signed external-verifier statements,
deployment evidence, auditor workpapers, underwriter packages, and deterministic
offline re-performance. It does not operate an accredited certification program
or issue an "EMILIA Certified" mark.

This document defines the future independent scheme: how conformance to the open
EMILIA specification would be demonstrated, who may attest it, and what a
conformance mark would and would not assert. It builds on the
[Neutrality Covenant](NEUTRALITY-COVENANT.md), the
[Auditor Control Catalog](AUDITOR-CONTROL-CATALOG.md), and the public conformance
vector suites. The specification and vectors stay Apache-2.0; a future scheme
adds an attestation layer on top of them, it does not close them.

## What this is, and the line it must not cross

Stewarding an open conformance suite creates a common technical bar: the vectors
are the gate every conforming verifier must pass. A future mark gives a buyer, an
auditor, or a regulator a stable object to cite. Its value depends on meaning
exactly one thing and never more.

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

A signed, versioned, publicly readable registry of statement issuers, each entry
carrying `{assessor_id, public_key, party_role, accreditation_scope, valid_from,
valid_to, revoked_at}`. An issuer is any party whose conformance records the
registry will resolve. `party_role` distinguishes first-party self-attestation,
second-party customer assessment, and third-party assessment. Only an issuer
whose applicable accreditation and scope have been independently confirmed may
be labeled accredited; self-attestation is never accreditation.

Self-attestation may remain a useful, explicitly labeled tier for open-source
adoption. It cannot be presented as independent certification. Independent-lab
and accredited-body tiers are separate claims, not stronger names for the same
activity.
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
| EU AI Act Article 14 (human oversight) | the technical measure a provider points to for effective oversight of high-risk AI | an independently verifiable per-action artifact, which is exactly what "effective" oversight has otherwise lacked |
| NIST AI RMF (MEASURE / MANAGE) | mapped subcategories ([NIST-AI-RMF-MAPPING](compliance/NIST-AI-RMF-MAPPING.md)) | the conformance record turns a mapped claim into a tested one |

The auditor still tests the deployment; the mark only removes the question of whether the
verifier itself is sound, which the auditor would otherwise have to take on faith or
re-derive.

## The business boundary (why this is a franchise, not a toll)

Per the [Neutrality Covenant](NEUTRALITY-COVENANT.md), the spec, the reference verifiers,
and every conformance vector are Apache-2.0 forever, and the offline verifier never calls
back to EMILIA. So there is no per-receipt metering point and there will never be a receipt
fee. The paid surface is managed operation and assurance, never verification
lock-in:

- **EMILIA Conformance:** free self-test plus paid, non-accredited witnessed
  testing and signed result packages for a named implementation and version.
- **EMILIA Deployment Assurance:** review Gate placement, bypass paths, pinned
  keys, policy configuration, failure behavior, and evidence retention. This is
  a vendor assessment, not independent certification.
- **EMILIA Continuous Assurance:** period-bound evidence packages, drift
  detection, exception reporting, and auditor-ready offline re-performance.
- **EMILIA Warranted Gate:** a separately contracted, narrowly scoped warranty
  after a successful baseline review. It covers named control behavior and never
  legal compliance, human understanding, or systems outside the protected
  boundary.
- **Future partner certification:** an independent certification body evaluates,
  reviews, decides, surveils, and controls any certification mark. EMILIA may
  steward the open scheme and supply evidence tooling, but it does not decide
  whether its own customer passes.

The mark's credibility is the asset. Charging to *issue* it to the wrong party, or letting
it drift toward meaning "trustworthy deployment," destroys the asset. The scheme is built to
make that drift impossible: the mark's own text carries its scope, and the honest-boundary
row travels with every control.

## Conformity-assessment boundary

| Activity | Current EMILIA claim | Future independent path |
|---|---|---|
| Testing | Non-accredited protocol, vector, and adversarial test report | A laboratory with an applicable [ISO/IEC 17025](https://www.iso.org/standard/66912.html) accreditation scope |
| Deployment review | Vendor or first-party assessment of a named Gate boundary | Independent inspection under an applicable programme |
| Verification | Period-bound re-performance of stated claims; the report names whether it is first-, second-, or third-party | A competent, impartial verification body operating under [ISO/IEC 17029](https://www.iso.org/standard/29352.html) |
| Certification | Not offered by EMILIA for its own Gate | An independent body operating the open scheme under [ISO/IEC 17065](https://www.iso.org/standard/46568.html) and the scheme guidance in [ISO/IEC 17067](https://www.iso.org/standard/55087.html) |
| Mark | No certification-looking mark today | Governed issuance, surveillance, suspension, withdrawal, and use under [ISO/IEC 17030](https://www.iso.org/standard/78283.html) |

Accreditation status, assessment-party role, and certification are separate
facts. Every issued report must state its scope, method, implementation version,
suite version, period, assumptions, exceptions, expiry, issuer role, and
accreditation status. A valid signature authenticates that statement; it does
not expand its scope.

## What is operational now

- `EP-ASSURANCE-PACKAGE-v1` and `ep-assure` package a decision population and
  independently recompute each reliance verdict under auditor-pinned inputs.
- `EP-EXTERNAL-VERIFICATION-STATEMENT-v1` lets an outside verifier sign the
  exact procedure, input digests, result, and limitations under a relying-party
  pinned key.
- Gate report modules produce deterministic auditor workpapers and underwriter
  packages while leaving conclusions and opinions null by construction.
- CF-1 and EG-1 provide executable conformance checks. They are technical
  self-tests unless an identified outside party witnesses and signs the run.

These are sellable assurance inputs and managed services. They are not an
operating certification programme.

## What must exist before certification is real

1. A signed, versioned conformance-record format and a `conformance:record` command in the
   verifier that emits it.
2. The assessor registry object, schema, and offline resolver (reuse the authority-registry
   machinery).
3. The `EP-CONFORMANT` mark object and its verifier.
4. At least one independent assessor other than the steward, so the registry is not a
   single-party list, plus documented evaluation, review, decision, surveillance,
   complaints, appeals, suspension, and withdrawal procedures.

Until those controls exist and an independent body has accepted the applicable
scope, public language must say `conformance test`, `deployment assessment`,
`verification`, or `assurance package` as applicable, never `certified`.
