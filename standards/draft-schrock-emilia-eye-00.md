# Verifiable, Scope-Bound Advisories for Authorization Posture (EMILIA Eye)
## draft-schrock-emilia-eye-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                              28 June 2026
Expires: 30 December 2026
```

### Abstract

This document defines the EMILIA Eye advisory: a scope-bound statement
that an authorization posture for a named scope has changed (designed to
be signed and offline-verifiable; the signing layer is specified here
but is not yet present in the reference implementation, see Section
13.6), carrying a scope-binding hash that prevents the
advisory from being replayed or re-targeted to a different scope. An Eye
advisory expresses an observation-derived posture (clear, caution,
elevated, or review_required) and a recommended action (none, log,
step_up_auth, require_signoff, or escalate). The central safety
invariant of this document is normative: an advisory MUST NEVER be the
sole gate on an action. A signal may only TIGHTEN posture — it may cause an
enforcement point to demand stronger authentication, human signoff, or
escalation — but it can never itself constitute the authorization. Eye
warns; an enforcement point verifies; an accountable human owns the
decision.

This work specifies the verifiability, scope-binding, and fail-safe
advisory semantics that signal-transport frameworks leave undefined. It
is a COMPOSABLE PROFILE: Eye advisories are carried as Security Event
Token [RFC8417] payloads and MAY be transported over the OpenID Shared
Signals Framework with Continuous Access Evaluation Profile (CAEP)
events. It is complementary to, not a replacement for, SSF/CAEP (which
define signal shape and transport, not verifiable bound fail-safe
advisory semantics), and it composes with the EP authorization receipt
[draft-schrock-ep-authorization-receipts], which remains the artifact
that actually authorizes an action. This document is experimental.

### Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79. Internet-Drafts are working documents
of the IETF. This document is an individual submission and has no
formal standing in the IETF standards process.

---

## 1. Introduction

Authorization decisions are made at a moment in time, but the conditions
that justified a decision change continuously. A device becomes
non-compliant; a credential is reported phished; an anomaly-detection
system observes impossible travel; a regulator publishes a sanctions
update. Continuous access evaluation frameworks exist precisely to
communicate such changes as they happen. What those frameworks
deliberately do not define is (a) whether the recipient can verify,
offline and without trusting the transmitter's live infrastructure, that
a given signal genuinely originated from a trusted source; (b) how a
signal is bound to one specific scope so it cannot be replayed against a
different subject; and (c) what a recipient is permitted to *do* with a
signal — in particular, whether a signal may, on its own, grant or deny
access.

This document closes those three gaps for the narrow but
high-consequence case of authorization posture. It does so without
reinventing the envelope or the transport. Eye advisories reuse the
Security Event Token [RFC8417] as their wire envelope and MAY ride
existing CAEP streams [CAEP] [SSF]. The contribution is three properties
layered on top: signed offline verifiability, cryptographic scope
binding, and a normative fail-safe rule that an advisory may only
tighten posture and may never be the sole gate.

The gaps this document closes:

1. **The verifiability gap.** A posture change delivered as plain JSON
   over an authenticated channel is only as trustworthy as the channel
   and the live database behind it. A relying party that caches,
   forwards, or audits the signal later cannot reconfirm its origin
   without re-querying the source. Eye signs the advisory so any holder
   of the issuer's public key can verify it offline, mirroring the
   offline-verifiability property of the EP authorization receipt.

2. **The scope-binding gap.** A signal that says "elevated risk" with a
   loosely attached subject reference can be copied and presented
   against a different subject. Eye binds each advisory to one scope via
   a scope-binding hash carried inside the signed payload, so
   re-targeting invalidates the signature.

3. **The authority gap.** Frameworks that carry session and posture
   events leave entirely to the consumer what to do with them, including
   the option of treating a signal as an autonomous enforcement trigger.
   Eye forbids that. An advisory is an input to a decision, never the
   decision.

### 1.1. Design Goals

- **G1 — Signed offline verifiability.** An Eye advisory MUST be
  verifiable by any party holding the issuer's public key, with no
  network access to the Eye service, mirroring the offline-verifiability
  property of the EP authorization receipt (Section 6.2.1).
- **G2 — Scope binding.** An advisory MUST carry a scope-binding hash
  inside its signed payload so it cannot be replayed against, or
  re-targeted to, a scope other than the one it was issued for
  (Section 5).
- **G3 — Never the sole gate.** An advisory MUST NOT be the sole gate
  between an entity and an action. A signal MAY only tighten posture; it
  MUST NOT itself constitute the authorization (Section 3). This is the
  central invariant of this specification.
- **G4 — Deterministic posture mapping.** The mapping from advisory
  status to recommended action to a posture change at the enforcement
  point MUST be deterministic and specified, so two conformant
  enforcement points consuming the same advisory tighten posture
  identically (Section 8).
- **G5 — Compose, do not reinvent.** Eye advisories MUST be expressible
  as a Security Event Token [RFC8417] payload, and SSF/CAEP transport is
  OPTIONAL. Eye defines the verifiable, bound, fail-safe layer; it does
  not define a new event envelope or a new delivery protocol
  (Section 10, Section 12).
- **G6 — Append-only honesty.** Advisories and their underlying
  observations are append-only; a status change is a new advisory that
  supersedes its predecessor, never a mutation of an existing one
  (Section 9).

### 1.2. Scope

This document defines the advisory artifact, its scope binding, its
signature, the observation signal registry, and the deterministic
status-to-posture mapping that bridges into an enforcement point. It
does not define a policy language, an anomaly-detection method, the
transport stream's management and verification (which SSF provides), or
the authorization artifact itself (which the EP authorization receipt
provides). Eye produces advice; it never produces an authorization.

Implementation status is honestly noted in Section 13.6: the signing,
SET-envelope, and CAEP-transport layers specified here are experimental
and not yet present in the reference implementation, which currently
computes scope-binding hashes but does not asymmetrically sign
advisories.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"MAY" are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

**Eye / Eye Service.** The service that ingests observations from
trusted sources and issues advisories. The Eye service is an
advice-producing party; under this protocol it is never an authorizing
party.

**Observation.** A single, source-attributed, scope-bound signal that
some condition relevant to authorization posture has been detected
(e.g., a device became non-compliant). Observations are the inputs from
which advisories are derived (Section 4).

**Signal Code.** A registered identifier naming the kind of an
observation (Section 7). Signal codes are the vocabulary in which
sources speak to Eye.

**Advisory.** The terminal Eye artifact: a scope-bound statement (signed in the Eye-Verifiable class; see Section 13.6)
of posture (status) and recommendation (recommended_action) for one
scope, derived from one or more contributing observations (Section 6).

**Scope.** The object an advisory is about, identified by a scope_type
(entity, action, resource, or environment) and a scope_ref. An advisory
speaks only about its scope.

**Scope-Binding Hash.** A SHA-256 digest over the canonical scope
identity, carried inside the signed advisory, that binds the advisory to
exactly one scope (Section 5).

**Enforcement Point.** The component that consumes an advisory and may
tighten authorization posture in response — for example, by raising the
required authentication level or demanding human signoff. In the EP
family this is the verifying executor of the EP authorization receipt
[draft-schrock-ep-authorization-receipts]. The enforcement point — not
Eye — owns the decision.

**Posture.** The strength of the checks an enforcement point applies to
a prospective action. Tightening posture means requiring more (stronger
auth, signoff, escalation); it never means granting access that policy
would otherwise deny.

## 3. The Fail-Safe Invariant: An Advisory Is Never the Sole Gate

This is the architectural invariant that governs every other design
choice in this document. It is stated first, before the wire format,
because the wire format exists to serve it.

**Eye warns. The enforcement point verifies. An accountable human
owns.** An Eye advisory MUST NOT be the sole gate between an entity and
an action. If an advisory is ever the only thing standing between an
entity and an action, the integration is non-conformant with this
specification.

Two corollaries make the invariant precise and testable:

1. **Tighten-only (one-directional).** A signal MAY only cause an
   enforcement point to demand *more* than it otherwise would (stronger
   authentication, human signoff, escalation, or a hard stop pending
   review). A signal MUST NOT cause an enforcement point to demand
   *less*, and a "clear" advisory MUST NOT be treated as an
   authorization, an approval, or a grant. The absence of a warning is
   not a permission.

2. **Necessary-not-sufficient.** An action that the underlying
   authorization policy would deny MUST remain denied regardless of any
   advisory. An advisory can subtract nothing from the set of conditions
   an action must satisfy; it can only add conditions. The authorization
   decision is owned by the enforcement point and, where the policy
   requires it, an accountable human (the EP signoff); the advisory is
   one input among those the decision considers.

Rationale. Signals are derived from heuristics, third-party feeds, and
detectors that fail in both directions. A false negative (no signal)
must never be readable as an affirmative grant, and a feed outage must
never widen access. Confining advisories to a tighten-only role means
the worst an advisory error can do is over-restrict — a fail-safe,
recoverable outcome — never over-authorize. A conformant enforcement
point that receives no advisory, an expired advisory, or an unverifiable
advisory MUST behave as though posture were unchanged by Eye and fall
back to its baseline policy; it MUST NOT fail open.

## 4. The Observation

An observation is a single source-attributed signal about one scope. It
is the input to advisory derivation and is itself scope-bound.

```json
{
  "ep_version": "1.0",
  "observation_id": "ep:eye:obs:01J...",
  "source_id": "ep:source:edr-crowdstrike",
  "source_type": "infrastructure",
  "scope_type": "entity",
  "scope_ref": "ep:entity:agent-recon-7",
  "scope_binding_hash": "sha256:7a3f...",
  "signal_code": "device.compliance.failed",
  "severity": "high",
  "evidence_ref": "ep:evidence:edr/8841",
  "detail": { "policy": "disk-encryption", "host": "wsx-12" },
  "observed_at": "2026-06-13T17:21:04Z",
  "expires_at": "2026-06-13T18:21:04Z",
  "created_at": "2026-06-13T17:21:05Z"
}
```

Rules:

- `source_id` MUST identify a source authenticated to the Eye service.
  `source_type` MUST be one of `internal`, `partner`, `regulatory`, or
  `infrastructure`.
- `signal_code` MUST be drawn from the signal registry (Section 7). An
  observation carrying an unregistered signal_code MUST NOT contribute
  to an advisory's posture; it MAY be logged.
- `severity` MUST be one of `info`, `low`, `medium`, `high`, or
  `critical`.
- `scope_binding_hash` MUST be computed as in Section 5 over this
  observation's `scope_type` and `scope_ref`.
- `expires_at` MUST be present. Observations are time-bounded inputs; an
  expired observation MUST NOT contribute to a newly issued advisory.

## 5. Scope Binding

Scope binding prevents an advisory (or observation) from being copied
and presented against a scope other than the one it was issued for. The
**scope-binding hash** is the SHA-256 digest of the JSON Canonicalization
Scheme [RFC8785] serialization of the scope identity object:

```json
{
  "ep_version": "1.0",
  "binding_type": "ep.eye.scope.v1",
  "scope_type": "entity",
  "scope_ref": "ep:entity:agent-recon-7"
}
```

Rules:

- The scope-binding hash MUST be carried inside the signed advisory
  payload (Section 6), so that altering either `scope_type` or
  `scope_ref` invalidates the signature.
- An enforcement point applying an advisory to a candidate action MUST
  recompute the scope-binding hash from the scope it is actually
  evaluating and MUST reject the advisory if the recomputed hash does
  not equal the advisory's `scope_binding_hash`. This is the check that
  defeats re-targeting.
- The scope-binding hash is a binding, not a secret: it commits to the
  scope but reveals only what the scope identity already reveals. Where
  `scope_ref` is sensitive, deployments MAY use a salted scope
  reference, provided the enforcement point can recompute it for the
  scope under evaluation.

## 6. The Advisory

An advisory is the scope-bound statement (signed in the Eye-Verifiable class; see Section 13.6) Eye issues for a scope.
It is the artifact a relying party verifies and an enforcement point
consumes.

### 6.1. Advisory Payload

```json
{
  "ep_version": "1.0",
  "advisory_type": "ep.eye.advisory.v1",
  "advisory_id": "ep:eye:adv:01J...",
  "issuer": "ep:eye:acme-primary",
  "scope_type": "entity",
  "scope_ref": "ep:entity:agent-recon-7",
  "scope_binding_hash": "sha256:7a3f...",
  "status": "elevated",
  "reason_codes": ["device.compliance.failed",
                   "auth.anomaly.impossible_travel"],
  "contributing_observations": ["ep:eye:obs:01J...",
                                "ep:eye:obs:02K..."],
  "recommended_action": "step_up_auth",
  "detail": { "highest_severity": "high" },
  "issued_at": "2026-06-13T17:21:06Z",
  "expires_at": "2026-06-13T17:36:06Z",
  "superseded_by": null
}
```

Rules:

- `status` MUST be one of `clear`, `caution`, `elevated`, or
  `review_required` (Section 8.1).
- `recommended_action` MUST be one of `none`, `log`, `step_up_auth`,
  `require_signoff`, or `escalate` (Section 8.2), and MUST be the value
  the deterministic mapping (Section 8) assigns to `status`.
- `reason_codes` MUST NOT be empty for any non-`clear` status. Each entry
  SHOULD be a registered `signal_code` drawn from the contributing
  observations.
- `contributing_observations` MUST list the `observation_id` of every
  observation that influenced `status`. For a `clear` advisory it MAY be
  empty.
- `scope_binding_hash` MUST equal the hash of this advisory's scope
  (Section 5).
- `expires_at` MUST be present. An enforcement point MUST treat an
  advisory whose `expires_at` is in the past as absent and fall back to
  baseline posture (Section 3); it MUST NOT infer a grant from expiry.

### 6.2. Advisory Signature and Offline Verification

The advisory is signed by the Eye operator's issuing key. The signed
document mirrors the structure of the EP authorization receipt's
evidence document so that the same verifier core can check both:

```json
{
  "@version": "EP-EYE-ADVISORY-v1",
  "payload": { "...": "Advisory Payload above" },
  "signature": {
    "algorithm": "Ed25519",
    "signer": "ep:eye:acme-primary",
    "key_id": "ep-eye-signing-key-1",
    "value": "b64u:..."
  }
}
```

The signature MUST be computed over the JCS [RFC8785] canonicalization
of the `payload` object, so that a verifier re-canonicalizes and
re-derives the exact bytes the signature covers. Ed25519 [RFC8032] is
the RECOMMENDED algorithm.

#### 6.2.1. Offline Verification Algorithm

A verifier with (the signed advisory, the issuer's trusted public key,
and the scope it is evaluating) and **no network access** MUST be able
to establish all of the following:

1. Verify the signature over `canonicalize(payload)` against the
   issuer's public key. The signer key MUST be pinned to a
   source-independent trust root, never trusted solely because it
   accompanied the advisory.
2. Recompute the scope-binding hash from the scope under evaluation;
   confirm it equals `payload.scope_binding_hash` (Section 5). A
   mismatch MUST cause rejection: the advisory is for a different scope.
3. Confirm that `recommended_action` is the value the deterministic
   mapping (Section 8) assigns to `status`; a divergent advisory MUST be
   rejected as malformed.
4. Confirm the current time is at or before `expires_at`. An expired
   advisory is treated as absent (Section 3).

As with the EP authorization receipt, offline verification establishes
authenticity and scope binding as of issuance, not currency. Two
properties are explicitly NOT established offline: (a) supersession — a
later advisory may have replaced this one via `superseded_by`, which a
cached holder cannot see; and (b) issuer-key revocation after issuance.
A relying party with freshness requirements MUST additionally consult
the Eye service or its published checkpoint online. Crucially, because
advisories are tighten-only (Section 3), a stale advisory can only
over-restrict, never over-authorize; the offline guarantee is therefore
fail-safe. Implementations MUST NOT describe offline verification as
establishing that an advisory is "currently the latest."

## 7. The Signal Registry

The signal registry is the controlled vocabulary of observation signal
codes. Each entry names a detectable condition, the `scope_type` it
applies to, and the maximum status it MAY justify. The registry below is
the experimental starting set; it is expected to grow. A deployment MAY
register additional codes in a private namespace (prefix `x-`) but MUST
NOT redefine a registered code.

| signal_code | scope | meaning | max |
|---|---|---|---|
| `device.compliance.failed` | entity | endpoint posture check failed | elev. |
| `credential.phish.reported` | entity | credential reported phished | review |
| `auth.anomaly.impossible_travel` | entity | geographically impossible logins | elev. |
| `session.assurance.downgraded` | entity | assurance dropped mid-session | elev. |
| `resource.sensitivity.raised` | resource | resource reclassified higher | caut. |
| `action.velocity.anomaly` | action | rate/pattern deviates baseline | elev. |
| `counterparty.sanctions.hit` | action | counterparty on sanctions list | review |
| `environment.threat.elevated` | env. | environment threat level raised | caut. |

The "max" column abbreviates the maximum status a single signal of that
code may justify (caut. = caution, elev. = elevated, review =
review_required). A "max status" caps how far a single signal of that
code may move posture; it does not floor it. Eye derives an advisory's
`status` from the contributing observations by taking the highest status
any non-expired contributing observation justifies, bounded by each
signal's max status. The full derivation is deployment policy and out of
scope; what is normative is that the resulting `status` deterministically
yields `recommended_action` per Section 8.

## 8. Deterministic Status-to-Posture Mapping

This section is the bridge from an Eye advisory into an enforcement point
— and, in the EP family, into EP verification. The mapping is normative
and deterministic: every conformant enforcement point consuming the same
advisory MUST tighten posture identically.

### 8.1. Status Semantics

- **clear.** No active observations; no signals of concern. *Not* an
  authorization — see Section 3.
- **caution.** Low-severity observations exist; context has changed but
  does not suggest immediate risk.
- **elevated.** Medium-to-high severity observations exist; context
  suggests increased risk warranting additional verification.
- **review_required.** Critical observations exist; context suggests the
  action should not proceed without explicit human review.

### 8.2. Recommended Action Semantics

- **none.** No additional action required by Eye.
- **log.** The enforcement point may record the advisory.
- **step_up_auth.** Raise the required authentication level for the
  action.
- **require_signoff.** Require accountable human signoff before the
  action proceeds.
- **escalate.** Escalate for manual review or handling; the action does
  not proceed on Eye's recommendation alone.

### 8.3. The Mapping

| advisory.status | recommended_action | Posture change at the enforcement point |
|---|---|---|
| `clear` | `none` | No change. Baseline policy applies unchanged. NOT a grant. |
| `caution` | `log` | Record the advisory; baseline policy otherwise unchanged. |
| `elevated` | `step_up_auth` | Require stronger authentication than baseline before proceeding. |
| `review_required` | `require_signoff` or `escalate` | Require accountable human signoff, or escalate; never proceed on Eye alone. |

Every entry in the "posture change" column is monotonic in the
tightening direction (Section 3): each named change adds a requirement
and removes none.

### 8.4. Bridge into the Enforcement-Point Profile and EP Verification

In an EP deployment, the enforcement point is the verifying executor of
the EP authorization receipt
[draft-schrock-ep-authorization-receipts]. The advisory tightens, but
never replaces, EP verification:

- On `step_up_auth`, the enforcement point SHOULD require an EP signoff
  key class corresponding to stronger assurance (e.g., a device-bound
  WebAuthn key) for the action's required approvals, raising the bar
  above the policy baseline.
- On `require_signoff`, the enforcement point MUST require a valid EP
  authorization receipt with accountable human signoff before the action
  executes, even if the baseline policy would not otherwise have
  required one. The advisory adds the signoff requirement; the EP
  receipt — not the advisory — authorizes the action.
- On `escalate`, the enforcement point MUST NOT allow the action to
  proceed on the advisory alone; it routes the action to human review,
  whose outcome (if it proceeds) is itself an EP signoff.

In every case the EP authorization receipt remains the artifact that
authorizes; the advisory only determines how high the bar is set. An
enforcement point MUST NOT synthesize, or treat the advisory as, an EP
authorization receipt (Section 3).

## 9. Advisory Lifecycle and Supersession

Advisories and observations are append-only. A posture change for a
scope is expressed by issuing a new advisory and setting the prior
advisory's `superseded_by` to the new `advisory_id`; an existing
advisory's signed payload is never mutated. Because the signed payload is
immutable, the superseding link is metadata visible only to a party
querying the Eye service online; an offline holder sees only the advisory
it holds, which is sound because tighten-only semantics make a stale
advisory fail-safe (Section 6.2.1). Deployments SHOULD keep advisory
`expires_at` windows short to bound the staleness an offline holder can
carry.

## 10. Composition: SET Envelope and Optional SSF/CAEP Transport

Eye does not define a new event envelope or a new delivery protocol. It
composes over existing standards and adds only the verifiability,
scope-binding, and fail-safe semantics those standards leave undefined.

### 10.1. Security Event Token Envelope

An Eye advisory MUST be expressible as a Security Event Token [RFC8417].
The signed advisory document (Section 6.2) is carried as the
event-specific payload of a SET event whose event-type URI is
`https://schemas.emiliaprotocol.ai/eye/advisory`:

```json
{
  "iss": "https://eye.acme.example",
  "iat": 1781000466,
  "jti": "ep:eye:adv:01J...",
  "aud": "https://ep.acme.example",
  "sub_id": { "format": "opaque", "id": "ep:entity:agent-recon-7" },
  "events": {
    "https://schemas.emiliaprotocol.ai/eye/advisory": {
      "@version": "EP-EYE-ADVISORY-v1",
      "payload": { "...": "Advisory Payload" },
      "signature": { "...": "advisory signature" }
    }
  }
}
```

The SET's own JWT-level protections (and any JWS signature over the SET)
are complementary to, and do not replace, the advisory's embedded
signature. The embedded signature is what survives re-transmission and
caching and provides the offline verifiability of Section 6.2.1; the SET
envelope provides standards-aligned event framing. Per [RFC8417], the
SET does not define how the event is delivered.

### 10.2. Optional SSF/CAEP Transport

Eye advisories MAY be transported over the OpenID Shared Signals
Framework [SSF] as SET-formatted events on a stream between an Eye
service (Transmitter) and an enforcement point (Receiver), alongside
Continuous Access Evaluation Profile [CAEP] events. CAEP defines event
types describing session and posture changes; Eye does not duplicate
them. Where a CAEP event (e.g., a device compliance change) is the
upstream cause of an observation, the observation's `evidence_ref` MAY
reference that CAEP event.

SSF/CAEP define the shape and transport of signals. They do not define
whether a signal is verifiable offline, how it is bound to a scope, or
what a recipient may do with it — in particular, they do not forbid
treating a signal as an autonomous enforcement trigger. Eye supplies
exactly those missing properties and is therefore the verifiable, bound,
fail-safe advisory layer on top of SSF/CAEP, **not** a competitor to
them. A deployment that uses SSF/CAEP transport MUST still enforce the
fail-safe invariant (Section 3) and scope-binding check (Section 5) on
every advisory it receives.

## 11. Conformance Classes

Honesty about deployment topology is a protocol feature, as in the EP
authorization receipt. An implementation MUST declare its class, and
claims MUST NOT state a stronger class than deployed.

**Eye-Verifiable (STRONG).** Advisories are asymmetrically signed
(Section 6.2) and verifiable offline; enforcement points perform the
full offline verification algorithm and enforce both the scope-binding
check and the fail-safe invariant.

**Eye-Bound (STANDARD).** Advisories carry and enforce the scope-binding
hash and the fail-safe invariant, but are not asymmetrically signed;
integrity rests on transport authentication and the out-of-band-known
hash. This matches the current reference implementation (Section 13.6).

**Eye-Advisory Only (BASIC).** Advisories are consumed as policy input
with the fail-safe invariant enforced, but without offline verification
or scope-binding enforcement. No verifiability claim is made.

The fail-safe invariant (Section 3) is REQUIRED of every conformance
class, including BASIC. It is the one property an Eye deployment may
never omit.

## 12. Relationship to Other Work

**Security Event Token [RFC8417]** defines the JWT-based event envelope
Eye reuses as its wire container. Eye adds verifiable, scope-bound,
fail-safe advisory semantics inside that envelope; it does not define a
new envelope.

**OpenID SSF / CAEP [SSF] [CAEP]** define asynchronous SET delivery and
a fixed set of session/posture event types. They standardize the shape
and transport of signals but deliberately leave undefined the verifiable
scope-bound advisory and the "never the sole gate" invariant. Eye
supplies those and rides SSF/CAEP as OPTIONAL transport — complementary,
not competing.

**EP authorization receipt [draft-schrock-ep-authorization-receipts]**
is the artifact that actually authorizes an action, binding an
accountable human signoff to one exact action and verifiable offline.
Eye composes with it: an advisory tightens the bar an EP receipt must
clear (Section 8.4) but never substitutes for the receipt. Eye warns;
the EP receipt authorizes.

**AuthZEN and policy engines (OPA, Cedar).** Authorization-decision
semantics live in a policy decision point consulted by a policy
enforcement point. Eye does not define a policy language; an Eye-aware
enforcement point acts as (or alongside) a policy enforcement point and
treats the advisory as additional context that can only tighten the
decision, never as the decision itself.

## 13. Security Considerations

**13.1. Fail-safe, never fail-open.** The defining risk this document
guards against is an advisory being read as a permission. The fail-safe
invariant (Section 3) is the mitigation, stated as a normative MUST: a
missing, expired, unverifiable, or `clear` advisory MUST leave baseline
policy in force and MUST NOT be treated as a grant. An implementation
that lets an Eye outage widen access has inverted the protocol's central
guarantee. Because advisories are tighten-only, every other failure mode
in this section degrades toward over-restriction, which is recoverable,
rather than toward over-authorization, which is not.

**13.2. False and adversarial signals.** A source may emit a false
observation — through error, feed poisoning, or compromise of the
source. Under tighten-only semantics the worst direct effect is denial
of service by over-restriction (spurious step-up or signoff), not
unauthorized access. Deployments SHOULD rate-limit and reputation-weight
sources, SHOULD bound how far any single signal_code can move posture
(the registry's max status, Section 7), and SHOULD NOT let a single
source unilaterally reach `review_required` for high-value scopes without
corroboration. An adversary who can *suppress* true signals gains only
the absence of tightening, which — by the fail-safe invariant — returns
the system to its baseline policy, not to an open state.

**13.3. Scope replay and re-targeting.** Without scope binding, an
advisory observed for one scope could be replayed against another. The
scope-binding hash (Section 5), carried inside the signed payload and
recomputed by the enforcement point against the scope it is actually
evaluating, defeats this: a re-targeted advisory fails the hash
comparison. Note that re-targeting an advisory can only ever *add*
tightening to the wrong scope (a fail-safe denial), never authorize it;
scope binding nonetheless MUST be enforced to prevent denial-of-service
by misdirected advisories.

**13.4. Issuer-key trust and pinning.** Offline verification
(Section 6.2.1) is only as sound as the trust root for the issuer's key.
A verifier MUST pin the issuer key to a source-independent trust root and
MUST NOT trust a key solely because it accompanied the advisory or
arrived over the same channel. Issuer-key revocation after issuance is
not detectable offline; a relying party with revocation requirements
MUST consult a current issuer-key checkpoint online. As elsewhere, the
tighten-only property bounds the damage: a forged advisory from an
untrusted key, if (wrongly) accepted, can only over-restrict.

**13.5. Staleness and supersession.** An offline holder cannot observe
that a newer advisory has superseded the one it holds (Section 9). For a
`clear` or low advisory this could mean acting on a posture milder than
the current truth — but because a missing or milder advisory only fails
to tighten (it never grants), the enforcement point's baseline policy
still applies. Relying parties that require currency MUST query online
and SHOULD keep `expires_at` windows short (Section 9). Implementations
MUST NOT describe a cached advisory as the authoritative current posture.

**13.6. Implementation status and what is not yet built.** This is an
experimental specification. The reference implementation currently
computes scope-binding and advisory hashes over canonical fields and
enforces append-only storage and the fail-safe invariant, but it does
*not* yet asymmetrically sign advisories, does not yet emit the SET
envelope (Section 10), and does not yet transport over SSF/CAEP. In the
conformance terms of Section 11, the current implementation is Eye-Bound
(STANDARD), not Eye-Verifiable (STRONG). The signing, SET-envelope, and
CAEP-transport sections describe target behavior, not deployed behavior,
and are marked experimental accordingly. No claim of production
deployment, adoption, or third-party relying-party use is made.

**13.7. What Eye does and does not decide.** Eye contributes context to
an authorization decision; it never makes one. The strongest accurate
claim is: "an Eye advisory can cause an action to require more before it
proceeds." It cannot cause an action to require less, and it cannot, by
itself, cause an action to proceed. Implementations MUST NOT represent
Eye as an access-control system, an authorization service, or a gate; it
is an advisory layer whose role is fixed by Section 3.

## 14. IANA Considerations

This document has no IANA actions. A future version may register the SET
event-type URI `https://schemas.emiliaprotocol.ai/eye/advisory` and the
`application/ep-eye-advisory+json` media type.

## 15. References

[RFC2119] Bradner, S., "Key words for use in RFCs", BCP 14.
[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase", BCP 14.
[RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)".
[RFC8417] Hunt, P., et al., "Security Event Token (SET)".
[RFC8032] Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature
   Algorithm (EdDSA)".
[SSF] OpenID Foundation, "OpenID Shared Signals Framework 1.0".
[CAEP] OpenID Foundation, "OpenID Continuous Access Evaluation Profile
   1.0".
[draft-schrock-ep-authorization-receipts] Schrock, I., "Authorization
   Receipts for High-Risk Agent Actions", individual Internet-Draft
   (work in progress).

## Author's Address

Iman Schrock
EMILIA Protocol, Inc.
United States
Email: team@emiliaprotocol.ai
