# Authorization Receipts for High-Risk Agent Actions (EP)
## draft-schrock-ep-authorization-receipts-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               9 June 2026
Expires: 11 December 2026
```

### Abstract

This document defines the EMILIA Protocol (EP) authorization receipt, a
cryptographic primitive that binds a named, accountable human approver
to one exact high-risk action before that action executes. An approver
holding their own signing key produces a signature over a canonical
Authorization Context containing the action hash, policy reference,
one-time nonce, and validity window. The resulting Trust Receipt is
Merkle-anchored and verifiable fully offline: a relying party can
confirm that a specific action was approved by an authorized human,
exactly once, without network access to any EP operator, log, or API.
The protocol additionally enforces separation of duties (an initiator
MUST NOT approve its own action) and one-time consumption (an
authorization, once consumed or refused, is terminally unusable). These
invariants are machine-checked in published TLA+ and Alloy models.

EP addresses organizational authorization of agent actions
(approver-to-action trust). It is complementary to, not a replacement
for, user-to-operator delegation work
[draft-nelson-agent-delegation-receipts], service-to-service identity
(WIMSE), and authentication-layer approval (CIBA [CIBA]).

### Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79. Internet-Drafts are working documents
of the IETF. This document is an individual submission and has no
formal standing in the IETF standards process.

---

## 1. Introduction

Agentic AI systems increasingly hold credentials sufficient to perform
irreversible operations: releasing payments, modifying beneficiary
records, rotating production credentials, deleting data. Existing
controls answer the question "is this actor authenticated and
authorized in general?" They do not answer the question that matters at
the moment of execution: "should this exact action happen, and which
accountable human said yes?"

Three structural gaps follow:

1. **The action gap.** Identity and access management authorizes
   *sessions and scopes*, not individual actions. Fraud that occurs
   inside a valid session through approved channels (e.g., business
   email compromise leading to a beneficiary change) is invisible to
   session-level controls.

2. **The accountability gap.** Where human approval exists, it is
   typically a click in a workflow tool, recorded in a mutable
   application database controlled by the operator of the approval
   system. There is no independent cryptographic evidence binding a
   specific human to a specific action.

3. **The verification gap.** Auditors, counterparties, and regulators
   must trust the operator's logs — produced by the party whose conduct
   is under examination. No artifact exists that a third party can
   verify with mathematics alone.

EP closes these gaps with a small protocol: before an irreversible
action executes, a named approver signs the exact action with a key
only the approver holds; the signed authorization is consumed exactly
once; and the resulting receipt is independently verifiable offline,
forever.

### 1.1. Design Goals

- **G1 — Action binding.** An approval is cryptographically bound to
  one exact action. It cannot authorize anything else.
- **G2 — Approver-held keys.** The approver's signature is produced by
  a key the EP operator does not possess. The operator orchestrates;
  it cannot forge.
- **G3 — One-time consumption.** An authorization is consumed at most
  once, globally. Replay across sessions, operators, or time is
  detectable and MUST be rejected.
- **G4 — Separation of duties.** The initiator of an action MUST NOT
  be an approver of that action. Policies MAY require m-of-n distinct
  approvers.
- **G5 — Offline verifiability.** A receipt is verifiable with no
  network access, using only the receipt, the approver's public key
  material, and a published log checkpoint. Offline verification
  establishes authenticity and log inclusion as of commit time, not
  current revocation status (Section 6.3).
- **G6 — Execution-side enforcement.** The strongest deployment places
  verification at the system of record: the executing service verifies
  the receipt before performing the action. Middleware-only deployments
  are explicitly defined as a weaker conformance class (Section 9).
- **G7 — Machine-checked safety.** The protocol state machine's safety
  properties are maintained as formal models (TLA+, Alloy) and checked
  in continuous integration. Implementations can be tested against a
  published conformance suite.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"MAY" are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

**Initiator.** The entity (typically an AI agent or automated process)
that proposes a high-risk action. The initiator is identified but never
trusted with approval authority over its own actions.

**Approver.** A named human (or, for lower assurance classes, an
organizational role occupied by a named human at decision time) who
holds approval authority under policy. The approver controls a private
signing key; see Section 5.

**Action.** A single proposed operation with concrete parameters
(e.g., one wire transfer to one beneficiary for one amount). Actions
are represented by an Action Object and identified by their action
hash (Section 3).

**Policy.** A named, versioned rule set determining, for a class of
actions, which approvers are required (including m-of-n thresholds),
validity windows, and amount or scope limits.

**Authorization Context.** The canonical structure an approver signs:
action hash, policy reference, initiator identity, nonce, expiry, and
chain binding (Section 4).

**Trust Receipt.** The terminal artifact: the Action Object digest, all
approver signatures, the consumption record, and a Merkle inclusion
proof against a signed log checkpoint (Section 6).

**Verifying Executor.** A system of record that verifies a Trust
Receipt (or a pre-execution Authorization Bundle) before performing
the action. See Section 9.

**EP Operator.** The party running the orchestration service (policy
registry, signoff routing, log). Under this protocol the operator is
*not* in the signing trust path for approvals (G2).

## 3. The Action Object and Action Hash

An Action Object is a JSON document with at minimum:

```json
{
  "ep_version": "1.0",
  "action_type": "wire.release",
  "target": { "system": "treasury.example", "resource": "wire/8841" },
  "parameters": { "amount": "2400000.00", "currency": "USD",
                   "beneficiary_account_hash": "sha256:..." },
  "initiator": "ep:entity:agent-recon-7",
  "policy_id": "ep:policy:wires-over-100k@v12",
  "requested_at": "2026-06-09T17:21:04Z"
}
```

The Action Object MUST be serialized using JSON Canonicalization Scheme
(JCS) [RFC8785]. The **action hash** is the SHA-256 digest of the
canonical serialization. Implementations MUST reject approval requests
whose action hash does not match a locally recomputed hash of the
presented Action Object. Sensitive parameter values MAY be carried as
salted hashes (as `beneficiary_account_hash` above) provided the
executing system can recompute them; the binding property is preserved
because the hash commits to the committed values.

## 4. The Authorization Context

For each required approver, the orchestrator constructs an
Authorization Context:

```json
{
  "ep_version": "1.0",
  "context_type": "ep.signoff.v1",
  "action_hash": "sha256:9f2c...",
  "policy_id": "ep:policy:wires-over-100k@v12",
  "policy_hash": "sha256:77ab...",
  "initiator": "ep:entity:agent-recon-7",
  "approver": "ep:approver:jchen-controller",
  "approver_index": 1,
  "required_approvals": 2,
  "nonce": "b64u:R9w1...",
  "issued_at": "2026-06-09T17:21:05Z",
  "expires_at": "2026-06-09T17:36:05Z",
  "prev_receipt_hash": "sha256:51d0..."
}
```

Rules:

- `nonce` MUST be at least 128 bits of CSPRNG output and MUST be
  globally unique per authorization attempt. It is the consumption key
  for G3.
- `policy_hash` commits to the exact policy version evaluated. A
  signature over a context with policy_hash X MUST NOT satisfy a
  requirement evaluated under policy_hash Y, even for the same
  policy_id.
- `prev_receipt_hash` chains this authorization to the issuing log's
  most recent receipt, contributing to tamper evidence.
- The context is JCS-canonicalized; the **context hash** is its
  SHA-256 digest. The approver signs the context hash.
- The approver MUST be shown, at signing time, a faithful human-readable
  rendering of the Action Object — not only the hash. Signing
  interfaces that display a different action than the one hashed are a
  presentation attack; see Section 11.3.

## 5. Approver Keys and the Signoff Signature

This section is the core upgrade over server-side approval systems.

### 5.1. Key Classes

**Class A — Device-bound keys (RECOMMENDED).** The approver's key is
generated and held in a platform authenticator or security key and
exercised via WebAuthn [WEBAUTHN]. The signature algorithm is ES256
(P-256) or Ed25519 where supported. The WebAuthn challenge MUST be the
context hash. The authenticator's user-verification flag (biometric or
PIN) MUST be required for signoff credentials. Attestation SHOULD be
captured at enrollment so relying parties can establish that the key is
hardware-bound.

**Class B — Software keys.** An Ed25519 keypair held in the approver's
client environment (CLI keychain, mobile secure enclave via app).
Acceptable where WebAuthn is impractical (headless approval terminals),
with the reduced assurance noted in receipts.

**Class C — Operator-custodied keys (LEGACY).** The EP operator signs
on the approver's behalf after authenticating them. This class exists
only to describe pre-existing deployments. Receipts produced under
Class C MUST be labeled `key_class: "C"` and relying parties SHOULD
treat them as evidence of operator assertion, not approver signature.
New deployments SHOULD NOT use Class C.

### 5.2. Enrollment and the Approver Directory

Approver public keys are enrolled into a signed Approver Directory
maintained per organization: a Merkle tree over
`(approver_id, public_key, key_class, valid_from, valid_to, roles)`
entries, with signed tree heads published alongside receipt log
checkpoints. A receipt's offline verifiability (G5) includes an
inclusion proof of the approver's key entry, so a verifier needs no
live directory access. Key rotation appends a new entry and terminates
the old one; signatures verify against the key entry valid at
`issued_at`.

Directory authority is a trust root and MUST NOT default to the EP
operator. The directory tree head MUST be signed by an
organization-controlled directory key (custody options parallel
Section 5.1; an organization-held hardware key is RECOMMENDED). Where
directory *operation* is delegated to the EP operator, every enrollment
entry MUST carry a second-party attestation — a signature over the new
entry by an organization administrator key or by a quorum of
already-enrolled approvers — and that attestation MUST be included in
the receipt's `approver_key_proofs`. Verifiers MUST treat a directory
head signed only by an operator-held key as operator assertion
(Class C-equivalent assurance), regardless of the key class of the
individual signoffs. Rationale: an operator that unilaterally controls
directory membership cannot forge an enrolled approver's signature, but
it can enroll a key it controls under a legitimate approver's name —
relocating the forgery rather than preventing it. See Section 11.6.

### 5.3. The Signoff

A signoff is:

```json
{
  "context_hash": "sha256:c41e...",
  "signature": "b64u:MEUCIQ...",
  "key_class": "A",
  "approver_key_id": "ep:key:jchen-controller#2026-01",
  "signed_at": "2026-06-09T17:24:40Z",
  "webauthn": { "authenticator_data": "b64u:...",
                 "client_data_json": "b64u:..." }
}
```

For Class A, verifiers MUST validate the WebAuthn assertion per
[WEBAUTHN] including that `clientDataJSON.challenge` equals the context
hash and that the user-verification bit is set. A denial is also signed
(over the context hash with a `decision: "denied"` envelope) so that
refusals are equally non-repudiable and equally terminal.

## 6. Consumption, Commitment, and the Trust Receipt

### 6.1. State Machine

An authorization attempt proceeds:

```
REQUESTED -> {PARTIALLY_APPROVED}* -> APPROVED -> COMMITTED
          \-> DENIED                          \-> EXPIRED
          \-> EXPIRED
```

COMMITTED, DENIED, and EXPIRED are terminal. The protocol invariants —
maintained as machine-checked models and REQUIRED of conforming
implementations — are:

- **ConsumeOnce.** A nonce transitions to a terminal state at most
  once, globally. Any second presentation MUST be rejected with a
  replay error.
- **BindingMatch.** A signoff satisfies only the context (and therefore
  only the action hash) it signs.
- **TerminalIrreversibility.** No transition exits a terminal state.
- **SelfApprovalImpossible.** For every signoff,
  `approver != initiator`; for m-of-n policies, approvers are pairwise
  distinct and each distinct from the initiator.
- **NoBypassWrite.** A COMMITTED state is reachable only through the
  full sequence; conforming verifying executors MUST NOT execute
  without verifying it (Section 9).

### 6.2. The Trust Receipt

Upon commitment the orchestrator assembles and logs the Trust Receipt:

```json
{
  "receipt_id": "ep:receipt:01J...",
  "action": { "...": "full Action Object" },
  "action_hash": "sha256:9f2c...",
  "contexts": [ { "...": "Authorization Context 1" }, { "..." : "..." } ],
  "signoffs": [ { "...": "Signoff 1" }, { "...": "Signoff 2" } ],
  "consumption": { "nonce": "b64u:R9w1...",
                    "state": "COMMITTED",
                    "committed_at": "2026-06-09T17:25:02Z" },
  "log_proof": { "leaf_index": 88412,
                  "inclusion_path": ["sha256:...", "..."],
                  "checkpoint": { "tree_size": 90210,
                                   "root_hash": "sha256:...",
                                   "log_signature": "b64u:...",
                                   "log_key_id": "ep:log:acme#1" } },
  "approver_key_proofs": [ { "directory_inclusion": "..." } ]
}
```

### 6.3. Offline Verification Algorithm

A verifier with (receipt, trusted log public key, trusted directory
root or pinned approver keys) and **no network access** MUST be able to
establish all of the following; the published verifier package performs
exactly these steps:

1. Recompute the action hash from the canonical Action Object; compare.
2. For each context: recompute the context hash; confirm it commits to
   the action hash, the policy hash, and a distinct approver.
3. For each signoff: verify the signature (and WebAuthn assertion where
   present) over the context hash against the approver key entry,
   checking the key's validity window contains `issued_at`.
4. Confirm SoD: initiator appears in no approver slot; approvers are
   pairwise distinct; the approval count satisfies
   `required_approvals`.
5. Verify the Merkle inclusion proof of the receipt leaf against the
   checkpoint root, and the checkpoint signature against the log key.
6. Confirm `signed_at` and `committed_at` fall within
   `[issued_at, expires_at]`.

Step 5 is what distinguishes EP receipts from log-access designs: the
checkpoint travels *inside* the receipt, so verification requires no
query to the log. Detecting log equivocation (split-view attacks)
additionally benefits from gossip or witness cosigning (Section 11.4),
which is an online activity; the offline guarantee is that *this
receipt is internally consistent, correctly signed by enrolled approver
keys, and was included in a log tree whose head the log operator
signed.*

Offline verification establishes authenticity, not currency. Two
properties are explicitly NOT established offline: (a) post-issuance
revocation — a receipt whose approver key was revoked an hour after
commitment still verifies; the artifact is evidence of validity *at
commit time*; and (b) log honesty against split views (Section 11.4).
A relying party with freshness or revocation requirements MUST
additionally consult a current directory head and log checkpoint
online. Implementations MUST NOT describe offline verification as
establishing that a receipt is "currently valid."

## 7. Multi-Approver Policies (m-of-n)

A policy MAY require k distinct approvers from a role set. Each
approver receives and signs an individual Authorization Context sharing
the same `action_hash` and `nonce` family but a distinct
`approver_index`. Commitment occurs only when k valid, distinct
signoffs exist before `expires_at`. Partial approval confers no
authority: a verifying executor presented with fewer than k signoffs
MUST refuse.

## 8. Delegation Constraints

Where an approver's authority is itself delegated, the delegation
record MUST be presented in the receipt's `approver_key_proofs`, and
the constraint **DelegateCannotExceedPrincipal** applies: the effective
scope of a delegate is the intersection of the delegation grant and the
principal's authority at signing time. Delegation chains are bounded
(RECOMMENDED depth ≤ 2) and every link is independently signed.

## 9. Conformance Classes and Execution-Side Enforcement

Honesty about deployment topology is a protocol feature. Three classes:

**EP-Verified Execution (STRONG).** The system of record (payment
switch, registry, deployment controller) verifies the Authorization
Bundle (receipt-less pre-execution form: action object, contexts,
signoffs, consumption attestation) before executing, and refuses
otherwise. The gate cannot be bypassed by any party that does not
control the system of record itself.

**EP-Gated Middleware (STANDARD).** An interception layer between the
agent and the executing credential enforces the gate. Provides strong
protection against agent error and prompt injection; an operator with
code control can bypass. Receipts remain valid evidence of what *was*
approved.

**EP-Evidence Only (BASIC).** Actions execute independently; receipts
are produced for audit. No enforcement claim is made.

Implementations MUST declare their class in receipts
(`enforcement_class`), and marketing or compliance claims MUST NOT
state a stronger class than deployed. This section exists because the
difference between "we proved the protocol" and "your deployment is
unbypassable" is the most common overclaim in this category.

## 10. Relationship to Other Work

**DRP [draft-nelson-agent-delegation-receipts]** binds a *user's*
delegation to an *operator's* instructions — upstream consumer
delegation. EP binds an *organizational approver* to an *exact action*
— downstream authorization with SoD and m-of-n, which DRP does not
formalize, and with offline verification, which DRP's log-access model
does not provide. The two compose: a DRP delegation can be referenced
in an EP Action Object's provenance field.

**CIBA [CIBA]** transports an authentication-time approval to a
backchannel device; it does not produce an action-bound, offline-
verifiable, one-time-consumable artifact. CIBA MAY serve as the
transport by which an approver is reached; the EP signoff is what they
produce when they get there.

**WIMSE / workload identity** authenticates the agent to services; EP
authorizes the action. Complementary layers.

**Receiver-attested logging (e.g., Sello)** has the receiving service
sign what it observed, post-hoc. EP is pre-execution authorization.
A complete deployment benefits from both: EP proves the action was
authorized; receiver attestation proves what then actually occurred.

## 11. Security Considerations

**11.1. Operator compromise.** Under key classes A/B, a compromised EP
operator can deny service and can fail to route signoff requests, and
it cannot *forge a signature*: it lacks approver keys, and it cannot
replay one (nonces are single-consumption and receipts chain). Two
operator-compromise paths remain and are stated plainly rather than
claimed away. First, an operator that controls the signing client's
rendering can harvest a *genuine* signature over an action the approver
misunderstood — a presentation attack (Section 11.3); for this reason
high-value policies REQUIRE an independently-authored rendering
surface. Second, an operator that unilaterally controls the Approver
Directory can enroll keys it controls (Sections 5.2, 11.6).
Accordingly, the accurate claim for classes A/B is: "the operator
cannot forge an approver's signature." The stronger claim — "the
operator cannot obtain an unauthorized approval" — additionally
requires the directory-authority and independent-rendering controls.
Under class C the operator can fabricate outright; hence the labeling
requirement.

**11.2. Approver device compromise.** A stolen authenticator with user
verification still requires the biometric/PIN. Organizations SHOULD
require key class A for high-value policies and SHOULD pair approval
with out-of-band action rendering (the approver sees the wire details
on a second surface).

**11.3. Presentation attacks.** The gravest risk in this protocol,
stated without minimization: the approver signs context hash H
believing it represents action X when it represents action Y. A
signature proves user presence and an act of approval toward *whatever
was rendered*; cryptography cannot prove the rendering was faithful.
Required mitigations, in increasing strength: (1) the signing client
MUST render the Action Object from the exact bytes that were hashed —
never from a separately supplied description; (2) for high-value
policies, render templates MUST be registered with the policy and
committed by `policy_hash`, so the display logic is part of what the
approver's signature covers; (3) for policies above an
organization-designated threshold, the material action parameters
(amount, beneficiary identifiers) MUST additionally be rendered on a
second surface not authored by the orchestrating operator — for
example, delivered by the verifying executor or an independent
operator to the approver's enrolled device over a separate channel.
The residual risk is stated honestly: absent a trusted display path
(hardware the operator does not author), rendering fidelity is
enforced by controls (2)–(3), by audit, and by consented mismatch
drills (Section 11.8) — not by mathematics. What the cryptography does
guarantee is exactness of evidence: the receipt contains the full
Action Object actually signed, so any divergence between what was
displayed and what was executed is detectable after the fact with
proof rather than testimony.

**11.4. Log equivocation.** A malicious log could show different trees
to different parties. Checkpoints SHOULD be witness-cosigned and/or
gossiped between independent EP operators; the federation profile makes
cross-operator checkpoint exchange mandatory.

**11.5. What the formal models do and do not prove.** The TLA+/Alloy
models prove safety of the authorization state machine: no replay, no
self-approval, no bypass *within the modeled system*, no partial
commitment. They prove nothing about any AI model's behavior, about
host compromise, or about deployments in a weaker conformance class.
Implementations MUST NOT represent the proofs as covering deployment
topologies they do not model. The models additionally do not yet cover
the WebAuthn challenge binding, the Approver Directory, log
checkpoints, or the m-of-n flow; those sections are specified, not
proven, and extending the models to them is tracked work.

**11.6. Directory authority.** Section 5 removes the operator from the
signature path; Section 5.2 must not readmit it as the authority that
decides which keys count. If the EP operator alone signs the Approver
Directory, a malicious operator can satisfy policy by enrolling a key
it controls under a nominally legitimate approver's name. The controls
in Section 5.2 (organization-held directory key; second-party
attestation on enrollment; Class C-equivalent treatment otherwise)
exist for this reason. Auditors SHOULD verify directory key custody as
part of any assessment that relies on receipts.

**11.7. What separation of duties does and does not provide.**
SelfApprovalImpossible (Section 6.1) defeats *unilateral*
self-approval: no initiator can approve its own action, and m-of-n
approvers are pairwise distinct identities. It does not defeat
collusion among distinct enrolled humans, one human who controls
multiple enrolled identities (an enrollment control — Section 5.2), or
a coerced approver. Receipts make such events *attributable* — named,
signed, and evidenced — which raises the cost of insider fraud; they
do not make it impossible, and implementations MUST NOT claim
otherwise.

**11.8. Approver fatigue.** A gate that humans route around protects
nothing; rubber-stamping is the empirical failure mode of every
human-in-the-loop control under volume. This protocol is therefore not
a general approval workflow: deployments MUST scope signoff policies
to genuinely high-risk, low-frequency actions and SHOULD handle volume
with policy (thresholds, allow-lists, velocity rules) rather than
human throughput. Operational countermeasures SHOULD include
monitoring time-to-sign distributions (signing latencies near the
floor indicate approval without review), tracking deny rates (a gate
that never denies is either perfectly upstream-filtered or
ceremonial), and consented render-mismatch drills that measure whether
approvers read what they sign. Such telemetry is deployment guidance,
not protocol; but the protocol's guarantees are only as strong as the
attention of the human at its center, and implementations SHOULD say
so to their customers.

## 12. IANA Considerations

This document has no IANA actions. A future version may register the
`application/ep-receipt+json` media type.

## 13. References

[RFC2119] Bradner, S., "Key words for use in RFCs", BCP 14.
[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase", BCP 14.
[RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)".
[CIBA] OpenID Foundation, "OpenID Connect Client-Initiated Backchannel
   Authentication Flow — Core 1.0".
[WEBAUTHN] W3C, "Web Authentication: An API for accessing Public Key
   Credentials, Level 2".
[draft-nelson-agent-delegation-receipts] Nelson, R., "Delegation
   Receipts for AI Agents", individual Internet-Draft (work in
   progress).

## Author's Address

Iman Schrock
EMILIA Protocol, Inc.
Glendale, California, USA
Email: team@emiliaprotocol.ai
