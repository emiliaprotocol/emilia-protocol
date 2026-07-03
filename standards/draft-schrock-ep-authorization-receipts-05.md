# Authorization Receipts for High-Risk Agent Actions
## draft-schrock-ep-authorization-receipts-05

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               2 July 2026
Expires: 3 January 2027


           Authorization Receipts for High-Risk Agent Actions
               draft-schrock-ep-authorization-receipts-05

Abstract

   This document defines the EMILIA Protocol (EP) authorization receipt,
   a cryptographic primitive that binds a named, accountable human
   approver to one exact high-risk action before that action executes.
   An approver holding their own signing key produces a signature over a
   canonical Authorization Context containing the action hash, policy
   reference, one-time nonce, and validity window.  The resulting Trust
   Receipt is Merkle-anchored and verifiable fully offline: a relying
   party can confirm that a specific action was approved by an
   authorized human, exactly once, without network access to any EP
   operator, log, or API.  The protocol additionally enforces separation
   of duties (an initiator must not approve its own action) and one-time
   consumption (an authorization, once consumed or refused, is
   terminally unusable).  These invariants are machine-checked in
   published TLA+ and Alloy models.

   EP addresses organizational authorization of agent actions (approver-
   to-action trust).  It is complementary to, not a replacement for,
   user-to-operator delegation work (draft-nelson-agent-delegation-
   receipts), service-to-service identity (WIMSE), and authentication-
   layer approval (CIBA).  EP is the human-authorization apex of the
   agent stack: it composes with, and does not replace, the agent
   identity, delegation, machine-policy, and transparency-log layers,
   supplying the named-human authorization evidence those layers
   reference but do not themselves produce.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.






Schrock                  Expires 3 January 2027                 [Page 1]

Internet-Draft          EP Authorization Receipts              July 2026


   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time.  It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as "work in progress."

   This Internet-Draft will expire on 3 January 2027.

Copyright Notice

   Copyright (c) 2026 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents (https://trustee.ietf.org/
   license-info) in effect on the date of publication of this document.
   Please review these documents carefully, as they describe your rights
   and restrictions with respect to this document.  Code Components
   extracted from this document must include Revised BSD License text as
   described in Section 4.e of the Trust Legal Provisions and are
   provided without warranty as described in the Revised BSD License.

Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   3
     1.1.  Design Goals  . . . . . . . . . . . . . . . . . . . . . .   5
     1.2.  Scope of Identity . . . . . . . . . . . . . . . . . . . .   6
   2.  Terminology . . . . . . . . . . . . . . . . . . . . . . . . .   6
   3.  The Action Object and Action Hash . . . . . . . . . . . . . .   7
   4.  The Authorization Context . . . . . . . . . . . . . . . . . .   7
     4.1.  Initiator Attestation (OPTIONAL)  . . . . . . . . . . . .   9
     4.2.  Agent Binding (OPTIONAL)  . . . . . . . . . . . . . . . .  11
   5.  Approver Keys and the Signoff Signature . . . . . . . . . . .  15
     5.1.  Key Classes . . . . . . . . . . . . . . . . . . . . . . .  15
     5.2.  Enrollment and the Approver Directory . . . . . . . . . .  15
     5.3.  The Signoff . . . . . . . . . . . . . . . . . . . . . . .  16
   6.  Consumption, Commitment, and the Trust Receipt  . . . . . . .  16
     6.1.  State Machine . . . . . . . . . . . . . . . . . . . . . .  17
     6.2.  The Trust Receipt . . . . . . . . . . . . . . . . . . . .  17
     6.3.  Offline Verification Algorithm  . . . . . . . . . . . . .  18
   7.  Multi-Approver Policies (m-of-n)  . . . . . . . . . . . . . .  19
   8.  Delegation Constraints  . . . . . . . . . . . . . . . . . . .  19
   9.  Conformance Classes and Execution-Side Enforcement  . . . . .  19
   10. Relationship to Other Work  . . . . . . . . . . . . . . . . .  20
   11. Security Considerations . . . . . . . . . . . . . . . . . . .  21
     11.1.  Operator Compromise  . . . . . . . . . . . . . . . . . .  21
     11.2.  Approver Device Compromise . . . . . . . . . . . . . . .  22
     11.3.  Presentation Attacks . . . . . . . . . . . . . . . . . .  22
     11.4.  Log Equivocation . . . . . . . . . . . . . . . . . . . .  22



Schrock                  Expires 3 January 2027                 [Page 2]

Internet-Draft          EP Authorization Receipts              July 2026


     11.5.  What the Formal Models Do and Do Not Prove . . . . . . .  22
     11.6.  Directory Authority  . . . . . . . . . . . . . . . . . .  23
     11.7.  What Separation of Duties Does and Does Not Provide  . .  23
     11.8.  Approver Fatigue . . . . . . . . . . . . . . . . . . . .  24
     11.9.  Initiator Attestation as an Attack Surface . . . . . . .  24
     11.10. No symmetric key on the verification trust path  . . . .  25
   12. IANA Considerations . . . . . . . . . . . . . . . . . . . . .  26
   13. Normative References  . . . . . . . . . . . . . . . . . . . .  26
   14. Informative References  . . . . . . . . . . . . . . . . . . .  26
   Appendix A.  Changes since -04  . . . . . . . . . . . . . . . . .  26
   Appendix B.  Changes since -00 (through -04)  . . . . . . . . . .  27
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .  28

1.  Introduction

   Agentic AI systems increasingly hold credentials sufficient to
   perform irreversible operations: releasing payments, modifying
   beneficiary records, rotating production credentials, deleting data.
   Existing controls answer the question "is this actor authenticated
   and authorized in general?"  They do not answer the question that
   matters at the moment of execution: "should this exact action happen,
   and which accountable human said yes?"

   Three structural gaps follow:

   1.  *The action gap.* Identity and access management authorizes
       _sessions and scopes_, not individual actions.  Fraud that occurs
       inside a valid session through approved channels (e.g., business
       email compromise leading to a beneficiary change) is invisible to
       session-level controls.

   2.  *The accountability gap.* Where human approval exists, it is
       typically a click in a workflow tool, recorded in a mutable
       application database controlled by the operator of the approval
       system.  There is no independent cryptographic evidence binding a
       specific human to a specific action.

   3.  *The verification gap.* Auditors, counterparties, and regulators
       must trust the operator's logs -- produced by the party whose
       conduct is under examination.  No artifact exists that a third
       party can verify with mathematics alone.

   EP closes these gaps with a small protocol: before an irreversible
   action executes, a named approver signs the exact action with a key
   only the approver holds; the signed authorization is consumed exactly
   once; and the resulting receipt is independently verifiable offline,
   forever.




Schrock                  Expires 3 January 2027                 [Page 3]

Internet-Draft          EP Authorization Receipts              July 2026


   Why existing mechanisms do not close this gap: each adjacent layer
   answers a different question, and none produces the artifact above.

   *  OAuth 2.0 with Rich Authorization Requests (RFC 9396) and GNAP
      (RFC 9635) authorize a client's _requested scope_; they do not
      produce a named human's offline-verifiable signature over the
      exact action that executed.

   *  The OAuth Step-Up Authentication Challenge (RFC 9470) can _demand_
      fresh human authentication for a sensitive operation, but yields
      no durable, portable artifact of that approval.

   *  Transaction Tokens (draft-ietf-oauth-transaction-tokens) propagate
      call context across workloads within a trust domain; they are
      short-lived, online-validated, and assert _workload_ identity, not
      a human's authorization of an action.

   *  The Security Event Token (RFC 8417) and CAEP convey, as issuer
      assertions, that an event _occurred_; they are not a human's pre-
      execution approval bound to one exact action.

   *  RATS (RFC 9334) and the Entity Attestation Token (RFC 9711) attest
      the trustworthiness of a _platform or workload_, not that a named
      human authorized an action -- a different trust root.

   *  SCITT (RFC 9943) provides an append-only transparency log and
      inclusion receipts, but is deliberately agnostic about _who
      authorized_ a statement -- which is precisely the question EP
      answers.

   *  The agent-action evidence work now emerging around that
      architecture -- per-action receipt envelopes, action capsules,
      post-execution profiles, pre-execution permits, and refusal events
      -- makes agent actions transparent, logged, and policy-checked;
      each of these profiles assumes, and none produces, the named-human
      authorization evidence itself.

   The emerging gap is therefore not lack of agent logs or action
   evidence.  It is lack of a portable human authorization artifact that
   can be verified independently of the operator, the agent runtime, and
   the transparency service.  EP is that narrow artifact, not a
   replacement for any of the above: it composes with them (Section 10)
   and can be carried in their formats -- for example, an EP receipt
   expressed as a COSE Signed Statement and logged by a SCITT
   Transparency Service, or referenced by digest from an action receipt,
   capsule, or permit.





Schrock                  Expires 3 January 2027                 [Page 4]

Internet-Draft          EP Authorization Receipts              July 2026


   The human-approval mechanism this document specifies -- a user-
   verification-gated signature over the exact Authorization Context
   (Section 5.1, Class A) -- is native to EP and self-contained.  It
   does not depend on, and is not a profile of, any other draft's
   acquiescence, consent, or confirmation mechanism; a conforming EP
   signoff is produced entirely by the controls defined here.  Where EP
   composes with adjacent work (Section 10), that composition is by
   reference, not dependency.

1.1.  Design Goals

   *  *G1 -- Action binding.* An approval is cryptographically bound to
      one exact action.  It cannot authorize anything else.

   *  *G2 -- Approver-held keys.* The approver's signature is produced
      by a key the EP operator does not possess.  The operator
      orchestrates; it cannot forge.

   *  *G3 -- One-time consumption.* An authorization is consumed at most
      once, globally.  Replay across sessions, operators, or time is
      detectable and MUST be rejected.

   *  *G4 -- Separation of duties.* The initiator of an action MUST NOT
      be an approver of that action.  Policies MAY require m-of-n
      distinct approvers.

   *  *G5 -- Offline verifiability.* A receipt is verifiable with no
      network access, using only the receipt, the approver's public key
      material, and a published log checkpoint.  Offline verification
      establishes authenticity and log inclusion as of commit time, not
      current revocation status (Section 6.3).

   *  *G6 -- Execution-side enforcement.* The strongest deployment
      places verification at the system of record: the executing service
      verifies the receipt before performing the action.  Middleware-
      only deployments are explicitly defined as a weaker conformance
      class (Section 9).

   *  *G7 -- Machine-checked safety.* The protocol state machine's
      safety properties are maintained as formal models (TLA+, Alloy)
      and checked in continuous integration.  Implementations can be
      tested against a published conformance suite.









Schrock                  Expires 3 January 2027                 [Page 5]

Internet-Draft          EP Authorization Receipts              July 2026


1.2.  Scope of Identity

   This document binds an approval to an _approver identifier_ whose key
   is enrolled in the Approver Directory (Section 5.2); it does not, by
   itself, prove that the holder of that identifier is a particular
   natural person.  Proof of a specific real-world identity -- that
   ep:approver:jchen-controller is the human Jordan Chen -- is out of
   scope.  The Approver Directory trust root (Section 5.2) is the
   explicit slot where an identity-proofing or key-discovery layer binds
   keys to named persons; the strength of any such binding is a property
   of that layer, not of the receipt format.  A receipt proves that a
   key enrolled under a given approver identifier signed the exact
   action; the mapping from identifier to person is established and
   asserted by the directory authority.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   *Initiator.* The entity (typically an AI agent or automated process)
   that proposes a high-risk action.  The initiator is identified but
   never trusted with approval authority over its own actions.

   *Approver.* A named human (or, for lower assurance classes, an
   organizational role occupied by a named human at decision time) who
   holds approval authority under policy.  The approver controls a
   private signing key; see Section 5.

   *Action.* A single proposed operation with concrete parameters (e.g.,
   one wire transfer to one beneficiary for one amount).  Actions are
   represented by an Action Object and identified by their action hash
   (Section 3).

   *Policy.* A named, versioned rule set determining, for a class of
   actions, which approvers are required (including m-of-n thresholds),
   validity windows, and amount or scope limits.

   *Authorization Context.* The canonical structure an approver signs:
   action hash, policy reference, initiator identity, nonce, expiry, and
   chain binding (Section 4).







Schrock                  Expires 3 January 2027                 [Page 6]

Internet-Draft          EP Authorization Receipts              July 2026


   *Initiator Attestation.* An OPTIONAL claim by the initiator, carried
   inside the Authorization Context, stating why the initiator escalated
   the action to a human (Section 4.1).  It is a claim, not proof of the
   initiator's internal state.

   *Trust Receipt.* The terminal artifact: the Action Object digest, all
   approver signatures, the consumption record, and a Merkle inclusion
   proof against a signed log checkpoint (Section 6).

   *Verifying Executor.* A system of record that verifies a Trust
   Receipt (or a pre-execution Authorization Bundle) before performing
   the action.  See Section 9.

   *EP Operator.* The party running the orchestration service (policy
   registry, signoff routing, log).  Under this protocol the operator is
   _not_ in the signing trust path for approvals (G2).

3.  The Action Object and Action Hash

   An Action Object is a JSON document with at minimum:

   {
     "ep_version": "1.0",
     "action_type": "wire.release",
     "target": { "system": "treasury.example",
                 "resource": "wire/8841" },
     "parameters": { "amount": "2400000.00", "currency": "USD",
                     "beneficiary_account_hash": "sha256:..." },
     "initiator": "ep:entity:agent-recon-7",
     "policy_id": "ep:policy:wires-over-100k@v12",
     "requested_at": "2026-06-09T17:21:04Z"
   }

   The Action Object MUST be serialized using JSON Canonicalization
   Scheme (JCS) [RFC8785].  The *action hash* is the SHA-256 digest of
   the canonical serialization.  Implementations MUST reject approval
   requests whose action hash does not match a locally recomputed hash
   of the presented Action Object.  Sensitive parameter values MAY be
   carried as salted hashes (as beneficiary_account_hash above) provided
   the executing system can recompute them; the binding property is
   preserved because the hash commits to the committed values.

4.  The Authorization Context

   For each required approver, the orchestrator constructs an
   Authorization Context:





Schrock                  Expires 3 January 2027                 [Page 7]

Internet-Draft          EP Authorization Receipts              July 2026


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

   Rules:

   *  nonce MUST be at least 128 bits of CSPRNG output and MUST be
      globally unique per authorization attempt.  It is the consumption
      key for G3, and is the receipt's freshness mechanism in the sense
      of the Entity Attestation Token (RFC 9711): a verifier-relevant
      nonce, here held to a 128-bit floor (twice the EAT minimum).  EP
      does not treat a timestamp alone as freshness; absolute time,
      where a relying party requires it, is asserted by an independent
      authority rather than by the operator.

   *  policy_hash commits to the exact policy version evaluated.  A
      signature over a context with policy_hash X MUST NOT satisfy a
      requirement evaluated under policy_hash Y, even for the same
      policy_id.

   *  prev_receipt_hash chains this authorization to the issuing log's
      most recent receipt, contributing to tamper evidence.

   *  The context is JCS-canonicalized; the *context hash* is its
      SHA-256 digest.  The approver signs the context hash.

   *  The approver MUST be shown, at signing time, a faithful human-
      readable rendering of the Action Object -- not only the hash.
      Signing interfaces that display a different action than the one
      hashed are a presentation attack; see Section 11.3.









Schrock                  Expires 3 January 2027                 [Page 8]

Internet-Draft          EP Authorization Receipts              July 2026


4.1.  Initiator Attestation (OPTIONAL)

   A producer MAY include an initiator_attestation member in any
   ep.signoff.v1 Authorization Context.  The member carries the
   initiator's own stated reason for escalating the action to a human.
   When present it MUST be a JSON object with the following members and
   no others:

   +==================+==================+======+=====================+
   |Field             |Required          |Type  |Description          |
   +==================+==================+======+=====================+
   |escalation_trigger|REQUIRED          |string|Why the initiator    |
   |                  |                  |(enum)|escalated.  Exactly  |
   |                  |                  |      |one of:              |
   |                  |                  |      |irreversibility,     |
   |                  |                  |      |magnitude,           |
   |                  |                  |      |uncertainty, novelty,|
   |                  |                  |      |authority_gap,       |
   |                  |                  |      |policy_rule.         |
   +------------------+------------------+------+---------------------+
   |policy_basis      |OPTIONAL (REQUIRED|string|Identifier of the    |
   |                  |whenever a        |      |policy or rule that  |
   |                  |deterministic     |      |fired, e.g.          |
   |                  |policy rule fired,|      |ep:policy:wires-over-|
   |                  |including always  |      |100k@v12/rule:dual-  |
   |                  |when              |      |auth.                |
   |                  |escalation_trigger|      |                     |
   |                  |is policy_rule)   |      |                     |
   +------------------+------------------+------+---------------------+
   |statement         |OPTIONAL          |string|Short free-text      |
   |                  |                  |      |reason the initiator |
   |                  |                  |      |gives the approver.  |
   |                  |                  |      |MUST NOT exceed 280  |
   |                  |                  |      |characters.          |
   +------------------+------------------+------+---------------------+

                                 Table 1

   Enum semantics:

   *  irreversibility -- the action cannot be undone once executed.

   *  magnitude -- the amount or scope exceeds what the initiator should
      act on alone.

   *  uncertainty -- the initiator's confidence in its own assessment is
      too low to proceed unaided.




Schrock                  Expires 3 January 2027                 [Page 9]

Internet-Draft          EP Authorization Receipts              July 2026


   *  novelty -- the action or counterparty has no precedent in the
      initiator's history.

   *  authority_gap -- the action requires authority the initiator was
      never granted.

   *  policy_rule -- a deterministic policy rule required signoff and
      none of the five substantive categories above captures why;
      policy_basis names the rule.

   Example context (fields as above, with the new member):

   {
     "ep_version": "1.0",
     "context_type": "ep.signoff.v1",
     "action_hash": "sha256:9f2c...",
     "policy_id": "ep:policy:wires-over-100k@v12",
     "policy_hash": "sha256:77ab...",
     "initiator": "ep:entity:agent-recon-7",
     "initiator_attestation": {
       "escalation_trigger": "magnitude",
       "policy_basis": "ep:policy:wires-over-100k@v12/rule:dual-auth",
       "statement": "Exceeds my single-action limit; new beneficiary."
     },
     "approver": "ep:approver:jchen-controller",
     "approver_index": 1,
     "required_approvals": 2,
     "nonce": "b64u:R9w1...",
     "issued_at": "2026-06-09T17:21:05Z",
     "expires_at": "2026-06-09T17:36:05Z"
   }

   Rules:

   *  *Status.* The member is OPTIONAL.  Existing issuers remain
      conformant; the field can be adopted policy-by-policy.

   *  *Binding.* No new signature, digest, or verification step is
      introduced.  The context is JCS-canonicalized as already required
      above; JCS serializes every member present, so
      initiator_attestation and everything inside it are part of the
      signed bytes.  The approver's signature therefore covers the
      stated reason: the receipt proves the stated reason was part of
      what the approver signed.  Receipts carrying this member verify
      under the existing Section 6.3 verifiers unmodified; a context
      without the member produces byte-identical canonical material to
      one produced today.




Schrock                  Expires 3 January 2027                [Page 10]

Internet-Draft          EP Authorization Receipts              July 2026


   *  *Trigger/basis precedence.* escalation_trigger always carries the
      substantive reason: when one of the first five enum values
      applies, the producer MUST use it, whether or not a deterministic
      rule also fired; policy_rule MUST be used only when no substantive
      category fits.  Independently of which trigger is chosen, whenever
      a deterministic policy rule fired, policy_basis MUST be populated
      with that rule's identifier.

   *  *Cross-context consistency.* When a receipt contains multiple
      contexts (m-of-n approvals), the initiator_attestation object, if
      present in any context, MUST be present in every context of that
      receipt, and its canonical form --
      canonicalize(initiator_attestation) -- MUST be identical across
      all of them.  Every approver signs the same stated reason.

   *  Producers MUST NOT add members beyond the three defined above in
      v1.

   *  A signing client implementing this member MUST render the
      attestation to the approver alongside the faithful human-readable
      rendering of the Action Object that this section already requires,
      subject to the untrusted-content display rules in Section 11.9.

   *  A signing client presented with a context whose statement exceeds
      280 characters MUST refuse to render it for signing.

   The attestation is a claim by the initiator, which this document
   identifies but never trusts (Section 2): it is the initiator's stated
   reason, not a verified fact, and it is not evidence of the
   initiator's internal state.  Verifiers implementing this member MUST
   check the cross-context consistency rule above and SHOULD surface the
   attestation and flag other violations of this section in verification
   reports; none of these checks affects signature validity, by design,
   so receipts verify on verifiers that predate this member.

4.2.  Agent Binding (OPTIONAL)

   A producer MAY include an agent_binding member in any ep.signoff.v1
   Authorization Context.  The member attributes the authorized action
   to an external *agent identity* and, optionally, the external
   *delegation* under which that agent was authorized to act.  When
   present it MUST be a JSON object with the following members and no
   others:








Schrock                  Expires 3 January 2027                [Page 11]

Internet-Draft          EP Authorization Receipts              July 2026


    +============+==========+========+================================+
    | Field      | Required | Type   | Description                    |
    +============+==========+========+================================+
    | agent_id   | REQUIRED | string | Non-empty external agent-      |
    |            |          |        | identity reference (URI, DID,  |
    |            |          |        | or opaque id).  This document  |
    |            |          |        | does not constrain its scheme. |
    +------------+----------+--------+--------------------------------+
    | delegation | OPTIONAL | object | The external delegation that   |
    |            |          |        | authorized the agent; members  |
    |            |          |        | below, no others.              |
    +------------+----------+--------+--------------------------------+
    | statement  | OPTIONAL | string | Short free-text note for the   |
    |            |          |        | approver.  MUST NOT exceed 280 |
    |            |          |        | characters.                    |
    +------------+----------+--------+--------------------------------+

                                  Table 2

   When delegation is present it MUST be a JSON object with the
   following members and no others:

    +=============+==========+========+==============================+
    | Field       | Required | Type   | Description                  |
    +=============+==========+========+==============================+
    | scheme      | REQUIRED | string | Non-empty name of the        |
    |             |          |        | external delegation          |
    |             |          |        | standard, e.g.  "WIMSE",     |
    |             |          |        | "DRP".                       |
    +-------------+----------+--------+------------------------------+
    | ref         | REQUIRED | string | Non-empty external receipt/  |
    |             |          |        | credential identifier.       |
    +-------------+----------+--------+------------------------------+
    | hash        | OPTIONAL | string | Content hash of the          |
    |             |          |        | referenced artifact,         |
    |             |          |        | formatted "sha256:<64-       |
    |             |          |        | lowercase-hex>".             |
    +-------------+----------+--------+------------------------------+
    | observed_at | OPTIONAL | string | RFC 3339 timestamp recording |
    |             |          |        | when the external delegation |
    |             |          |        | evidence was observed or     |
    |             |          |        | known valid.  See L4         |
    |             |          |        | evidence freshness below.    |
    +-------------+----------+--------+------------------------------+

                                 Table 3

   Example context (fields as above, with the new member):



Schrock                  Expires 3 January 2027                [Page 12]

Internet-Draft          EP Authorization Receipts              July 2026


   {
     "ep_version": "1.0",
     "context_type": "ep.signoff.v1",
     "action_hash": "sha256:9f2c...",
     "policy_id": "ep:policy:wires-over-100k@v12",
     "policy_hash": "sha256:77ab...",
     "initiator": "ep:entity:agent-recon-7",
     "agent_binding": {
       "agent_id": "did:web:agents.example.com:recon-7",
       "delegation": {
         "scheme": "WIMSE",
         "ref": "urn:wimse:cred:9c41ab",
         "hash": "sha256:2f9a...",
         "observed_at": "2026-06-09T17:20:48Z"
       },
       "statement": "Acting for treasury-ops under wire delegation."
     },
     "approver": "ep:approver:jchen-controller",
     "approver_index": 1,
     "required_approvals": 2,
     "nonce": "b64u:R9w1...",
     "issued_at": "2026-06-09T17:21:05Z",
     "expires_at": "2026-06-09T17:36:05Z"
   }

   Rules:

   *  *Status.* The member is OPTIONAL.  Existing issuers remain
      conformant; the field can be adopted policy-by-policy.

   *  *Claim, not proof.* agent_binding records that the action was
      _presented_ as being taken by agent_id under delegation ref.  This
      document identifies but never trusts the binding (Section 2): it
      is neither proof of the agent's identity nor proof of the
      delegation's validity, both of which remain the responsibility of
      the referenced external system.  A verifier MUST NOT treat
      agent_binding as proof of either; it MAY surface agent_id and
      delegation to the relying party as part of the verified context,
      clearly labeled as a reference to an external system.

   *  *Binding.* No new signature, digest, or verification step is
      introduced.  The context is JCS-canonicalized as already required
      above; JCS serializes every member present, so agent_binding and
      everything inside it are part of the signed bytes.  The approver's
      signature therefore covers the binding.  Receipts carrying this
      member verify under the existing Section 6.3 verifiers unmodified;
      a context without it produces byte-identical canonical material to
      one produced today.



Schrock                  Expires 3 January 2027                [Page 13]

Internet-Draft          EP Authorization Receipts              July 2026


   *  *Cross-context consistency.* When a receipt contains multiple
      contexts (m-of-n approvals), the agent_binding object, if present
      in any context, MUST be present in every context of that receipt,
      and its canonical form -- canonicalize(agent_binding) -- MUST be
      identical across all of them.  Every approver signs the same
      attribution.

   *  Producers MUST NOT add members beyond those defined above in v1,
      in either agent_binding or its delegation.

   *  A signing client implementing this member SHOULD render agent_id
      (and delegation if present) to the approver alongside the faithful
      human-readable rendering of the Action Object that this section
      already requires, subject to the untrusted-content display rules
      in Section 11.9.  A signing client presented with a context whose
      statement exceeds 280 characters MUST refuse to render it for
      signing.

   *L4 evidence freshness (OPTIONAL).* A human authorization decision is
   only as trustworthy as the upstream agent-identity and delegation
   evidence it relied on.  If a decision is enforced correctly against a
   delegation claim that was never constrained or has since expired, the
   failure surfaces at the authorization layer but originates in the
   identity/delegation layer beneath it.  This document makes that
   dependency explicit and recordable without absorbing the identity
   layer:

   *  A producer MAY populate delegation.observed_at with the RFC 3339
      time at which the external delegation evidence was observed or
      known valid.  Like the rest of the binding, it is covered by the
      approver's signature.

   *  A relying party MAY enforce freshness against observed_at.  When
      it does, the evaluation MUST fail closed: a missing observed_at, a
      timestamp later than the evaluation time, or an age exceeding the
      relying party's configured maximum MUST be treated as not-fresh.
      When no maximum age is configured, freshness is not evaluated and
      the evidence is still surfaced for the audit record.

   This keeps the receipt agnostic to which external identity/delegation
   scheme prevails: the relying party binds to and records whatever
   evidence was presented rather than requiring that layer to converge,
   and a stale or unconstrained upstream claim becomes detectable after
   the fact rather than silently absorbed.  As with the Initiator
   Attestation, none of these checks affects signature validity, by
   design, so receipts verify on verifiers that predate this member.





Schrock                  Expires 3 January 2027                [Page 14]

Internet-Draft          EP Authorization Receipts              July 2026


5.  Approver Keys and the Signoff Signature

   This section is the core upgrade over server-side approval systems.

5.1.  Key Classes

   Key classes classify KEY CUSTODY -- who holds and exercises the
   approver's signing key -- and nothing else.  They are distinct from,
   and unrelated to, any assurance-level or conformance-class vocabulary
   used elsewhere; a companion document on assurance classification uses
   different identifiers precisely to avoid collision with these.

   *Class A -- Device-bound keys (RECOMMENDED).* The approver's key is
   generated and held in a platform authenticator or security key and
   exercised via WebAuthn [WEBAUTHN].  The signature algorithm is ES256
   (P-256) or Ed25519 where supported.  The WebAuthn challenge MUST be
   the context hash.  The authenticator's user-verification flag
   (biometric or PIN) MUST be required for signoff credentials.  This
   user-verification-gated signature is the native EP human-approval
   act; it is fully defined by this section and does not rely on any
   external acquiescence or confirmation mechanism.  Attestation SHOULD
   be captured at enrollment so relying parties can establish that the
   key is hardware-bound.

   *Class B -- Software keys.* An Ed25519 keypair held in the approver's
   client environment (CLI keychain, mobile secure enclave via app).
   Acceptable where WebAuthn is impractical (headless approval
   terminals), with the reduced assurance noted in receipts.

   *Class C -- Operator-custodied keys (LEGACY).* The EP operator signs
   on the approver's behalf after authenticating them.  This class
   exists only to describe pre-existing deployments.  Receipts produced
   under Class C MUST be labeled key_class: "C" and relying parties
   SHOULD treat them as evidence of operator assertion, not approver
   signature.  New deployments SHOULD NOT use Class C.

5.2.  Enrollment and the Approver Directory

   Approver public keys are enrolled into a signed Approver Directory
   maintained per organization: a Merkle tree over (approver_id,
   public_key, key_class, valid_from, valid_to, roles) entries, with
   signed tree heads published alongside receipt log checkpoints.  A
   receipt's offline verifiability (G5) includes an inclusion proof of
   the approver's key entry, so a verifier needs no live directory
   access.  Key rotation appends a new entry and terminates the old one;
   signatures verify against the key entry valid at issued_at.





Schrock                  Expires 3 January 2027                [Page 15]

Internet-Draft          EP Authorization Receipts              July 2026


   Directory authority is a trust root and MUST NOT default to the EP
   operator.  The directory tree head MUST be signed by an organization-
   controlled directory key (custody options parallel Section 5.1; an
   organization-held hardware key is RECOMMENDED).  Where directory
   _operation_ is delegated to the EP operator, every enrollment entry
   MUST carry a second-party attestation -- a signature over the new
   entry by an organization administrator key or by a quorum of already-
   enrolled approvers -- and that attestation MUST be included in the
   receipt's approver_key_proofs.  Verifiers MUST treat a directory head
   signed only by an operator-held key as operator assertion (Class
   C-equivalent assurance), regardless of the key class of the
   individual signoffs.  Rationale: an operator that unilaterally
   controls directory membership cannot forge an enrolled approver's
   signature, but it can enroll a key it controls under a legitimate
   approver's name -- relocating the forgery rather than preventing it.
   See Section 11.6.

   This directory is also the binding point between approver identifiers
   and real-world persons (Section 1.2).  The strength of that binding
   -- how an organization proves that an enrolled identifier is the
   person it names, and how key-discovery layers attach to it -- is a
   property of the directory authority and any identity layer bound to
   it, not of the receipt format defined here.

5.3.  The Signoff

   A signoff is:

   {
     "context_hash": "sha256:c41e...",
     "signature": "b64u:MEUCIQ...",
     "key_class": "A",
     "approver_key_id": "ep:key:jchen-controller#2026-01",
     "signed_at": "2026-06-09T17:24:40Z",
     "webauthn": { "authenticator_data": "b64u:...",
                   "client_data_json": "b64u:..." }
   }

   For Class A, verifiers MUST validate the WebAuthn assertion per
   [WEBAUTHN] including that clientDataJSON.challenge equals the context
   hash and that the user-verification bit is set.  A denial is also
   signed (over the context hash with a decision: "denied" envelope) so
   that refusals are equally non-repudiable and equally terminal.

6.  Consumption, Commitment, and the Trust Receipt






Schrock                  Expires 3 January 2027                [Page 16]

Internet-Draft          EP Authorization Receipts              July 2026


6.1.  State Machine

   An authorization attempt proceeds:

   REQUESTED -> {PARTIALLY_APPROVED}* -> APPROVED -> COMMITTED
             \-> DENIED                          \-> EXPIRED
             \-> EXPIRED

   COMMITTED, DENIED, and EXPIRED are terminal.  The protocol invariants
   -- maintained as machine-checked models and REQUIRED of conforming
   implementations -- are:

   *  *ConsumeOnce.* A nonce transitions to a terminal state at most
      once, globally.  Any second presentation MUST be rejected with a
      replay error.

   *  *BindingMatch.* A signoff satisfies only the context (and
      therefore only the action hash) it signs.

   *  *TerminalIrreversibility.* No transition exits a terminal state.

   *  *SelfApprovalImpossible.* For every signoff, approver !=
      initiator; for m-of-n policies, approvers are pairwise distinct
      and each distinct from the initiator.

   *  *NoBypassWrite.* A COMMITTED state is reachable only through the
      full sequence; conforming verifying executors MUST NOT execute
      without verifying it (Section 9).

6.2.  The Trust Receipt

   Upon commitment the orchestrator assembles and logs the Trust
   Receipt:


















Schrock                  Expires 3 January 2027                [Page 17]

Internet-Draft          EP Authorization Receipts              July 2026


   {
     "receipt_id": "ep:receipt:01J...",
     "action": { "...": "full Action Object" },
     "action_hash": "sha256:9f2c...",
     "contexts": [ { "...": "Authorization Context 1" } ],
     "signoffs": [ { "...": "Signoff 1" },
                   { "...": "Signoff 2" } ],
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

6.3.  Offline Verification Algorithm

   A verifier with (receipt, trusted log public key, trusted directory
   root or pinned approver keys) and *no network access* MUST be able to
   establish all of the following; the published verifier package
   performs exactly these steps:

   1.  Recompute the action hash from the canonical Action Object;
       compare.

   2.  For each context: recompute the context hash; confirm it commits
       to the action hash, the policy hash, and a distinct approver.

   3.  For each signoff: verify the signature (and WebAuthn assertion
       where present) over the context hash against the approver key
       entry, checking the key's validity window contains issued_at.

   4.  Confirm SoD: initiator appears in no approver slot; approvers are
       pairwise distinct; the approval count satisfies
       required_approvals.

   5.  Verify the Merkle inclusion proof of the receipt leaf against the
       checkpoint root, and the checkpoint signature against the log
       key.

   6.  Confirm signed_at and committed_at fall within [issued_at,
       expires_at].





Schrock                  Expires 3 January 2027                [Page 18]

Internet-Draft          EP Authorization Receipts              July 2026


   Step 5 is what distinguishes EP receipts from log-access designs: the
   checkpoint travels _inside_ the receipt, so verification requires no
   query to the log.  Detecting log equivocation (split-view attacks)
   additionally benefits from gossip or witness cosigning
   (Section 11.4), which is an online activity; the offline guarantee is
   that _this receipt is internally consistent, correctly signed by
   enrolled approver keys, and was included in a log tree whose head the
   log operator signed_.

   Offline verification establishes authenticity, not currency.  Two
   properties are explicitly NOT established offline: (a) post-issuance
   revocation -- a receipt whose approver key was revoked an hour after
   commitment still verifies; the artifact is evidence of validity _at
   commit time_; and (b) log honesty against split views (Section 11.4).
   A relying party with freshness or revocation requirements MUST
   additionally consult a current directory head and log checkpoint
   online.  Implementations MUST NOT describe offline verification as
   establishing that a receipt is "currently valid."

   The Initiator Attestation (Section 4.1), where present, is covered by
   the context hash recomputed in step 2 above; no additional
   verification step is required for it.

7.  Multi-Approver Policies (m-of-n)

   A policy MAY require k distinct approvers from a role set.  Each
   approver receives and signs an individual Authorization Context
   sharing the same action_hash and nonce family but a distinct
   approver_index.  Commitment occurs only when k valid, distinct
   signoffs exist before expires_at.  Partial approval confers no
   authority: a verifying executor presented with fewer than k signoffs
   MUST refuse.

8.  Delegation Constraints

   Where an approver's authority is itself delegated, the delegation
   record MUST be presented in the receipt's approver_key_proofs, and
   the constraint *DelegateCannotExceedPrincipal* applies: the effective
   scope of a delegate is the intersection of the delegation grant and
   the principal's authority at signing time.  Delegation chains are
   bounded (RECOMMENDED depth of at most 2) and every link is
   independently signed.

9.  Conformance Classes and Execution-Side Enforcement

   Honesty about deployment topology is a protocol feature.  Three
   classes:




Schrock                  Expires 3 January 2027                [Page 19]

Internet-Draft          EP Authorization Receipts              July 2026


   *EP-Verified Execution (STRONG).* The system of record (payment
   switch, registry, deployment controller) verifies the Authorization
   Bundle (receipt-less pre-execution form: action object, contexts,
   signoffs, consumption attestation) before executing, and refuses
   otherwise.  The gate cannot be bypassed by any party that does not
   control the system of record itself.

   *EP-Gated Middleware (STANDARD).* An interception layer between the
   agent and the executing credential enforces the gate.  Provides
   strong protection against agent error and prompt injection; an
   operator with code control can bypass.  Receipts remain valid
   evidence of what _was_ approved.

   *EP-Evidence Only (BASIC).* Actions execute independently; receipts
   are produced for audit.  No enforcement claim is made.

   Implementations MUST declare their class in receipts
   (enforcement_class), and marketing or compliance claims MUST NOT
   state a stronger class than deployed.  This section exists because
   the difference between "we proved the protocol" and "your deployment
   is unbypassable" is the most common overclaim in this category.

10.  Relationship to Other Work

   *DRP* ([I-D.nelson-agent-delegation-receipts]) binds a _user's_
   delegation to an _operator's_ instructions -- upstream consumer
   delegation.  EP binds an _organizational approver_ to an _exact
   action_ -- downstream authorization with SoD and m-of-n, which DRP
   does not formalize, and with offline verification, which DRP's log-
   access model does not provide.  The two compose: a DRP delegation can
   be referenced in an EP Action Object's provenance field.

   *CIBA* ([CIBA]) transports an authentication-time approval to a
   backchannel device; it does not produce an action-bound, offline-
   verifiable, one-time-consumable artifact.  CIBA MAY serve as the
   transport by which an approver is reached; the EP signoff is what
   they produce when they get there.

   *WIMSE / workload identity* authenticates the agent to services; EP
   authorizes the action.  Complementary layers.

   *Receiver-attested logging (e.g., Sello)* has the receiving service
   sign what it observed, post-hoc.  EP is pre-execution authorization.
   A complete deployment benefits from both: EP proves the action was
   authorized; receiver attestation proves what then actually occurred.






Schrock                  Expires 3 January 2027                [Page 20]

Internet-Draft          EP Authorization Receipts              July 2026


   *AgentROA (draft-nivalto-agentroa-route-authorization), AIIP, and
   CIRP* define machine-side, per-hop execution and route receipts for
   agent actions under delegated authority; none binds a named,
   accountable _human_ to the action.  EP supplies that human-authority
   root, and its delegation chain shares AgentROA's monotonic ("tighten-
   only") scope-narrowing discipline.

   *The Entity Attestation Token (RFC 9711, RATS)* attests the _agent or
   platform_ -- model, keys, posture; EP attests the _human
   authorization_. The two are orthogonal and composable: an EAT says
   the machine is what it claims; an EP receipt says a named person
   approved the exact action.

   *Transaction Tokens (draft-ietf-oauth-transaction-tokens)* propagate
   workload and agent authorization context across a machine call chain;
   EP is the human-authority root from which such a chain descends.

   *Evidence Record Syntax (RFC 4998)* preserves signed evidence across
   algorithm aging by periodic re-timestamping.  EP applies the same
   approach to long-lived receipts via an evidence-record renewal chain,
   so a receipt verifiable today remains verifiable after its original
   algorithms weaken -- a property the 10-25+ year retention schedules
   of government records require.

11.  Security Considerations

11.1.  Operator Compromise

   Under key classes A/B, a compromised EP operator can deny service and
   can fail to route signoff requests, and it cannot _forge a
   signature_: it lacks approver keys, and it cannot replay one (nonces
   are single-consumption and receipts chain).  Two operator-compromise
   paths remain and are stated plainly rather than claimed away.  First,
   an operator that controls the signing client's rendering can harvest
   a _genuine_ signature over an action the approver misunderstood -- a
   presentation attack (Section 11.3); for this reason an independently-
   authored rendering surface is REQUIRED for high-value policies.
   Second, an operator that unilaterally controls the Approver Directory
   can enroll keys it controls (Section 5.2, Section 11.6).
   Accordingly, the accurate claim for classes A/B is: "the operator
   cannot forge an approver's signature."  The stronger claim -- "the
   operator cannot obtain an unauthorized approval" -- additionally
   requires the directory-authority and independent-rendering controls.
   Under class C the operator can fabricate outright; hence the labeling
   requirement.






Schrock                  Expires 3 January 2027                [Page 21]

Internet-Draft          EP Authorization Receipts              July 2026


11.2.  Approver Device Compromise

   A stolen authenticator with user verification still requires the
   biometric/PIN.  Organizations SHOULD require key class A for high-
   value policies and SHOULD pair approval with out-of-band action
   rendering (the approver sees the wire details on a second surface).

11.3.  Presentation Attacks

   The gravest risk in this protocol, stated without minimization: the
   approver signs context hash H believing it represents action X when
   it represents action Y.  A signature proves user presence and an act
   of approval toward _whatever was rendered_; cryptography cannot prove
   the rendering was faithful.  Required mitigations, in increasing
   strength: (1) the signing client MUST render the Action Object from
   the exact bytes that were hashed -- never from a separately supplied
   description; (2) for high-value policies, render templates MUST be
   registered with the policy and committed by policy_hash, so the
   display logic is part of what the approver's signature covers; (3)
   for policies above an organization-designated threshold, the material
   action parameters (amount, beneficiary identifiers) MUST additionally
   be rendered on a second surface not authored by the orchestrating
   operator -- for example, delivered by the verifying executor or an
   independent operator to the approver's enrolled device over a
   separate channel.  The residual risk is stated honestly: absent a
   trusted display path (hardware the operator does not author),
   rendering fidelity is enforced by controls (2)-(3), by audit, and by
   consented mismatch drills (Section 11.8) -- not by mathematics.  What
   the cryptography does guarantee is exactness of evidence: the receipt
   contains the full Action Object actually signed, so any divergence
   between what was displayed and what was executed is detectable after
   the fact with proof rather than testimony.

11.4.  Log Equivocation

   A malicious log could show different trees to different parties.
   Checkpoints SHOULD be witness-cosigned and/or gossiped between
   independent EP operators; the federation profile makes cross-operator
   checkpoint exchange mandatory.

11.5.  What the Formal Models Do and Do Not Prove

   The TLA+/Alloy models prove safety of the authorization state
   machine: no replay, no self-approval, no bypass _within the modeled
   system_, no partial commitment.  They prove nothing about any AI
   model's behavior, about host compromise, or about deployments in a
   weaker conformance class.  Implementations MUST NOT represent the
   proofs as covering deployment topologies they do not model.  For the



Schrock                  Expires 3 January 2027                [Page 22]

Internet-Draft          EP Authorization Receipts              July 2026


   same honesty: three normative mechanisms in this document are
   specified ahead of the reference implementation and are not yet
   exercised by it or by conformance vectors -- the operator-signed-
   directory assurance downgrade (Section 5.2), delegation records in
   approver_key_proofs and the DelegateCannotExceedPrincipal check
   (Section 8), and enforcement_class emission (Section 9).
   Implementers MUST treat the text as normative and the reference
   implementation as incomplete on these three points, not the reverse.
   The m-of-n quorum flow IS now modeled: a checked Alloy model (formal/
   ep_quorum.als in the repository) proves SelfApprovalImpossible,
   NoHumanFillsTwoSlots, NoKeyFillsTwoSlots, TwoPersonRuleHolds, and
   ordered-chain acyclicity/linearity against the quorum verifier and
   its conformance vectors.  The models additionally do not yet cover
   the WebAuthn challenge binding, the Approver Directory, log
   checkpoints, or the Initiator Attestation (Section 4.1); those
   sections are specified, not proven, and extending the models to them
   is tracked work.

11.6.  Directory Authority

   Section 5 removes the operator from the signature path; Section 5.2
   must not readmit it as the authority that decides which keys count.
   If the EP operator alone signs the Approver Directory, a malicious
   operator can satisfy policy by enrolling a key it controls under a
   nominally legitimate approver's name.  The controls in Section 5.2
   (organization-held directory key; second-party attestation on
   enrollment; Class C-equivalent treatment otherwise) exist for this
   reason.  Auditors SHOULD verify directory key custody as part of any
   assessment that relies on receipts.

11.7.  What Separation of Duties Does and Does Not Provide

   SelfApprovalImpossible (Section 6) defeats _unilateral_ self-
   approval: no initiator can approve its own action, and m-of-n
   approvers are pairwise distinct identities.  It does not defeat
   collusion among distinct enrolled humans, one human who controls
   multiple enrolled identities (an enrollment control -- Section 5.2),
   or a coerced approver.  Receipts make such events _attributable_ --
   named, signed, and evidenced -- which raises the cost of insider
   fraud; they do not make it impossible, and implementations MUST NOT
   claim otherwise.










Schrock                  Expires 3 January 2027                [Page 23]

Internet-Draft          EP Authorization Receipts              July 2026


11.8.  Approver Fatigue

   A gate that humans route around protects nothing; rubber-stamping is
   the empirical failure mode of every human-in-the-loop control under
   volume.  This protocol is therefore not a general approval workflow:
   deployments MUST scope signoff policies to genuinely high-risk, low-
   frequency actions and SHOULD handle volume with policy (thresholds,
   allow-lists, velocity rules) rather than human throughput.
   Operational countermeasures SHOULD include monitoring time-to-sign
   distributions (signing latencies near the floor indicate approval
   without review), tracking deny rates (a gate that never denies is
   either perfectly upstream-filtered or ceremonial), and consented
   render-mismatch drills that measure whether approvers read what they
   sign.  Such telemetry is deployment guidance, not protocol; but the
   protocol's guarantees are only as strong as the attention of the
   human at its center, and implementations SHOULD say so to their
   customers.

11.9.  Initiator Attestation as an Attack Surface

   The statement member of an Initiator Attestation (Section 4.1) is
   attacker-influenceable free text rendered to a human at the moment of
   decision -- a social-engineering surface aimed at the approver,
   adjacent to the presentation attacks of Section 11.3.  A compromised
   or prompt-injected initiator can state any trigger and any reason;
   injection can change what the initiator _proposes_, including this
   field, but it cannot change what a human _approves_ on their own
   hardware, because the device-bound signature (Section 5.1) is outside
   the model context.  Conforming signing clients MUST therefore render
   the statement as untrusted content: plain text only, with no markup,
   links, or control characters rendered; the 280-character cap
   enforced; and visually distinct styling that labels it as the
   initiator's unverified claim, clearly separated from the operator-
   rendered Action Object.  This is consistent with the rendering-
   faithfulness discipline of Section 11.3: the approver's decision
   input is the rendered Action Object; the statement is commentary from
   a party the protocol never trusts.  A related residual vector is
   divide-and-misinform: because each approver signs their own context,
   a malicious orchestrator can show different approvers of an m-of-n
   receipt different attestations, and every individual signature
   remains valid.  The cross-context consistency rule (Section 4.1)
   exists for this; verifiers implementing the member MUST flag
   violations, but on verifiers that predate the member such a receipt
   still verifies -- the rule is a conformance check, not a signature
   property.






Schrock                  Expires 3 January 2027                [Page 24]

Internet-Draft          EP Authorization Receipts              July 2026


   Privacy: statements written by an agent mid-task can leak sensitive
   operational context -- counterparty details, internal findings,
   fragments of prompts -- into receipts that are long-lived and
   portable by design.  Deployments SHOULD prefer escalation_trigger
   plus policy_basis identifiers over free text wherever a rule id
   captures the reason, SHOULD constrain or template statement
   generation for regulated data, and MUST apply the same retention and
   disclosure controls to attestation content as to the rest of the
   receipt.

   Absence is not evidence: a receipt without an attestation means only
   that the issuer did not populate it -- not that the initiator judged
   the action routine, and not that no escalation reasoning occurred.
   Verifiers and auditors MUST NOT infer anything from the absence of an
   attestation alone.  (Separately, and unchanged: for an action a
   policy gates on signoff, the absence of any valid receipt at all
   remains evidence that the control was bypassed -- that property comes
   from the gate, not from this member.)

   No trust feedback: policy engines MUST NOT use initiator_attestation
   content to relax thresholds, skip approvers, or raise any trust
   score.  The initiator must gain nothing by saying the right words;
   the attestation is a claim by a party the protocol identifies but
   never trusts, not proof of its internal state.

11.10.  No symmetric key on the verification trust path

   Every artifact a relying party verifies offline -- the approver
   signoff (Class A: ES256/P-256), the operator commit and receipt
   (Ed25519), the log inclusion proof, and the portable revocation
   statement (Ed25519) -- is bound by an ASYMMETRIC signature whose
   verifying key the relying party holds independently of the issuer.
   No step in offline verification relies on a Message Authentication
   Code, a shared secret, or any symmetric primitive.  This is
   deliberate and load-bearing: a symmetric construction (for example an
   HMAC-chained audit log) is verifiable only by a party holding the
   same secret as the producer, which is precisely the party whose
   conduct the evidence is meant to constrain -- its keeper can rewrite
   its own history undetectably.  An EP receipt's issuer cannot.
   Conforming verifier implementations MUST NOT introduce a symmetric
   primitive on the verification path; an implementation that does so
   does not provide EP's non-repudiation property.  (HMAC MAY appear
   elsewhere in a deployment -- e.g. authenticating an operator's own
   cron or webhook calls -- provided it is never a link in the chain a
   third party verifies.)






Schrock                  Expires 3 January 2027                [Page 25]

Internet-Draft          EP Authorization Receipts              July 2026


12.  IANA Considerations

   This document has no IANA actions.  A future version may register the
   application/ep-receipt+json media type.

13.  Normative References

   [CIBA]     OpenID Foundation, "OpenID Connect Client-Initiated
              Backchannel Authentication Flow - Core 1.0", September
              2021, <https://openid.net/specs/openid-client-initiated-
              backchannel-authentication-core-1_0.html>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

   [WEBAUTHN] W3C, "Web Authentication: An API for accessing Public Key
              Credentials, Level 2", April 2021,
              <https://www.w3.org/TR/webauthn-2/>.

14.  Informative References

   [I-D.nelson-agent-delegation-receipts]
              Nelson, R., "Delegation Receipt Protocol for AI Agent
              Authorization", Work in Progress, Internet-Draft, draft-
              nelson-agent-delegation-receipts-10, 13 June 2026,
              <https://datatracker.ietf.org/doc/html/draft-nelson-agent-
              delegation-receipts-10>.

Appendix A.  Changes since -04

   -05 adds the human-authorization-receipt composition frame for the
   SCITT agent-action statement cluster (how a WHO receipt is
   referenced, by digest, from capsule/record-style statements); updates
   the SCITT citation to RFC 9943; adds the key-custody disambiguation
   note in Section 5.1 (key classes classify custody, not assurance
   levels); corrects the formal-models status (the m-of-n quorum flow is
   now Alloy-checked) and states plainly which three normative



Schrock                  Expires 3 January 2027                [Page 26]

Internet-Draft          EP Authorization Receipts              July 2026


   mechanisms the reference implementation does not yet cover.

Appendix B.  Changes since -00 (through -04)

   This summary covers -00 through -04.  Section numbering is stable;
   all changes are new subsections or in-place additions.

   1.  New OPTIONAL Authorization Context member initiator_attestation
       (new Section 4.1): a REQUIRED escalation_trigger enum
       (irreversibility, magnitude, uncertainty, novelty, authority_gap,
       policy_rule), an OPTIONAL policy_basis rule identifier, and an
       OPTIONAL length-capped (<= 280 character) statement.  The member
       is OPTIONAL; it is covered by the context hash via the JCS
       canonicalization already normative in Section 4, so the
       approver's signature covers the stated reason; receipts carrying
       it verify under the existing Section 6.3 verifiers unmodified;
       and it is a claim by the initiator -- identified but never
       trusted -- not proof of the initiator's internal state.  A
       terminology entry and a step-2 note in Section 6.3 were added
       accordingly.

   2.  Security Considerations additions (new Section 11.9): the
       statement is attacker-influenceable text presented to a human
       (prompt-injection -> social-engineering surface); conforming
       signing clients MUST render it as untrusted content (no markup,
       length cap, distinct styling), consistent with the Section 11.3
       rendering-faithfulness caveat.  Adds privacy guidance for free-
       text statements in long-lived receipts (prefer policy_basis
       identifiers), the rule that absence of an attestation is not
       evidence of non-escalation, the cross-context consistency
       requirement, and the prohibition on using attestation content as
       a trust input.  The formal-models section now lists the Initiator
       Attestation among the not-yet-modeled areas.

   3.  Introduction/terminology clarifications (new text in the
       Introduction, new Section 1.2, and a sentence in Section 5.1 and
       Section 5.2): makes unmistakable that (a) EP's user-verification-
       gated Class-A signoff is native to this draft and does not depend
       on any other draft's acquiescence/confirmation mechanism, and (b)
       proof of a specific natural-person identity is out of scope --
       the Approver Directory trust root is the explicit slot where
       identity/key-discovery layers bind keys to named persons.

   4.  New OPTIONAL Authorization Context member agent_binding (new
       Section 4.2): an external agent-identity reference (agent_id) and
       an OPTIONAL delegation (scheme, ref, OPTIONAL hash, OPTIONAL
       observed_at), plus an OPTIONAL length-capped (<= 280 character)
       statement.  Like initiator_attestation, it is OPTIONAL, covered



Schrock                  Expires 3 January 2027                [Page 27]

Internet-Draft          EP Authorization Receipts              July 2026


       by the context hash via the JCS canonicalization already
       normative in Section 4, verifies under the existing Section 6.3
       verifiers unmodified, and is a claim -- identified but never
       trusted -- not proof of the agent's identity or the delegation's
       validity.  The OPTIONAL delegation.observed_at records when the
       upstream identity/delegation (L4) evidence was observed; a
       relying party MAY enforce freshness against it fail-closed,
       keeping the receipt agnostic to which external identity scheme
       prevails while making a stale or unconstrained upstream claim
       detectable after the fact.

   5.  Housekeeping: version and date bumped in the header; this
       appendix added; the idnits non-ASCII em-dash / curly-quote
       cleanup from -00 carried forward as a build step.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai






























Schrock                  Expires 3 January 2027                [Page 28]

```
