# The Agent Action Control Manifest: A Public Effect-Boundary Control Plane for Machine Actions
## draft-schrock-agent-action-manifest-00

> Readable mirror of the xml2rfc source ([`draft-schrock-agent-action-manifest-00.xml`](./draft-schrock-agent-action-manifest-00.xml)). The XML is authoritative.

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               2 July 2026
Expires: 3 January 2027


  The Agent Action Control Manifest: A Public Effect-Boundary Control
                       Plane for Machine Actions
                 draft-schrock-agent-action-manifest-00

Abstract

   A growing set of specifications defines evidence _objects_ for
   machine actions: transparency statements, workload-identity and
   transaction tokens, permits, action capsules, and authorization,
   delegation, and inference receipts.  What they mostly do not define
   is the public control plane that says, for a given irreversible
   action, _which_ evidence is required, at _what_ assurance tier, bound
   to _which_ real system-of-record fields, under _what_ replay model,
   and _what_ evidence must exist after the action runs.

   This document defines the Agent Action Control Manifest: a machine-
   readable document a service publishes at a well-known location that
   declares, per consequential action, the enforcement point, the
   required authorization receipt profile and assurance tier, the
   execution-binding fields that MUST be observed from the system of
   record, the replay model, and the evidence that MUST be emitted after
   the effect boundary.  It also carries an OPTIONAL, advisory _effects_
   preview (reversibility, data-exposure class, cost class, downstream
   reach, and whether human consent is required) so a runtime can weigh
   consequences before it seeks authorization.  It is the declaration an
   agent runtime reads to learn what it must satisfy before an
   irreversible action, and that an independent scanner audits.  The
   manifest _declares_ policy; it never replaces enforcement, which
   remains authoritative at the action boundary.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.






Schrock                  Expires 3 January 2027                 [Page 1]

Internet-Draft        Agent Action Control Manifest            July 2026


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

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   2
   2.  Terminology . . . . . . . . . . . . . . . . . . . . . . . . .   3
   3.  Manifest Location and Versioning  . . . . . . . . . . . . . .   3
   4.  Manifest Structure  . . . . . . . . . . . . . . . . . . . . .   4
   5.  Action Control Declarations . . . . . . . . . . . . . . . . .   4
   6.  Semantics: Declaration Is Not Enforcement . . . . . . . . . .   6
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .   7
   8.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   7
   9.  Normative References  . . . . . . . . . . . . . . . . . . . .   7
   10. Informative References  . . . . . . . . . . . . . . . . . . .   8
   Appendix A.  Example Manifest (Non-Normative) . . . . . . . . . .   9
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .  10

1.  Introduction

   Layered web conventions tell software what it may do: robots.txt
   declares crawler policy, CORS declares cross-origin policy,
   security.txt [RFC9116] declares where to report vulnerabilities, and
   authorization-server metadata [RFC8414] declares an issuer's
   endpoints and capabilities.  When an autonomous agent drives a tool
   or API, no equivalent declaration exists for the properties that
   matter at machine speed: whether an action is irreversible, what
   authorization it needs, which observed execution fields the
   authorization must bind, and what evidence must survive it.




Schrock                  Expires 3 January 2027                 [Page 2]

Internet-Draft        Agent Action Control Manifest            July 2026


   The evidence-object ecosystem does not fill this gap.  Transparency
   architecture [RFC9943] logs signed statements; workload and
   transaction-token work identifies the acting principal; permit,
   capsule, and action-receipt work records decisions and effects.  Each
   defines an artifact; none defines the public contract that binds a
   specific consequential action to the specific evidence and assurance
   it requires.  Tool-catalog declarations (tool annotations, agent
   cards) sit closer, but they describe what a tool _can do_ and hint at
   destructiveness; they do not state what evidence a caller must
   present, at what assurance, bound to which fields, with what replay
   semantics.  The manifest defined here is also deliberately protocol-
   agnostic: one declaration covers the same consequential action
   whether it is reached as a tool call, an HTTP API, or an agent-to-
   agent message.

   This document defines that contract as a manifest a service
   publishes, composing above the receipt primitive
   [I-D.schrock-ep-authorization-receipts] and the assurance taxonomy
   [I-D.schrock-ep-assurance-classes] it references.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   Consequential action  An operation whose effect is irreversible or
      materially hard to reverse — a payment, a deletion, a production
      deploy, a destructive data operation, a permission change.

   Control plane  The declarative contract, defined by this manifest,
      mapping each consequential action to its authorization, execution-
      binding, replay, and evidence requirements.

   Effect boundary  The point at which the action mutates the system of
      record; the control MUST be enforced before it.

3.  Manifest Location and Versioning

   A service SHOULD publish its manifest at the well-known URI
   [RFC8615]:

   /.well-known/agent-action-control.json






Schrock                  Expires 3 January 2027                 [Page 3]

Internet-Draft        Agent Action Control Manifest            July 2026


   served with media type application/json over a transport providing
   server authentication and integrity.  The current manifest version
   identifier is EP-ACTION-CONTROL-MANIFEST-v0.2.  An earlier,
   declaration-only predecessor (EP-ACTION-RISK-MANIFEST-v0.1, served at
   /.well-known/agent-actions.json, without the control block defined in
   Section 5) is superseded by this version.

   A consumer that encounters an unrecognized @version MUST treat the
   document as discovery-only: it MUST NOT infer weaker requirements
   from fields it does not understand.  Consumers MAY cache the manifest
   under ordinary HTTP cache semantics; because enforcement is
   authoritative at the action boundary (Section 6), manifest staleness
   fails safe — an outdated manifest can at worst cause a caller to
   present insufficient evidence and be refused, never an unauthorized
   execution.

4.  Manifest Structure

   The manifest is a JSON object [RFC8259].  This section defines the
   interoperable model; a field-level JSON Schema for the profile is
   published at the URL named by $schema and pins field types and
   requiredness for implementations of that profile.

   @version, $schema, profile (REQUIRED)  The version identifier, the
      URL of the JSON Schema, and the profile name (emilia.action-
      control).

   service (REQUIRED)  The publishing service (name, issuer origin,
      manifest URL).

   defaults (REQUIRED)  The default disposition, which MUST be fail-
      closed for consequential actions: missing, invalid, and stale
      receipts refused; one-time consumption; strict evidence logging.

   evidence_profiles (REQUIRED)  The evidence formats the manifest
      references (authorization receipt, execution attestation, reliance
      packet, transparency statement).

   actions (REQUIRED)  The per-action control declarations (Section 5).

5.  Action Control Declarations

   Each action declaration carries an identifier, a match (how to
   recognize the action — e.g. protocol + tool, or method + path), the
   canonical action_type, an advisory risk, receipt_required, the
   minimum assurance_class, and max_age_sec — the maximum age, in
   seconds, of the presented authorization receipt at verification time,
   measured from its issuance timestamp; an older receipt MUST be



Schrock                  Expires 3 January 2027                 [Page 4]

Internet-Draft        Agent Action Control Manifest            July 2026


   refused as stale.  The match member selects the surface; the
   action_type is the canonical name the authorization evidence binds
   to.  A publisher MUST NOT publish overlapping match selectors whose
   declarations conflict; a consumer that finds more than one matching
   declaration MUST apply the most restrictive one.  When
   receipt_required is true the declaration MUST also carry a control
   object:

   enforcement_point  Where the control runs (pre_execution or
      pre_effect_commit); enforcement MUST precede the effect boundary.
      For HTTP surfaces the declaration also names the transport
      binding: on refusal the service SHOULD return 428 [RFC6585] with
      the declared challenge header, and the caller presents its receipt
      in the declared proof header.

   authorization_receipt  The required receipt profile (an offline-
      verifiable authorization receipt
      [I-D.schrock-ep-authorization-receipts]).

   replay  The replay model; for consequential actions
      one_time_consumption with a required receipt identifier.

   execution_binding  That the authorized action MUST bind material
      fields observed from the _system of record_ (source:
      system_of_record), and the non-empty set of required_fields that
      MUST match.  This is what stops "approve $250K to Vendor A" from
      executing as "$300K to Vendor B".

   evidence_output  The evidence that MUST exist after the action: an
      execution attestation, a reliance packet, and a record of blocked
      attempts; optionally a transparency registration.

   A declaration MAY carry an OPTIONAL effects member: a machine-
   readable preview of what the action does, so an agent runtime or a
   human approver can weigh consequences before authorizing.  Like risk,
   effects is ADVISORY — it is not a security control and MUST NOT
   substitute for the receipt requirement; the fail-closed control is
   the enforcement point, not a label.  Its members:

   reversibility  Whether the effect can be undone: irreversible,
      hard_to_reverse, or reversible.  An honest class, not a guarantee.

   data_exposure  The most sensitive data class the action exposes or
      mutates: none, internal, pii, or regulated.

   cost_class  An order-of-magnitude impact band (none, low, material,





Schrock                  Expires 3 January 2027                 [Page 5]

Internet-Draft        Agent Action Control Manifest            July 2026


      high) — a class, not a figure: the manifest is static, and the
      actual amount is an execution-binding field observed from the
      system of record.

   downstream  External systems or services the effect propagates to, so
      a caller can see blast radius beyond the immediate resource.

   consent_required  Whether an explicit human-consent interaction is
      required for this action, distinct from the authorization receipt:
      the receipt is the durable, offline-verifiable evidence; consent
      is the interaction that produces it.  A true value means the
      runtime MUST surface the effect to a human before an authorization
      is sought.

   The effects preview and the control requirement answer different
   questions — "what will this do, and how consequential is it" versus
   "what authorization evidence is required, and how is it enforced" —
   and a runtime uses the first to decide whether to seek the second.
   Neither substitutes for the other: a low-cost_class action can still
   be irreversible and demand the strongest tier, and the effects
   preview never lowers a declared control.

   A declaration MAY additionally carry a conformance member naming the
   conformance level the enforcement claims to meet and the checks it
   passes (for example: missing receipt refused, insufficient assurance
   refused, execution mismatch refused, replay refused, tamper refused).
   This turns the declared posture into a set of independently re-
   runnable tests rather than an assertion.

   A verifier MUST be able to recompute, from the action itself, that
   the presented authorization is over the same action and meets the
   declared assurance tier; it MUST NOT rely on a self-asserted
   assurance value (see the assurance-class taxonomy
   [I-D.schrock-ep-assurance-classes]).

6.  Semantics: Declaration Is Not Enforcement

   A service MUST enforce its receipt requirement at the effect boundary
   regardless of the manifest, and a caller MUST NOT infer that an
   action is safe because the manifest omits it or marks it not-
   required.  Enforcement is authoritative; the manifest exists so the
   requirement is discoverable and auditable, not so it can be disabled
   by editing a file.  The declaration (this manifest) and the audit (an
   independent scan of the live surface) are a pair; a service that both
   publishes a manifest and passes an independent scan has a verifiable,
   not merely asserted, posture.





Schrock                  Expires 3 January 2027                 [Page 6]

Internet-Draft        Agent Action Control Manifest            July 2026


7.  Security Considerations

   *Enforcement is authoritative, not the manifest.* A manifest that
   omits an action, or marks it not-required, does not make that action
   safe; the enforcement point is the control.  Treating the manifest as
   authoritative would let an attacker who can edit or spoof it disable
   protection.

   *Integrity and authenticity.* The manifest MUST be served over an
   authenticated, integrity-protected transport and MAY be signed;
   unsigned manifests fetched over an untrusted path MUST NOT be relied
   upon beyond discovery.

   *Advisory fields are not scores.* The risk field MUST NOT be read as
   a measurement of safety or as a substitute for the receipt
   requirement.  The security property is the fail-closed control, not a
   severity label.

   *Information disclosure.* A manifest enumerates a service's high-
   consequence actions; publishers SHOULD assume it is public and SHOULD
   NOT encode secrets or internal-only endpoints.

   *Downgrade and receipt disclosure.* Because enforcement is
   authoritative, an attacker who spoofs or weakens a manifest cannot
   disable protection — a caller misled into presenting weaker or no
   evidence is refused, a denial of service at worst.  The sharper risk
   is disclosure: a spoofed manifest could induce an agent to present an
   authorization receipt — which may carry an approver identity and
   action details — to an attacker-controlled endpoint.  A consumer
   SHOULD present a receipt only to the origin from which the manifest
   was authenticated, and receipt audience binding limits what a
   misdirected receipt is worth.

8.  IANA Considerations

   This document requests registration of the following well-known URI
   in the "Well-Known URIs" registry established by [RFC8615]:

   URI suffix  agent-action-control.json

   Change controller  IETF

   Specification document  This document

   Status  permanent

9.  Normative References




Schrock                  Expires 3 January 2027                 [Page 7]

Internet-Draft        Agent Action Control Manifest            July 2026


   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions (EP)", Work in Progress, Internet-Draft, draft-
              schrock-ep-authorization-receipts-05, July 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              authorization-receipts-05>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC6585]  Nottingham, M. and R. Fielding, "Additional HTTP Status
              Codes", RFC 6585, April 2012,
              <https://www.rfc-editor.org/info/rfc6585>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, May 2017,
              <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8259]  Bray, T., "The JavaScript Object Notation (JSON) Data
              Interchange Format", STD 90, RFC 8259, December 2017,
              <https://www.rfc-editor.org/info/rfc8259>.

   [RFC8615]  Nottingham, M., "Well-Known Uniform Resource Identifiers
              (URIs)", RFC 8615, May 2019,
              <https://www.rfc-editor.org/info/rfc8615>.

10.  Informative References

   [I-D.schrock-ep-assurance-classes]
              Schrock, I., "Assurance Classes for Authorization
              Receipts", Work in Progress, Internet-Draft, draft-
              schrock-ep-assurance-classes-00, July 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              assurance-classes-00>.

   [RFC8414]  Jones, M., Sakimura, N., and J. Bradley, "OAuth 2.0
              Authorization Server Metadata", RFC 8414, June 2018,
              <https://www.rfc-editor.org/info/rfc8414>.

   [RFC9116]  Foudil, E. and Y. Shafranovich, "A File Format to Aid in
              Security Vulnerability Disclosure", RFC 9116, April 2022,
              <https://www.rfc-editor.org/info/rfc9116>.

   [RFC9943]  Birkholz, H., Delignat-Lavaud, A., Fournet, C., Deshpande,
              Y., and S. Lasker, "An Architecture for Trustworthy and
              Transparent Digital Supply Chains", RFC 9943, March 2026,
              <https://www.rfc-editor.org/info/rfc9943>.



Schrock                  Expires 3 January 2027                 [Page 8]

Internet-Draft        Agent Action Control Manifest            July 2026


Appendix A.  Example Manifest (Non-Normative)

   The following example, abridged from a live deployment, declares one
   consequential action.  A payment-release tool is reachable over a
   tool-call protocol; executing it requires a device-verified named-
   human authorization receipt no older than 900 seconds, bound to the
   material fields as observed from the system of record, consumed
   exactly once, with post-execution evidence.

   {
     "@version": "EP-ACTION-CONTROL-MANIFEST-v0.2",
     "$schema": "https://example.com/schemas/action-control-v0.2.json",
     "profile": "emilia.action-control",
     "service": {
       "name": "Example payments service",
       "issuer": "https://example.com",
       "manifest_url":
         "https://example.com/.well-known/agent-action-control.json"
     },
     "defaults": {
       "decision_point": "pre_effect_commit",
       "missing_receipt": "refuse",
       "invalid_receipt": "refuse",
       "stale_receipt": "refuse",
       "replay": "one_time_consumption",
       "evidence_log": "strict"
     },
     "evidence_profiles": {
       "authorization_receipt": "EP-RECEIPT-v1",
       "execution_attestation": "EP-EXECUTION-ATTESTATION-v1",
       "reliance_packet": "EP-RELIANCE-PACKET-v1",
       "transparency": "SCITT-compatible Signed Statement"
     },
     "actions": [
       {
         "id": "money_movement.release",
         "action_type": "payment.release",
         "risk": "critical",
         "receipt_required": true,
         "assurance_class": "class_a",
         "max_age_sec": 900,
         "match": { "protocol": "mcp", "tool": "release_payment" },
         "effects": {
           "reversibility": "irreversible",
           "data_exposure": "regulated",
           "cost_class": "high",
           "downstream": ["ledger", "counterparty_bank", "settlement"],
           "consent_required": true



Schrock                  Expires 3 January 2027                 [Page 9]

Internet-Draft        Agent Action Control Manifest            July 2026


         },
         "control": {
           "enforcement_point": "pre_effect_commit",
           "status": 428,
           "challenge_header": "Receipt-Required",
           "proof_header": "X-EMILIA-Receipt",
           "authorization_receipt": {
             "required": true,
             "profile": "EP-RECEIPT-v1",
             "verifier": "offline"
           },
           "replay": {
             "mode": "one_time_consumption",
             "receipt_id_required": true
           },
           "execution_binding": {
             "required": true,
             "source": "system_of_record",
             "required_fields": [
               "action_type", "amount_usd", "currency",
               "payment_instruction_id", "beneficiary_account_hash"
             ]
           },
           "evidence_output": {
             "audit_event": true,
             "execution_attestation": true,
             "reliance_packet": true,
             "blocked_attempts": true
           }
         },
         "conformance": {
           "level": "EG-1",
           "checks": [
             "missing_receipt_refused",
             "software_on_classA_refused",
             "execution_mismatch_refused",
             "replay_refused",
             "tamper_refused"
           ]
         }
       }
     ]
   }

Author's Address






Schrock                  Expires 3 January 2027                [Page 10]

Internet-Draft        Agent Action Control Manifest            July 2026


   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai















































Schrock                  Expires 3 January 2027                [Page 11]
```
