# A Human Authority Registry for Agent-Action Authorization
## draft-schrock-ep-authority-registry-00

> Readable mirror of the xml2rfc source ([`draft-schrock-ep-authority-registry-00.xml`](./draft-schrock-ep-authority-registry-00.xml)). The XML is authoritative.

```
Network Working Group                                         I. Schrock
Intended status: Informational                               2 July 2026
Expires: 3 January 2027

       A Human Authority Registry for Agent-Action Authorization
                 draft-schrock-ep-authority-registry-00

Abstract

   Workload-identity work answers "which machine acted" and token work
   answers "what was requested."  Neither answers a question a high-
   consequence authorization depends on: _is the human whose signature
   backs this action actually entitled to approve this class of action,
   for this organization, right now, with this key — and are they barred
   from approving their own request?_

   This document defines the Human Authority Registry: the authoritative
   record a verifier or enforcement point consults to decide whether an
   authorization receipt [I-D.schrock-ep-authorization-receipts] was
   produced by an in-scope, currently authorized approver.  It specifies
   the registry entry (approver identity, organization, permitted action
   classes, maximum assurance class, validity window, signing keys,
   revocation status, self-approval and quorum constraints), the
   verification rule binding a receipt to an active entry, and how the
   relevant registry state is distributed for offline checking.  It is
   complementary to workload-identity and delegation work, not a
   replacement for either.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.

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
   3.  Authority Entry . . . . . . . . . . . . . . . . . . . . . . .   3
   4.  Verification Rule . . . . . . . . . . . . . . . . . . . . . .   4
   5.  Offline Verification  . . . . . . . . . . . . . . . . . . . .   5
   6.  Relationship to Other Work  . . . . . . . . . . . . . . . . .   5
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .   5
   8.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   5
   9.  Normative References  . . . . . . . . . . . . . . . . . . . .   6
   10. Informative References  . . . . . . . . . . . . . . . . . . .   6
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .   6

1.  Introduction

   An authorization receipt proves that some keyholder signed an exact
   action.  Whether that keyholder was _allowed_ to authorize that
   action is a separate question, and it is the question that turns a
   signature into an accountable authorization.  Today that entitlement
   lives in scattered, operator-internal places: an IAM group, a
   spreadsheet of approvers, an application's own database.  None of it
   is portable, and none of it lets a third party — an auditor, a
   counterparty, a regulator — confirm offline that the human who signed
   was authorized to.

   This document defines a registry for exactly that: the record of
   which humans may approve which action classes, for which
   organization, during which window, with which keys, subject to
   revocation and separation-of-duties constraints.  It is deliberately
   about _human authority for actions_, distinct from workload identity
   (which principal is running) and from delegation of machine scope.
   It composes with the authorization-receipt and enforcement-point
   profiles: the receipt carries the signature, the registry says
   whether the signer was entitled, and the enforcement point consults
   both.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   Approver  A named, accountable human entitled to authorize actions.

   Registry  The authoritative collection of authority entries defined
      here.

   Entry  One approver's authority record (Section 3).

3.  Authority Entry

   An authority entry is a record with at least the following fields:

   approver_id (REQUIRED)  A stable identifier for the accountable
      human.

   org (REQUIRED)  The organization on whose behalf the approver may
      authorize.

   action_classes (REQUIRED)  The set of action types or classes the
      approver may authorize.  An authorization for an action outside
      this set MUST NOT be accepted.

   max_assurance_class (REQUIRED)  The highest assurance class the
      approver may assert (see the assurance-class taxonomy).  An entry
      does not raise a receipt's proven class; it bounds it.

   keys (REQUIRED)  The public key(s) the approver signs with.  A
      receipt whose signing key is not among these MUST NOT be
      attributed to this approver.

   valid_from / valid_until (REQUIRED)  The window during which the
      entry is effective.  An authorization timestamped outside the
      window MUST be refused.

   revoked (REQUIRED)  Revocation status and effective time.  A key or
      entry revoked as of time T invalidates authorizations produced
      after T.

   self_approval_forbidden (REQUIRED)  Whether this approver may
      authorize an action they also initiated.  When true (the
      RECOMMENDED default for high-risk actions), an authorization whose
      initiator equals the approver MUST be refused.

   quorum_eligible (OPTIONAL)  Whether this approver may count toward a
      Class Q quorum, and any group constraints on distinctness.

4.  Verification Rule

   An authorization receipt is _authority-backed_ for an action if and
   only if, at the authorization time:

   1.  the receipt's signing key resolves to a registry entry;

   2.  the entry is within its validity window and not revoked as of the
       authorization time;

   3.  the action's class is within the entry's action_classes;

   4.  the receipt's proven assurance class does not exceed the entry's
       max_assurance_class;

   5.  if self_approval_forbidden is true, the approver is not the
       initiator of the action; and

   6.  for a Class Q authorization, each contributing approver satisfies
       (1)–(5) and the approvers are distinct and quorum-eligible.

   If any condition fails, the receipt MUST NOT be treated as authority-
   backed, and a verifier that cannot resolve the entry MUST fail
   closed.

5.  Offline Verification

   Auditors, counterparties, and edge deployments frequently verify
   without live access to the registry.  A registry operator SHOULD
   publish signed, timestamped registry snapshots (or per-entry signed
   attestations) so a relying party can perform the Section 4 checks
   offline against a snapshot whose freshness it can bound.  A snapshot
   older than a relying party's freshness policy MUST be treated as
   unable to establish authority, not as granting it.

6.  Relationship to Other Work

   This registry is about human approval authority for actions.  It is
   orthogonal to workload identity (WIMSE), which establishes which
   software principal is running, and complementary to delegation and
   authorization-evidence-chain work
   [I-D.schrock-ep-authorization-evidence-chain], which binds a
   delegation from a human authority root down to an acting agent.  The
   registry is the source of truth for the human-authority root those
   chains terminate in, and the entitlement an enforcement point checks
   a receipt against.

7.  Security Considerations

   *The registry is a trust root; protect it accordingly.* Whoever can
   write an entry can authorize approvers.  Registry writes MUST be
   strongly controlled and auditable, and snapshots MUST be signed so
   relying parties detect tampering.

   *Revocation propagation.* The security of revocation depends on
   relying parties consulting sufficiently fresh state.  Offline
   verifiers MUST enforce a freshness bound on snapshots; a stale
   snapshot cannot be used to accept an authorization from a since-
   revoked key.

   *Separation of duties.* The self_approval_forbidden and quorum-
   distinctness rules are the defense against a single compromised or
   coerced insider authorizing their own high-risk action; they MUST be
   enforced at verification, not merely recorded.

   *Bounding, not granting.* An entry bounds what an approver may
   assert; it never raises a receipt's proven assurance class.  Proven
   assurance still comes from the receipt's own evidence.

8.  IANA Considerations

   This document has no IANA actions.

9.  Normative References

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions (EP)", Work in Progress, Internet-Draft, draft-
              schrock-ep-authorization-receipts-05, July 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              authorization-receipts-05>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, May 2017,
              <https://www.rfc-editor.org/info/rfc8174>.

10.  Informative References

   [I-D.schrock-ep-authorization-evidence-chain]
              Schrock, I., "Authorization Evidence Chain (EP)", Work in
              Progress, Internet-Draft, draft-schrock-ep-authorization-
              evidence-chain-00, June 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              authorization-evidence-chain-00>.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai
```
