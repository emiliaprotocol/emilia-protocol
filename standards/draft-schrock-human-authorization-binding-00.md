# Binding Named-Human Authorization Evidence into Agent-Action Records
## draft-schrock-human-authorization-binding-00

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               3 July 2026
Expires: 4 January 2027


  Binding Named-Human Authorization Evidence into Agent-Action Records
              draft-schrock-human-authorization-binding-00

Abstract

   A recurring pattern spans the agent-action record formats now in
   development: a record about an agent's action reserves a place for
   "the human authorization" — an approver disposition, an authority
   context, a human-override field, an actor slot, a signed grant, an
   approval reference — and leaves its semantics undefined.  Each
   format, reasonably, does not want to specify human-authorization
   evidence itself; none, so far, says what filling the slot means.
   This document defines that one thing, host-agnostically: how any
   record binds named-human authorization evidence, either BY REFERENCE
   (a content digest of the authorization artifact's canonical bytes) or
   EMBEDDED (a compact, self-describing claim carrying named approvals
   and optional distinct-human quorum semantics), with five requirements
   that make the binding mean the same thing in every host: digest
   grounding, action agreement, verified-versus-accepted discipline,
   fail-closed absence, and embedded/referenced consistency.  An
   informative appendix maps the binding onto the reserved slots of
   eleven current documents.  This document defines no new authorization
   format: the referenced evidence verifies under its own specification.

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

   This Internet-Draft will expire on 4 January 2027.





Schrock                  Expires 4 January 2027                 [Page 1]

Internet-Draft         Human-Authorization Binding             July 2026


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
     1.1.  Terminology . . . . . . . . . . . . . . . . . . . . . . .   3
   2.  Binding by Reference  . . . . . . . . . . . . . . . . . . . .   3
   3.  The Embedded Claim  . . . . . . . . . . . . . . . . . . . . .   4
   4.  Binding Requirements  . . . . . . . . . . . . . . . . . . . .   4
   5.  Claim Naming  . . . . . . . . . . . . . . . . . . . . . . . .   5
   6.  Security Considerations . . . . . . . . . . . . . . . . . . .   5
   7.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   6
   8.  References  . . . . . . . . . . . . . . . . . . . . . . . . .   6
     8.1.  Normative References  . . . . . . . . . . . . . . . . . .   6
     8.2.  Informative References  . . . . . . . . . . . . . . . . .   6
   Appendix A.  Host-Format Mappings (Informative) . . . . . . . . .   6
   Appendix B.  Implementation Status  . . . . . . . . . . . . . . .   8
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .   8

1.  Introduction

   Record formats for agent actions are proliferating, and almost all of
   them make the same, sound scoping decision: human authorization is
   somebody else's format.  The result is a set of reserved-but-empty
   slots.  A post-execution action capsule carries an approver
   disposition whose authority is opaque; a pre-execution permit stubs
   an authority context; audit-trail records carry a human-override
   field with a privacy carve-out where the human should be; a
   provenance graph has an optional actor; an audit architecture
   requires a "signed grant" whose format is an unassigned work item; an
   intent chain names an approval reference with no semantics.  Each
   slot is an invitation.  Eleven invitations with eleven ad-hoc answers
   would be worse than none.






Schrock                  Expires 4 January 2027                 [Page 2]

Internet-Draft         Human-Authorization Binding             July 2026


   This document is the single answer: a host-agnostic definition of
   what it means to bind named-human authorization evidence into any
   record, plus the small set of requirements that keep the binding
   trustworthy regardless of host.  It deliberately does not define the
   authorization evidence itself — a bound artifact verifies under its
   own specification (for example
   [I-D.schrock-ep-authorization-receipts] for named-human receipts and
   quorum) — and the appendix mappings to host formats are informative
   descriptions of public slot fields, offered for host authors to
   correct or adopt.

1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   Host record: any signed or logged record about an agent action that
   carries the binding (a capsule, permit, audit record, provenance
   node, token, or chain).  Authorization artifact: the evidence being
   bound (a named-human authorization receipt, a quorum receipt, or an
   equivalent artifact defined elsewhere).

2.  Binding by Reference

   The reference form is a JSON member (claim name
   "human_authorization_ref"; see Section 5) carried anywhere in the
   host record the host format designates:

   "human_authorization_ref": {
     "digest": "sha256:<hex of the artifact's canonical bytes>",
     "format": "ep-receipt | ep-quorum | <other artifact type>",
     "locator": "<OPTIONAL hint URI; acquisition is out of scope>"
   }

   The digest MUST be computed over the authorization artifact's
   canonical bytes as defined by the artifact's own specification (for
   EP artifacts, the JCS [RFC8785] I-JSON profile).  The locator is a
   hint only: a verifier obtains the artifact through whatever channel
   the deployment provides, and relies on digest equality, never on the
   channel.  The reference form supports disclosure minimization: a host
   record can travel without the artifact, and a relying party that
   requires the evidence fails closed until the bytes are produced.






Schrock                  Expires 4 January 2027                 [Page 3]

Internet-Draft         Human-Authorization Binding             July 2026


3.  The Embedded Claim

   The embedded form carries the evidence inline as a compact, self-
   describing claim (claim name "human_authorization"):

   "human_authorization": {
     "v": "EP-HAC-v1",
     "action_digest": "sha256:<hex>",
     "mode": "single | quorum",
     "approvals": [
       { "approver": "<named accountable principal>",
         "role": "<OPTIONAL>",
         "key_class": "A | B | C",
         "signoff": { "...the approver's own signature object..." } }
     ],
     "policy": "<OPTIONAL policy identifier>",
     "quorum": { "required": 2, "distinct_humans": true,
                 "ordered": false }
   }

   Each approval names an accountable human principal and carries that
   principal's own signature over the action binding, verifiable offline
   under the artifact specification the claim profiles.  When mode is
   "quorum", the distinct-humans and ordering semantics of
   [I-D.schrock-ep-quorum] apply: the required number of DISTINCT
   accountable humans, not merely distinct signatures.  Key classes
   classify key custody as defined by the receipts specification and
   imply nothing about assurance levels.

4.  Binding Requirements

   Five requirements hold for every host, and they are what make the
   binding mean the same thing everywhere:

   1.  B1: Digest grounding.  A binding is credited only against
       artifact bytes: the reference form by digest equality, the
       embedded form by verifying the contained signatures.  A host
       field that merely asserts "a human approved" without either MUST
       NOT be treated as human-authorization evidence.

   2.  B2: Action agreement.  When the host record binds an action (via
       an action digest, a subject digest, or equivalent), the
       authorization artifact's action binding MUST agree with it.  An
       artifact authorizing a different action MUST invalidate the
       binding, not merely weaken it.






Schrock                  Expires 4 January 2027                 [Page 4]

Internet-Draft         Human-Authorization Binding             July 2026


   3.  B3: Verified versus accepted.  Verifying the binding (digests and
       signatures hold) is distinct from accepting it (the relying party
       trusts the artifact's issuer via out-of-band pinned key
       material).  A verifier MUST report the two separately, and a
       binding from an unpinned issuer MUST NOT be accepted.

   4.  B4: Fail-closed absence.  The absence of a binding is the absence
       of evidence, never a default.  A relying party whose policy
       requires human authorization MUST treat an unbound or
       unresolvable binding as insufficient.  Absence becomes positive
       evidence only through a signed observed-absence statement naming
       the search performed.

   5.  B5: Consistency.  When a host record carries both forms, the
       embedded claim's canonical bytes MUST hash to the reference's
       digest; a mismatch invalidates both.

5.  Claim Naming

   The canonical claim names are "human_authorization_ref" and
   "human_authorization".  The claim was first deployed under the
   vendor-prefixed name "ep_human_authorization"; implementations SHOULD
   accept it and MUST treat it as an alias of the embedded form.  Host
   formats that already name their slot (an authority context, an actor,
   an approval reference) MAY carry the binding object under their own
   member name; the object's members, not the slot's name, are what this
   document defines.

6.  Security Considerations

   The slot is a target.  An attacker who can fill a host record's
   authorization slot chooses what a relying party later treats as the
   human's approval; every defense here exists for that reason.  B1
   removes assertion-only filling; B2 defeats splicing a genuine
   artifact from a different action (the confused-deputy case); B3
   prevents a self-issued artifact from being self-accepted; B4 prevents
   silence from being read as consent; B5 prevents the two forms from
   telling two stories.  Replay and one-time-use semantics belong to the
   authorization artifact and its enforcement point; a host record MUST
   NOT extend an artifact's validity by carrying it.  The reference form
   additionally serves privacy: the named human travels only in the
   artifact, which can be withheld until a relying party with a need to
   know requires it — at the cost, by B4, of the evidence not counting
   until produced.







Schrock                  Expires 4 January 2027                 [Page 5]

Internet-Draft         Human-Authorization Binding             July 2026


7.  IANA Considerations

   This document has no IANA actions.  Registration of the claim names
   in the JWT and CWT claims registries is anticipated for a future
   revision, after host-format feedback.

8.  References

8.1.  Normative References

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

8.2.  Informative References

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions", Work in Progress, Internet-Draft, draft-schrock-
              ep-authorization-receipts-05, July 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-
              authorization-receipts/>.

   [I-D.schrock-ep-quorum]
              Schrock, I., "Multi-Party Human Authorization (EP-
              QUORUM)", Work in Progress, Internet-Draft, draft-schrock-
              ep-quorum-01, June 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-
              quorum/>.

Appendix A.  Host-Format Mappings (Informative)

   The following mappings describe, from each cited document's public
   text, where the binding fits.  They are informative, derived from the
   revisions named, and offered for the host authors to correct or
   adopt; absence of a format from this list implies nothing, and no
   mapping asserts a host author's endorsement.




Schrock                  Expires 4 January 2027                 [Page 6]

Internet-Draft         Human-Authorization Binding             July 2026


   *  draft-mih-scitt-agent-action-capsule-01: a capsule whose
      disposition reports a human approver carries
      human_authorization_ref alongside the disposition; B2 binds it to
      the capsule's action digest.

   *  draft-munoz-scitt-permit-profile-00: the authority_context member
      carries the reference form; the permit's decision then rests on
      evidence, not assertion.

   *  draft-sharif-agent-audit-trail-00: the human_override field
      carries the reference form, giving the named-but-privacy-carved
      human an artifact rather than an inline identity.

   *  draft-bates-atp-00: a provenance node's actor field carries the
      reference form; validators add B1-B5 to lineage checks.

   *  draft-aylward-aiga-00: the reserved X.509v3 extension slot carries
      the reference digest, binding machine identity to the human
      authorization behind its issuance.

   *  draft-nelson-agent-delegation-receipts-10: a delegation receipt
      carries the embedded claim as a co-signing layer where multi-party
      approval is required (multi-party is out of the host's scope by
      its own statement).

   *  draft-rosenberg-aiproto-cheq-00: the confirmation object's
      signature, left TBD by the host, is the embedded claim; a quorum
      of confirmations aggregates under mode "quorum".

   *  draft-yossif-psea-02: a Verifier's attestation-result object (out
      of the host's scope) carries the reference form binding the
      presence proof to the authorization it evidenced.

   *  draft-kuehlewind-audit-architecture-00: the "signed grant" work
      item (WI-5) and step-up approval responses are instances of the
      embedded claim; Authorization Transition Records carry the
      reference form.

   *  The ACP (agent communication protocols) charter's "confirmation
      and evidence requirements for AI agent operations": the
      confirmation step's evidence is the embedded claim; scoped access
      tokens carry the reference form.

   *  SPICE-adjacent intent chains: the approval_ref member is the
      reference form's digest, giving the named field its missing
      semantics.





Schrock                  Expires 4 January 2027                 [Page 7]

Internet-Draft         Human-Authorization Binding             July 2026


Appendix B.  Implementation Status

   The embedded claim profiles a shipped format (the EP receipt and
   quorum artifacts, three-language verifier suite with shared
   conformance vectors in one repository).  The binding checks (digest
   grounding, action agreement, verified-versus-accepted, fail-closed
   absence) are exercised by the reference implementation's evidence-
   graph layer and by a deterministic binding vector published with the
   repository (examples/binding/human-authorization-binding-vector.mjs).

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai



































Schrock                  Expires 4 January 2027                 [Page 8]

```
