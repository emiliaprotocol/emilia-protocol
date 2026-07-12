# Assurance Classes for Authorization Receipts
## draft-schrock-ep-assurance-classes-00

> Readable mirror of the xml2rfc source ([`draft-schrock-ep-assurance-classes-00.xml`](./draft-schrock-ep-assurance-classes-00.xml)). The XML is authoritative.

```
Network Working Group                                         I. Schrock
Intended status: Informational                              12 July 2026
Expires: 13 January 2027

              Assurance Classes for Authorization Receipts
                 draft-schrock-ep-assurance-classes-00

Abstract

   Authorization of a high-risk agent action is not binary.  A software
   signer asserting a policy decision, an authenticated human clicking
   approve, a human completing a device user-verification ceremony, and
   a quorum of distinct humans each doing so are four materially
   different levels of assurance — and a policy for a consequential
   action needs to say which level it demands.

   This document defines a small, ordered taxonomy of assurance classes
   for authorization receipts [I-D.schrock-ep-authorization-receipts] —
   Class S, Class H, Class V, and Class Q — the monotonic comparison
   rule by which a required class is satisfied, and the central anti-
   forgery invariant that a class asserted in a receipt payload is
   treated as the lowest class until it is proof-backed.  The taxonomy
   is the policy primitive an enforcement point, a manifest, or an
   authority registry uses to express and check "how strong must the
   human authorization be?"

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

   This Internet-Draft will expire on 13 January 2027.

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
   3.  The Assurance Classes . . . . . . . . . . . . . . . . . . . .   3
   4.  The Comparison Rule . . . . . . . . . . . . . . . . . . . . .   4
   5.  Proof-Backed Assurance (the Anti-Forgery Invariant) . . . . .   4
   6.  Relationship to Other Profiles  . . . . . . . . . . . . . . .   4
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .   5
   8.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   5
   9.  Normative References  . . . . . . . . . . . . . . . . . . . .   5
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .   5

1.  Introduction

   A policy that says only "this action requires authorization"
   underspecifies the control.  Releasing a $10 refund and wiring $10M
   do not warrant the same authorization strength, and a system that
   treats a software-signed decision and a two-person device-verified
   approval as equivalent has no defense in depth.  What is missing is a
   shared, ordered vocabulary for _how strong_ the human authorization
   behind a receipt is, so that policy can require a floor and a
   verifier can enforce it.

   This document defines that vocabulary as four assurance classes and
   the rule for comparing them.  It does not define how a signature is
   produced, how a key is held, or how a quorum is gathered; those
   belong to the authorization-receipt specification
   [I-D.schrock-ep-authorization-receipts] and to deployment.  It
   defines only the classes, their order, the satisfaction rule, and the
   requirement that a claimed class be proven rather than trusted.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

3.  The Assurance Classes

   Four assurance classes are defined, in increasing order of assurance.
   Each maps to a concrete assurance value carried in a receipt's
   assurance field.  The identifiers are mnemonic (S for software, H for
   authenticated human, V for device-verified human, Q for quorum) and
   are deliberately disjoint from the key-custody classes (Class A,
   Class B, Class C) of [I-D.schrock-ep-authorization-receipts], which
   classify who holds the approver's signing key, not how strong the
   authorization ceremony behind a receipt was.

   Class S — software / automation signer (receipt assurance value:
   "software")  The authorization is asserted by a software component or
      automation key, not by a human completing an interactive ceremony.
      This is the lowest class and the default floor (Section 5).
      Appropriate for low-risk or read-mostly actions.

   Class H — authenticated human, no device user verification
   (RESERVED, OPTIONAL)  A human authenticated to the approving system
      approved the action, but without a hardware user-verification
      ceremony bound to the signing key.  Class H is defined for
      deployments that distinguish an authenticated-human approval from
      a device-verified one; a deployment that does not make this
      distinction need not implement Class H.

   Class V — device user-verified human (receipt assurance value:
   "class_a")  A named human completed a device user-verification
      ceremony (for example WebAuthn user verification / passkey with a
      local gesture) whose result is bound to the signing key that
      produced the receipt.  This is the baseline for high-risk actions.
      The receipt assurance value "class_a" is retained unchanged for
      compatibility with deployed receipts; it names the key-custody
      Class A ceremony of [I-D.schrock-ep-authorization-receipts] that
      proves this assurance class, and is a value string, not an
      identifier of this taxonomy.

   Class Q — quorum of distinct humans (receipt assurance value:
   "quorum")  Two or more distinct humans, each meeting at least Class

      V, authorized the same action under an m-of-n rule with distinct-
      human enforcement.  Class Q is the highest class and the
      appropriate floor for critical, separation-of-duties actions.

4.  The Comparison Rule

   The classes form a total order:

   Class S < Class H < Class V < Class Q

   A policy states the minimum class an action requires.  A receipt
   satisfies the requirement if and only if its _proven_ class
   (Section 5) is greater than or equal to the required class on this
   order.  A verifier MUST reject a receipt whose proven class is lower
   than the required class, and MUST fail closed when it cannot
   determine the proven class.

5.  Proof-Backed Assurance (the Anti-Forgery Invariant)

   A class value present in a receipt payload is a _claim_, not
   evidence.  An attacker who can shape a payload can write "quorum"
   into it as easily as "software".  Therefore:

   A verifier MUST treat a claimed assurance class as the lowest class
   (Class S) until the class is proof-backed by evidence the verifier
   independently checks — for example a device user-verification
   attestation for Class V, or the required number of distinct,
   individually verified human signatures for Class Q.  A receipt that
   asserts Class V or Class Q without the corresponding proof MUST be
   treated as Class S for the comparison in Section 4.

   This inverts the trust default: assurance is earned by proof, not
   granted by assertion.  It is the difference between a system that can
   be talked into a high-assurance decision and one that cannot.

6.  Relationship to Other Profiles

   The assurance class is the shared policy primitive across the EP
   profiles: an Agent Action Manifest declares the class an action
   requires; an enforcement point compares the proven class of a
   presented receipt against that requirement; an authority registry
   records the maximum class a given approver is entitled to assert.
   This document defines the classes and their comparison; those
   profiles consume them.

7.  Security Considerations

   *Downgrade and class-confusion.* The comparison rule is only sound if
   the proven class cannot be inflated by a claim.  The proof-backed
   invariant (Section 5) is the control; implementations MUST NOT read
   the class from an untrusted payload field and act on it without
   verifying the underlying evidence.

   *Fail closed on ambiguity.* If a verifier cannot establish the proven
   class — missing attestation, unrecognized evidence, partial quorum —
   it MUST treat the receipt as failing the requirement, never as
   provisionally meeting it.

   *Quorum distinctness.* Class Q depends on the distinctness of the
   humans in the quorum; a quorum satisfied by one human holding
   multiple keys, or by an initiator approving their own action, does
   not meet Class Q regardless of signature count.

8.  IANA Considerations

   This document has no IANA actions.  A future revision may request an
   IANA registry for authorization-receipt assurance classes; the four
   classes here are defined in-document pending that.

9.  Normative References

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions (EP)", Work in Progress, Internet-Draft, draft-
              schrock-ep-authorization-receipts-06, July 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              authorization-receipts-06>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, May 2017,
              <https://www.rfc-editor.org/info/rfc8174>.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai
```
