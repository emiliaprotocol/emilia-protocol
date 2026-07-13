# Canonical Action Identifiers for Composable Agent-Action Evidence
## draft-schrock-canonical-action-identifier-00

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                              13 July 2026
Expires: 14 January 2027


   Canonical Action Identifiers for Composable Agent-Action Evidence
             draft-schrock-canonical-action-identifier-00

Abstract

   Evidence about one agent action is now produced by several
   independent ecosystems at once: an authorization receipt states who
   approved the action, a payment mandate states what a payer agreed
   to, a transparency-log statement makes a claim about the action
   auditable, an action record describes what was executed.  Each
   artifact digests the action in its own native form and verifies
   inside its own trust boundary with its own tooling.  This document
   defines the Canonical Action Identifier (CAID), the SHA-256 digest
   of the action object's canonical form under the JSON
   Canonicalization Scheme (JCS), and the rule by which such artifacts
   compose: each artifact independently binds the same CAID, never by
   one artifact embedding or ingesting another's evidence.  A relying
   party states a requirement expression over named leg types; the
   verdict is ALLOW only when every required leg verifies under its
   own rules and binds the identical CAID, and any splice, forgery, or
   absence yields a refusal naming the unsatisfied requirement.  The
   identifier carries no semantics beyond identity: it does not
   authorize and does not attest; it names the exact action so that
   independent claims about that action can be joined.  This document
   defines no receipt, mandate, or statement format; each leg verifies
   under its own specification.

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



Schrock                 Expires 14 January 2027                 [Page 1]

Internet-Draft        Canonical Action Identifiers             July 2026


   This Internet-Draft will expire on 14 January 2027.

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

   1.  Introduction . . . . . . . . . . . . . . . . . . . . . . . .   3
     1.1.  Terminology . . . . . . . . . . . . . . . . . . . . . .   4
   2.  The Canonical Action Identifier  . . . . . . . . . . . . . .   4
     2.1.  Computation . . . . . . . . . . . . . . . . . . . . . .   4
     2.2.  Canonicalization Profile  . . . . . . . . . . . . . . .   5
   3.  The Join Rule  . . . . . . . . . . . . . . . . . . . . . . .   5
     3.1.  The Digest-Binding Record . . . . . . . . . . . . . . .   5
     3.2.  Verifying a Leg . . . . . . . . . . . . . . . . . . . .   6
   4.  Fail-Closed Composition  . . . . . . . . . . . . . . . . . .   6
     4.1.  Relying-Party Inputs  . . . . . . . . . . . . . . . . .   6
     4.2.  The Requirement Expression  . . . . . . . . . . . . . .   7
     4.3.  Verdict and Refusals  . . . . . . . . . . . . . . . . .   7
   5.  Identity, Not Authority  . . . . . . . . . . . . . . . . . .   8
   6.  Relationship to Existing Evidence Ecosystems . . . . . . . .   8
   7.  Security Considerations  . . . . . . . . . . . . . . . . . .   9
   8.  IANA Considerations  . . . . . . . . . . . . . . . . . . . .  11
   9.  References . . . . . . . . . . . . . . . . . . . . . . . . .  11
     9.1.  Normative References  . . . . . . . . . . . . . . . . .  11
     9.2.  Informative References  . . . . . . . . . . . . . . . .  11
   Appendix A.  Implementation Status . . . . . . . . . . . . . . .  12
   Author's Address . . . . . . . . . . . . . . . . . . . . . . . .  13










Schrock                 Expires 14 January 2027                 [Page 2]

Internet-Draft        Canonical Action Identifiers             July 2026


1.  Introduction

   Several ecosystems now emit signed evidence about agent actions,
   and they converge on the same scene: one consequential action,
   several independently produced artifacts about it.  An
   authorization receipt names the human or quorum that approved the
   action.  A payment mandate records, in the payment ecosystem's own
   cart schema, what a payer agreed to.  A transparency-log statement
   makes a claim about the action registrable and auditable.  An
   action or audit record describes what was executed.  Each artifact
   is signed by a different issuer, digests the action in a different
   native form, and verifies with different tooling under a different
   specification.  None of them is wrong to do so.

   The open problem is joining them.  Two answers circulate, and both
   are bad.  The first is the envelope: one format grows fields to
   embed the others, and every verifier of the envelope inherits the
   obligation to verify everything inside it.  The second is
   ingestion: one verifier consumes another verifier's output as
   evidence inside its own trust boundary, and after that a relying
   party can no longer say whose rules established what.

   This document specifies a deliberately thin third answer: a shared
   name.  The Canonical Action Identifier (CAID) is a digest of the
   action object itself, computed the same way by everyone.
   Independently produced artifacts compose by each binding the same
   CAID.  Nothing is embedded and nothing is ingested; each leg keeps
   verifying inside its own trust boundary with its own tooling, and
   the CAID is the only shared coordinate between legs.  A relying
   party then states which leg types it requires and obtains a single
   fail-closed verdict.  Each claim in the composition survives as a
   durable signed artifact bound to the exact action, verifiable
   offline against keys the relying party has pinned, independent of
   any mediator that carried it.

   This document is a composition layer, not a competitor to any
   evidence format.  It defines no authorization receipt, no payment
   mandate, no transparency-log statement, and no action record, and
   it does not profile or replace any of them.  Each of those
   ecosystems keeps its own artifact, schema, and verifier; this
   document specifies only the identifier they can share and the rule
   for joining on it.








Schrock                 Expires 14 January 2027                 [Page 3]

Internet-Draft        Canonical Action Identifiers             July 2026


1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   Action object: the JSON object describing the exact action the
   evidence is about: its type, its parameters, its target, its
   requested time.  Which members an action object carries is a
   deployment decision; this document takes the object as given.

   CAID: the Canonical Action Identifier of an action object, computed
   as specified in Section 2.

   Leg: one independently produced evidence artifact about the action,
   together with the material its own specification requires to verify
   it.

   Leg type: a short identifier naming a class of leg for use in
   requirement expressions.

   Native digest: the digest a leg's own ecosystem computes over its
   own form of the action or artifact.

   Digest-binding record: the signed record (Section 3.1) by which a
   leg binds its native digest to the CAID.

   Relying party: the party that composes the legs and acts on the
   verdict.

2.  The Canonical Action Identifier

2.1.  Computation

   The CAID of an action object is the SHA-256 [RFC6234] digest of the
   action object's canonical form under the JSON Canonicalization
   Scheme (JCS) [RFC8785], represented as lowercase hexadecimal:

      CAID = lowercase-hex(SHA-256(JCS(action-object)))

   Where a digest value is carried in an artifact, it MAY be prefixed
   with "sha256:".  A CAID is credited only by recomputation: a party
   that holds an action object recomputes the digest from the object's
   canonical bytes rather than trusting a carried value, and the
   relying party's expected CAID comes from its own copy of the action
   object (Section 4.1).


Schrock                 Expires 14 January 2027                 [Page 4]

Internet-Draft        Canonical Action Identifiers             July 2026


   Two action objects that differ in any member have different CAIDs,
   up to the collision resistance of SHA-256.  The identifier names
   exactly the object that was canonicalized: a member not present in
   the action object is not named by its CAID.

2.2.  Canonicalization Profile

   RFC 8785 serializes numbers using ECMAScript conventions, and
   implementations in other languages commonly serialize non-integer
   reals differently, so a raw JSON real in an action object can
   canonicalize to different bytes across implementations.  Action
   objects used with this document SHOULD therefore restrict scalar
   values to strings, booleans, null, and integers within the safe
   integer range (an I-JSON [RFC7493] discipline), and SHOULD carry
   non-integer quantities as strings; monetary amounts customarily
   already are.  The reference implementation (Appendix A) enforces
   exactly this profile and rejects values outside it rather than
   canonicalizing them ambiguously.

3.  The Join Rule

   Independently produced legs compose by each binding the same CAID.
   One prohibition comes before the mechanics: a leg MUST NOT ingest
   another leg's evidence into its own trust boundary, and composition
   MUST NOT be expressed by one artifact embedding another.  Each leg
   verifies under its own specification with its own tooling; the CAID
   is the only shared coordinate between legs.

3.1.  The Digest-Binding Record

   Each leg carries a digest-binding record: a statement, signed by
   the leg's own issuer, that the leg's native digest and the CAID
   name the same action.  The record is a JSON object:

   {
     "@type": "EP-CAID-BINDING-v1",
     "leg": "<leg type>",
     "leg_digest": "sha256:<hex of the leg's native digest>",
     "caid": "sha256:<hex of the CAID>",
     "issued_at": "<RFC 3339 instant>",
     "signature": "<base64url signature by the leg's own issuer>"
   }

   The signature is computed over the JCS canonical form of the record
   without its "signature" member, under the issuer key the relying
   party pins for that leg's role (Section 4.1).  A leg whose native
   digest is itself the JCS action digest carries the degenerate
   record in which "leg_digest" equals "caid".


Schrock                 Expires 14 January 2027                 [Page 5]

Internet-Draft        Canonical Action Identifiers             July 2026


3.2.  Verifying a Leg

   A leg verifies when both of the following hold:

   1.  The leg's native evidence verifies under the leg's own
       specification, with the leg's own tooling, against the key
       material the relying party has pinned for that leg's role.  For
       a cart mandate this includes that the mandate carries the
       digest of the cart actually presented; for a signed statement
       this includes that the statement's own signature verifies and
       that its subject agrees with the binding record's CAID.

   2.  The binding record's "@type" and "leg" members are the expected
       values, its "leg_digest" equals the native digest recomputed
       from the presented evidence, and its signature verifies under
       the issuer key pinned for that leg's role.

   A leg that verifies attests exactly one value to the composition:
   the CAID carried in its binding record.  Whether that CAID is the
   right one is not the leg's decision; Section 4 makes it the relying
   party's.

4.  Fail-Closed Composition

4.1.  Relying-Party Inputs

   Composition is evaluated against three inputs the relying party
   owns.  A presenter supplies legs; it supplies none of these.

   1.  One trust anchor per leg role.  The relying party pins the
       issuer key material it accepts for each leg type separately.
       There is no flat key bag: key material pinned for one role MUST
       NOT satisfy another role.

   2.  The requirement expression (Section 4.2).  An expression
       carried by a presenter is descriptive metadata only: a
       presenter MUST NOT choose its own sufficiency bar, and no ALLOW
       is reachable from a presenter-supplied expression.

   3.  The expected CAID, computed from the relying party's own
       independently constructed copy of the action object.  Internal
       agreement among legs is insufficient: a presenter can make
       every leg agree on the wrong action.







Schrock                 Expires 14 January 2027                 [Page 6]

Internet-Draft        Canonical Action Identifiers             July 2026


4.2.  The Requirement Expression

   The requirement expression is a boolean expression over leg-type
   identifiers, with the operators AND and OR and parenthesized
   grouping, evaluated over the set of leg types that satisfied both
   tests of Section 4.3.  Leg-type identifiers are restricted to
   letters, digits, and the characters "_", ".", ":", and "-".  The
   expression exercised by the reference implementation (Appendix A)
   is:

      ep-action AND ap2-cart-mandate AND scitt-statement

   An identifier evaluates true when a leg of that type verified and
   bound the expected CAID.  Display labels carried alongside legs
   never satisfy an identifier; only the typed verification result
   does.

4.3.  Verdict and Refusals

   Each presented leg is evaluated to two separate results: VERIFIED
   (both checks of Section 3.2 hold) and BOUND (the CAID the leg
   attests equals the relying party's expected CAID).  A leg enters
   the satisfied set only when both hold.  The composed verdict is
   ALLOW only when all of the following hold:

   *  the relying party supplied its own requirement expression;

   *  the relying party supplied its expected CAID;

   *  the expression is well formed within the verifier's parser
      limits; and

   *  the expression evaluates true over the satisfied set.

   Every other outcome is a refusal that states its reason.  Three
   refusal classes cover the attacks that matter.

   Splice: a leg verifies but binds a different CAID.  Every signature
   on the leg is genuine; the artifact was minted for a different
   action.  The leg is reported as binding a different action than the
   composition, it does not enter the satisfied set, and the refusal
   names the unsatisfied requirement together with the set of leg
   types that did satisfy it.

   Forgery: a leg's native evidence or binding record fails signature
   or digest verification.  The leg is reported as not verifying, with
   the same consequences.



Schrock                 Expires 14 January 2027                 [Page 7]

Internet-Draft        Canonical Action Identifiers             July 2026


   Absence: a required leg is not presented.  Its identifier is never
   satisfied, and the refusal names the unsatisfied requirement.

   Fail-closed means a refusal with a stated reason, never a crash: a
   malformed composition document, input exceeding the verifier's
   resource limits, and an exception thrown by a leg verifier each
   yield a refusal.

5.  Identity, Not Authority

   CAID equality proves exactly one thing: that the legs speak about
   the same action.  It proves nothing else.  A CAID does not
   authorize the action.  A CAID does not attest to any property of
   the action.  A CAID with no legs bound to it is only a name.  The
   strength of a composed verdict is bounded, leg by leg, by what each
   leg's own verification establishes under its own specification and
   by the relying party's acceptance of that leg's issuer; composition
   adds legs, it never strengthens any individual leg's claim.

6.  Relationship to Existing Evidence Ecosystems

   This document takes a composition-partner posture toward the
   ecosystems whose artifacts it joins.  Naming an ecosystem here
   records that its artifacts can join by CAID; it does not assert,
   and must not be read as, that ecosystem's endorsement of or
   participation in this document.

   Authorization receipts.  A receipt naming the human or quorum that
   authorized an action, for example
   [I-D.schrock-ep-authorization-receipts], is one leg class.  A
   receipt that already binds its action by the JCS action digest has
   the CAID as its native digest and carries the degenerate binding
   record.  This document does not profile receipt formats.

   Payment mandates.  A mandate in which a payer's agreement to a
   specific cart is signed over the payment ecosystem's own cart
   schema is one leg class; the reference implementation exercises an
   AP2-shaped cart mandate.  The mandate keeps digesting the purchase
   in its own cart form, so its checkout digest is a different digest
   of the same purchase, and the digest-binding record is precisely
   that crosswalk.  This document does not define, replace, or profile
   any payment-mandate format.

   Transparency-log statements.  A signed statement about the action,
   registrable with a transparency service in the sense of the SCITT
   architecture [RFC9943], is one leg class; the reference
   implementation exercises a SCITT-style statement shape.  The
   statement's subject can name the action digest, while the leg's


Schrock                 Expires 14 January 2027                 [Page 8]

Internet-Draft        Canonical Action Identifiers             July 2026


   native digest is the digest of the signed statement itself, the
   value a transparency service would register; the binding record
   joins the two.  This document does not define or profile
   transparency-log statement formats.

   Action and audit records.  A record of what an agent executed, or
   of what an audit trail observed, joins like any other leg whenever
   its format binds an action digest.

7.  Security Considerations

   The identifier is the join point, so the attacks are on the join.

   Splicing.  The strongest attack the join must survive is the one in
   which every signature is genuine: a leg minted for a different
   action, by its real issuer, presented under this action's
   composition.  No signature check catches it; only equality of the
   bound CAID with the relying party's expected CAID does.  This is
   why the expected CAID MUST come from the relying party's own
   construction of the action object (Section 4.1), and why a leg that
   verifies but binds a different CAID invalidates the composition
   rather than weakening it.

   Forged bindings.  The digest-binding record is signed by the leg's
   own issuer precisely so that no third party can mint bindings
   between digests it does not speak for.  A binding whose signature
   does not verify under the key pinned for that leg's role is a
   refusal.

   Absence.  The absence of a required leg is the absence of evidence,
   never a default.  A relying party whose requirement names a leg
   type fails closed until a leg of that type is presented and
   verifies.

   Identity is not truth.  CAID equality proves the legs speak about
   the same action, never that any leg's claim is true.  A composed
   ALLOW holds only under the relying party's stated requirement, and
   it inherits every limitation of each leg's own verification and
   acceptance rules, including the distinction between evidence that
   verified and an issuer the relying party accepts.

   Cross-role key confusion.  Trust anchors are pinned per leg role.
   A flat key set would let an issuer trusted for one role satisfy a
   requirement naming another; the composition MUST evaluate each leg
   only against the anchors pinned for its role.





Schrock                 Expires 14 January 2027                 [Page 9]

Internet-Draft        Canonical Action Identifiers             July 2026


   Presenter-chosen sufficiency.  A presenter that could supply the
   requirement expression would choose its own bar.  The expression a
   presenter carries is descriptive; only the relying party's own
   expression is evaluated toward ALLOW.

   Canonicalization and resources.  The identifier depends on
   canonical bytes being identical across implementations; the profile
   of Section 2.2 exists because non-integer JSON reals serialize
   differently across languages.  A verifier SHOULD bound the
   resources it spends on presented material; the reference verifier
   enforces limits on document depth, node count, and string bytes,
   and refuses rather than crashing on input outside them.

   Validity and replay.  The binding record joins digests; it does not
   extend any leg's validity.  Freshness, revocation, one-time use,
   and replay semantics belong to each leg's own specification and
   enforcement point, and carrying a leg in a composition MUST NOT
   extend them.
































Schrock                 Expires 14 January 2027                [Page 10]

Internet-Draft        Canonical Action Identifiers             July 2026


8.  IANA Considerations

   This document has no IANA actions.

9.  References

9.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC6234]  Eastlake 3rd, D. and T. Hansen, "US Secure Hash
              Algorithms (SHA and SHA-based HMAC and HKDF)", RFC 6234,
              DOI 10.17487/RFC6234, May 2011,
              <https://www.rfc-editor.org/info/rfc6234>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

9.2.  Informative References

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions", Work in Progress, Internet-Draft, draft-schrock-
              ep-authorization-receipts-05, July 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-
              authorization-receipts/>.

   [RFC7493]  Bray, T., Ed., "The I-JSON Message Format", RFC 7493,
              DOI 10.17487/RFC7493, March 2015,
              <https://www.rfc-editor.org/info/rfc7493>.

   [RFC7942]  Sheffer, Y. and A. Farrel, "Improving Awareness of
              Running Code: The Implementation Status Section", BCP
              205, RFC 7942, DOI 10.17487/RFC7942, July 2016,
              <https://www.rfc-editor.org/info/rfc7942>.





Schrock                 Expires 14 January 2027                [Page 11]

Internet-Draft        Canonical Action Identifiers             July 2026


   [RFC9943]  Birkholz, H., Delignat-Lavaud, A., Fournet, C., Deshpande,
              Y., and S. Lasker, "An Architecture for Trustworthy and
              Transparent Digital Supply Chains", RFC 9943,
              DOI 10.17487/RFC9943, June 2026,
              <https://www.rfc-editor.org/info/rfc9943>.

Appendix A.  Implementation Status

   This section records the existence of running code to assist
   review, in the spirit of [RFC7942]; it is to be removed before any
   publication as an RFC.

   The repository github.com/emiliaprotocol/emilia-protocol publishes
   a runnable demonstration of this document at
   examples/caid-crosswalk.mjs, under the Apache-2.0 license,
   executable offline with Node.js and no network access.  The file
   constructs one underlying commerce action and three heterogeneous
   legs:

   *  an EP canonical action digest leg (leg type "ep-action") whose
      native digest is the JCS action digest, carrying the degenerate
      binding record;

   *  an AP2-shaped cart mandate (leg type "ap2-cart-mandate"): a
      compact SD-JWT-style signed object over the mandate's own cart
      schema, carrying its own checkout digest; the file states that
      it illustrates the join and is not a conformant AP2
      implementation;

   *  a SCITT-style signed statement (leg type "scitt-statement"): an
      illustrative JSON statement shape with protected headers,
      payload, and signature, explicitly not COSE_Sign1, whose subject
      names the action digest and whose native digest is the digest of
      the signed statement.

   Each leg's issuer signs its own digest-binding record, and the
   composition is evaluated by the repository's evidence-chain
   verifier under the relying-party-pinned requirement expression
   "ep-action AND ap2-cart-mandate AND scitt-statement" and the
   relying party's expected CAID.  Run as a script, the file
   demonstrates exactly four scenarios and exits nonzero if any
   deviates from its expected verdict:

   1.  the exact composition: all three legs verify and bind the same
       CAID; the verdict is ALLOW;





Schrock                 Expires 14 January 2027                [Page 12]

Internet-Draft        Canonical Action Identifiers             July 2026


   2.  a cross-binding splice: a genuinely signed cart mandate minted
       for a different purchase is presented under this action's
       composition; every signature verifies; the leg is reported as
       binding a different action, and the verdict is a refusal naming
       the unsatisfied requirement;

   3.  a forged binding record: a statement leg whose binding
       signature does not verify; the leg is reported as not
       verifying, and the verdict is a refusal naming the unsatisfied
       requirement;

   4.  a missing leg: no statement leg is presented; the verdict is a
       refusal naming the unsatisfied requirement.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai
































Schrock                 Expires 14 January 2027                [Page 13]
```
