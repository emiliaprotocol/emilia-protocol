# Authority Documents and Graded Introduction: Trust Establishment for Agent-Action Evidence Without Prior Federation
## draft-schrock-ep-authority-introduction-00

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               3 July 2026
Expires: 4 January 2027


  Authority Documents and Graded Introduction: Trust Establishment for
             Agent-Action Evidence Without Prior Federation
               draft-schrock-ep-authority-introduction-00

Abstract

   Every signed-evidence format in the agent-action space specifies
   verification and defers acceptance to "a pinned issuer key,
   distributed out of band."  The result is that two organizations with
   no prior relationship cannot begin relying on each other's evidence
   without a human key ceremony.  This document fills the acceptance
   half.  It defines the Authority Document: a signed, hash-chained,
   sequence-numbered declaration of an organization's evidence-issuing
   keys, with per-key validity windows, custody classes, and revocation;
   rotations carry a continuity signature by a key from the previous
   document, so first contact is the only leap of faith and everything
   after is mechanical.  Verification of an artifact resolves the key
   that was valid AT ISSUANCE, so rotation never breaks old evidence and
   compromise never retroactively voids honest history.  Acceptance
   itself becomes a graded, replayable verdict: introduction evidence
   (chain consistency, domain binding, transparency-log inclusion and
   age, endorsements by the relying party's pinned anchors) is evaluated
   under a relying-party policy per action class, so a young, unendorsed
   issuer can be acceptable for low-value actions while insufficient for
   money movement, and its acceptance widens mechanically as its
   verifiable history accrues.  Nothing in this document creates trust
   from nothing; it makes the bootstrap checkable and the residual risk
   priced by the relying party's own policy.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.







Schrock                  Expires 4 January 2027                 [Page 1]

Internet-Draft           Authority Introduction                July 2026


   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time.  It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as "work in progress."

   This Internet-Draft will expire on 4 January 2027.

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
   2.  The Authority Document (EP-AUTHORITY-DOC-v1)  . . . . . . . .   3
   3.  Rotation, Continuity, and Time-of-Issuance  . . . . . . . . .   4
   4.  Anti-Equivocation . . . . . . . . . . . . . . . . . . . . . .   5
   5.  Introduction as Evidence: Graded, Replayable Acceptance . . .   5
   6.  Compromise Recovery . . . . . . . . . . . . . . . . . . . . .   6
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .   6
   8.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   6
   9.  References  . . . . . . . . . . . . . . . . . . . . . . . . .   6
     9.1.  Normative References  . . . . . . . . . . . . . . . . . .   6
     9.2.  Informative References  . . . . . . . . . . . . . . . . .   7
   Appendix A.  Implementation Status  . . . . . . . . . . . . . . .   7
   Author's Address  . . . . . . . . . . . . . . . . . . . . . . . .   7

1.  Introduction

   The agent-action evidence stack has converged on a discipline this
   document's siblings state as "verified versus accepted": verifying an
   artifact (its signatures and bindings hold, given a public key) is
   distinct from accepting it (the relying party trusts the issuer, via
   out-of-band pinned key material).  The discipline is correct, and it
   has an unspecified half.  How the relying party comes to pin that key
   — how two strangers are INTRODUCED — appears in no specification: one
   working group explicitly forbids dynamic trust-anchor lookup, another



Schrock                  Expires 4 January 2027                 [Page 2]

Internet-Draft           Authority Introduction                July 2026


   flags the absence of a well-known discovery path as unresolved, and
   every receipt format, including this document's own family, writes
   "pinned out of band" and moves on.  Web transport had the same
   problem and got a public-key infrastructure; agent evidence has
   nothing.

   The design here rejects two familiar shapes.  It is not a
   certificate-authority hierarchy: there is no root everyone must
   trust, because the parties who rely on agent-action evidence (banks,
   insurers, auditors, counterparties) do not share one sovereign.  And
   it is not trust-on-first-use alone, because TOFU without history,
   consistency, or endorsement gives a relying party nothing to grade.
   Instead: make the issuer's key history a verifiable, append-only
   structure; harvest the trust roots that already exist (domain
   control, transparency logs, peer endorsement) as EVIDENCE rather than
   authority; and make acceptance a policy verdict over that evidence,
   per action class, replayable by any third party.

1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

2.  The Authority Document (EP-AUTHORITY-DOC-v1)

   An authority document is a JSON object, served from the
   organization's own origin (RECOMMENDED: /.well-known/ep-
   authority.json) and registrable to a transparency service:




















Schrock                  Expires 4 January 2027                 [Page 3]

Internet-Draft           Authority Introduction                July 2026


   {
     "@version": "EP-AUTHORITY-DOC-v1",
     "org": { "name": "...", "domain": "acme.example" },
     "seq": 3,
     "prev_doc_digest": "sha256:<core digest of doc seq 2>",
     "root_key": "<b64url SPKI>",
     "issuer_keys": [
       { "kid": "<hex>", "key": "<b64url SPKI>",
         "custody_class": "A",
         "valid_from": "...", "valid_to": "...",
         "revoked_at": "<OPTIONAL>" }
     ],
     "issued_at": "...",
     "sig": "<root_key over the canonical core>",
     "continuity_sig": "<by a key from the PREVIOUS doc>",
     "endorsements": [ { "by_org": "...", "by_key": "...",
                         "doc_digest": "...", "sig": "..." } ]
   }

   The signed core is the document without sig, continuity_sig, and
   endorsements; its canonical digest is the document's identity.
   Endorsements are countersignatures over that digest by OTHER
   authorities — third-party attestations that ride with the document
   without being part of it.

3.  Rotation, Continuity, and Time-of-Issuance

   Documents chain: seq increments by one, prev_doc_digest names the
   previous core digest, and each rotation MUST carry a continuity
   signature by the previous document's root key or one of its non-
   revoked issuer keys.  A verifier walking the chain therefore needs
   exactly one leap — the first document it ever saw — and every
   subsequent rotation is mechanically checkable.  A rotation without
   valid continuity MUST be flagged, never silently accepted; whether
   endorsements can substitute for continuity is the relying party's
   policy (Section 6), not a default.

   Two invariants govern key resolution, and implementations that miss
   either will hurt someone:

   1.  Time of issuance.  An artifact verifies against the key that was
       valid WHEN THE ARTIFACT WAS ISSUED.  Rotation never invalidates
       previously issued evidence, and a revocation voids a key only for
       signatures claimed at or after revoked_at — honest history
       survives compromise.






Schrock                  Expires 4 January 2027                 [Page 4]

Internet-Draft           Authority Introduction                July 2026


   2.  Newest document authoritative.  The newest document that mentions
       a key identifier is authoritative for it.  A revocation recorded
       in document N MUST NOT be undone by resolving the same key
       identifier against the pre-revocation entry in document N-1.

4.  Anti-Equivocation

   A malicious authority might show different documents to different
   relying parties.  Two defenses compose: the hash chain makes any fork
   of history unpresentable to a party that holds the other branch
   (prev-digest mismatch is a hard failure), and registration of each
   document revision to a transparency service [RFC9943] makes the
   document history globally consistent — every relying party that
   checks inclusion is checking the SAME history, which upgrades trust-
   on-first-use to trust-on-first-use-with-global-consistency.  Log
   registration is an introduction-evidence input, not a prerequisite:
   its absence is graded by policy, not hard-failed.

5.  Introduction as Evidence: Graded, Replayable Acceptance

   Acceptance is not a boolean in a config file; it is a verdict over
   introduction evidence, evaluated under a RELYING-PARTY policy, using
   the same closed five-verdict classification and replay-digest
   discipline as the evidence-sufficiency layer this family defines for
   actions ([I-D.schrock-ep-action-evidence-graph]).  The evidence
   facts: the authority chain itself (consistent, signed, no unexplained
   continuity breaks); domain binding (the relying party's own attested
   observation that it fetched this document digest from the
   organization's origin); transparency-log inclusion and FIRST-LOGGED
   AGE (history is load-bearing: an issuer whose documents have been
   logged, unforked, for a year is a different risk than one logged
   yesterday); and endorsements, graded by whether the endorser is among
   the relying party's own pinned anchors.

   Policies are per action class.  A young, unendorsed issuer can be
   admissible for low-value actions while missing_evidence for money
   movement; when its logged history lengthens or a pinned anchor
   endorses it, its acceptance widens with NO reconfiguration on the
   relying party's side — the same policy now evaluates to a wider
   verdict.  Trust accrues in a public, portable, verifiable form, and
   every relying party benefits from the history every other interaction
   created.  That property, not any single mechanism in this document,
   is the point.








Schrock                  Expires 4 January 2027                 [Page 5]

Internet-Draft           Authority Introduction                July 2026


6.  Compromise Recovery

   If an authority loses its keys entirely, continuity breaks by
   construction.  The recovery path is explicit rather than exceptional:
   the successor document is published with no (or invalid) continuity
   signature, the break is flagged by every verifier, and the relying
   party's policy decides what substitutes — typically an endorsement
   threshold (a quorum of the relying party's pinned anchors
   countersigning the successor document) plus a revocation statement
   over the compromised keys.  A relying party with no such policy
   simply continues to refuse: fail closed is the default, recovery is
   opt-in.

7.  Security Considerations

   Nothing creates trust from nothing, and this document does not claim
   to.  What it removes is the UNCHECKABILITY of the bootstrap: first
   contact is one observation among several gradable facts rather than a
   silent leap, and everything after first contact is mechanical.  The
   residual assumptions are named: domain binding inherits the Web PKI
   and is worth exactly that; log-backed consistency is as strong as the
   log's operator or the cross-log witnessing above it; endorsements are
   as strong as the endorser and mean nothing until a relying party pins
   one.  Key-resurrection (resolving a revoked key through an older
   document) is defeated by the newest-document-authoritative rule;
   fork-equivocation by the hash chain plus log consistency; rotation-
   based history rewriting by time-of-issuance resolution.  The
   acceptance verdict inherits the fail-closed precedence of the
   classification it reuses: no combination of missing observations ever
   grades toward acceptance.

8.  IANA Considerations

   This document has no IANA actions.  A well-known URI registration
   (ep-authority.json) is anticipated for a future revision.

9.  References

9.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.



Schrock                  Expires 4 January 2027                 [Page 6]

Internet-Draft           Authority Introduction                July 2026


   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

9.2.  Informative References

   [I-D.schrock-ep-action-evidence-graph]
              Schrock, I., "Action Evidence Graphs and Evidence Policy
              Replay for High-Risk Agent Actions (EP-AEG)", Work in
              Progress, Internet-Draft, draft-schrock-ep-action-
              evidence-graph-00, July 2026,
              <https://datatracker.ietf.org/doc/draft-schrock-ep-action-
              evidence-graph/>.

   [RFC9943]  Birkholz, H., Delignat-Lavaud, A., Fournet, C., Deshpande,
              Y., and S. Lasker, "An Architecture for Trustworthy and
              Transparent Digital Supply Chains", RFC 9943,
              DOI 10.17487/RFC9943, June 2026,
              <https://www.rfc-editor.org/info/rfc9943>.

   [SPIFFE-FED]
              SPIFFE Project, "SPIFFE Federation: trust bundle
              endpoints", 2024,
              <https://spiffe.io/docs/latest/architecture/federation/>.

   [TUF]      TUF Project, "The Update Framework: root key rotation and
              continuity", 2024, <https://theupdateframework.io/>.

Appendix A.  Implementation Status

   A reference implementation (document creation and rotation, chain
   verification with continuity and fork detection, time-of-issuance key
   resolution with the newest-document-authoritative rule, endorsements,
   and graded introduction verdicts with replay digests) is published
   Apache-2.0 in the EMILIA Protocol repository (lib/authority/
   authority-doc.js), with a test suite covering the invariants in this
   document: rotation without continuity is flagged; fork-equivocation
   is a hard failure; revocation voids the future but not honest
   history; an unpinned endorsement never satisfies a pinned-endorsement
   requirement; and the same chain, observations, and policy replay to
   the same verdict and digest.

Author's Address

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America



Schrock                  Expires 4 January 2027                 [Page 7]

Internet-Draft           Authority Introduction                July 2026


   Email: team@emiliaprotocol.ai


















































Schrock                  Expires 4 January 2027                 [Page 8]

```
