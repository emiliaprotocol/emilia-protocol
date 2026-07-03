# Proof-of-Curtailment: the grid.curtailment Action Profile
## draft-schrock-kintzele-grid-curtailment-00

```




Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               J. Kintzele
Expires: 30 December 2026                                           COSA
                                                            28 June 2026


   EMILIA Protocol: Grid Curtailment Authorization Profile (Proof-of-
                              Curtailment)
               draft-schrock-kintzele-grid-curtailment-00

Abstract

   This document defines grid.curtailment, an EMILIA Protocol (EP)
   action-type profile for authorizing and proving bounded, reversible
   curtailment of electrical load by autonomous or agentic systems --
   the "Proof-of-Curtailment" used by the GRACE (Grid-Responsive
   Authorized Compute Events) vertical.  It rides the EP authorization
   receipt ([I-D.schrock-ep-authorization-receipts]) and the human-
   oversight profile, and introduces no new cryptography.  A market-
   authorized party issues a bounded curtailment order that a facility
   verifies offline and fail-closed; the event emits a settlement-grade,
   offline-verifiable bundle proving who authorized it, what was
   allowed, whether the facility complied, and what should be paid.  EP
   proves authorization and evidence integrity -- a necessary, not
   sufficient, condition; it does not invent the demand-response
   baseline.

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

   This Internet-Draft will expire on 30 December 2026.







Schrock & Kintzele      Expires 30 December 2026                [Page 1]

Internet-Draft             EP Grid Curtailment                 June 2026


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
   2.  The Curtailment Order . . . . . . . . . . . . . . . . . . . .   2
   3.  Gate Predicates (Fail-Closed) . . . . . . . . . . . . . . . .   3
   4.  Telemetry Attestation and the Proof-of-Curtailment Bundle . .   3
   5.  Relationship to Other Work  . . . . . . . . . . . . . . . . .   4
   6.  Security Considerations . . . . . . . . . . . . . . . . . . .   4
   7.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   4
   8.  References  . . . . . . . . . . . . . . . . . . . . . . . . .   4
   Authors' Addresses  . . . . . . . . . . . . . . . . . . . . . . .   5

1.  Introduction

   Demand-response markets pay large flexible loads (notably AI
   datacenters) to curtail, but the record that a load actually
   curtailed when paid is self-reported and trust-based.  This profile
   supplies a portable, tamper-evident, offline-verifiable artifact for
   that record.  It does not move power (a scheduler does) and does not
   define the baseline methodology (the program/ISO does); it binds the
   authorizing party to the exact, bounded, reversible event and makes
   the application of the program's prescribed baseline method un-
   fudgeable.

2.  The Curtailment Order

   An EP-RECEIPT-v1 whose action object carries: action_type =
   "grid.curtailment"; effect_class = "power_reduction"; facility;
   target_delta_kw; window {not_before, not_after}; expires_at (SHOULD
   equal window.not_after); baseline_method_hash (a sha256 commitment to
   the program's prescribed baseline method identifier -- it pins, it
   does not define); control_mode (human-oversight profile, typically
   "on_the_loop"); and OPTIONAL protected_lanes, telemetry_sources,
   approver, max_duration.  Hard cuts (large target_delta_kw or full-



Schrock & Kintzele      Expires 30 December 2026                [Page 2]

Internet-Draft             EP Grid Curtailment                 June 2026


   site) MUST use EP-QUORUM (m-of-n distinct signers).

   An order draws against a SEASONAL ENVELOPE: a prior EP-RECEIPT-v1 in
   which a named human (or quorum) authorizes bounded participation for
   a program period -- a maximum aggregate target_delta_kw, a
   participation window, a per-event max_duration, and a minimum notice.
   The envelope is the human authorization; an individual order is a
   machine dispatch that must fit inside it.  This is what lets
   curtailment run at machine speed while a compromised or erroneous
   dispatcher key can never exceed what a human already authorized.

3.  Gate Predicates (Fail-Closed)

   A facility controller changes posture only if all hold: the order
   verifies (Ed25519 over RFC 8785 / JCS, [RFC8785]) against the
   _pinned_ authority key; action_type is "grid.curtailment"; the
   current time is within window; and the current time is before
   expires_at.  In addition, and load-bearing: the order's
   target_delta_kw MUST NOT exceed the seasonal envelope's UNSPENT
   balance (the envelope's authorized aggregate minus the sum of
   already-settled events under it), and the order MUST fit the
   envelope's window, per-event duration, and notice bounds.  An order
   that exceeds the remaining balance is refused even under a validly
   signed authority key -- the envelope, not any single order, is the
   ceiling.

   A refused order is not silent.  On any gate-predicate failure or a
   protected-lane conflict, the controller MUST emit a signed REFUSAL
   receipt (an EP-RECEIPT-v1 over the refused order's digest, the
   failing predicate, and the time), so the dispatcher obtains
   verifiable evidence of "no, and here is why," not an absence.  A
   refusal is evidence in the same sense an authorization is, and is
   offline-verifiable by the same parties.

4.  Telemetry Attestation and the Proof-of-Curtailment Bundle

   Power telemetry is signed by an attested meter (an EP-RECEIPT-v1 over
   {meter_id, unit, baseline_method_hash, samples}), so any altered
   sample breaks verification.  The Proof-of-Curtailment Bundle composes
   the order, the facility acknowledgment, the attested telemetry, and
   the computed delivered kW*h, with the pinning keys.  Verification
   (all MUST pass): the order verifies against the authority key; the
   acknowledgment against the facility key; the telemetry against the
   meter key; telemetry.baseline_method_hash equals
   order.baseline_method_hash; and recomputing delivered kW*h from the
   signed samples equals the claimed value.  Anyone can run this
   offline, with no account.




Schrock & Kintzele      Expires 30 December 2026                [Page 3]

Internet-Draft             EP Grid Curtailment                 June 2026


   The meter's signature over baseline_method_hash binds the settlement
   bundle to a single event under a single program method, so the same
   physical power reduction cannot be sold into two programs: a second
   bundle claiming the same meter samples under a different method hash
   fails the equality check, and a second claim under the same method
   resolves to the same event digest.  Settlement is single-use per
   event by construction, the demand-response analogue of one-time
   receipt consumption.

5.  Relationship to Other Work

   This is a profile of [I-D.schrock-ep-authorization-receipts]; human
   oversight rides the EP human-oversight profile; long-term
   preservation rides EP Evidence-Record renewal ([RFC4998]-style);
   optional transparency anchoring composes with SCITT/COSE.  It
   composes with -- does not replace -- energy-market dispatch protocols
   (for example OpenADR, IEEE 2030.5), which carry the dispatch while EP
   carries the authorization and the proof.

6.  Security Considerations

   Over-trust is the dominant risk: a valid bundle proves authorization
   and telemetry integrity against a pinned method, not that the
   baseline is physically correct (baseline estimation belongs to the
   program).  Spoofed, stale, and replayed orders are refused fail-
   closed, as are orders exceeding the human-authorized envelope balance
   -- a compromised dispatcher key spends only what the envelope already
   authorized, never more.  Double-counting the same reduction across
   programs is defeated by the meter-signed method binding.  EP is a
   necessary, not sufficient, condition for trustworthy demand response.

7.  IANA Considerations

   This document registers the "grid.curtailment" action-type in the EP
   action-type profile registry.  It has no other IANA actions.

8.  References

   [I-D.schrock-ep-authorization-receipts]
              Schrock, I., "Authorization Receipts for High-Risk Agent
              Actions", Work in Progress, Internet-Draft, draft-schrock-
              ep-authorization-receipts-04, 30 June 2026,
              <https://datatracker.ietf.org/doc/html/draft-schrock-ep-
              authorization-receipts-04>.

   [RFC4998]  Gondrom, T., Brandner, R., and U. Pordesch, "Evidence
              Record Syntax (ERS)", RFC 4998, DOI 10.17487/RFC4998,
              August 2007, <https://www.rfc-editor.org/info/rfc4998>.



Schrock & Kintzele      Expires 30 December 2026                [Page 4]

Internet-Draft             EP Grid Curtailment                 June 2026


   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

Authors' Addresses

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai


   Justin Kintzele
   COSA
   United States of America
   Email: jkintzele@jdieselny.com


































Schrock & Kintzele      Expires 30 December 2026                [Page 5]

```
