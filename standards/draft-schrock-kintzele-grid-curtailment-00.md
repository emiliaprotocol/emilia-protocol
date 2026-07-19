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
   4.  Telemetry Attestation and the Proof-of-Curtailment Bundle . .   4
   5.  Relationship to Other Work  . . . . . . . . . . . . . . . . .   4
   6.  Security Considerations . . . . . . . . . . . . . . . . . . .   5
   7.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   5
   8.  References  . . . . . . . . . . . . . . . . . . . . . . . . .   5
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
   a program period.  The envelope's bounds are dimensioned so no check
   ever compares mixed units: max_event_kw (a per-event instantaneous
   power cap), max_period_kwh (a cumulative energy budget for the
   period), max_events (an event-count budget), max_event_hours (a
   cumulative event-hours budget), a participation window, and a minimum
   notice.  The envelope is the human authorization; an individual order
   is a machine dispatch that must fit inside it.  This is what lets
   curtailment run at machine speed while a compromised or erroneous
   dispatcher key can never exceed what a human already authorized.

3.  Gate Predicates (Fail-Closed)

   A facility controller changes posture only if all hold: the order
   verifies (Ed25519 over RFC 8785 / JCS, [RFC8785]) against the
   _pinned_ authority key; action_type is "grid.curtailment"; the
   current time is within window; and the current time is before
   expires_at.  In addition, and load-bearing: the order MUST fit every
   envelope dimension in that dimension's own unit.  The order's
   target_delta_kw MUST NOT exceed max_event_kw (power against power);
   the event's projected energy (target_delta_kw times the window
   duration) MUST NOT exceed the envelope's remaining energy budget
   (max_period_kwh minus the energy already settled under it); and the
   event count and cumulative event-hours, counting this event, MUST fit
   their remaining budgets.  The order MUST also fit the envelope's
   window and notice bounds.  A bound or spent-accounting value that a
   check needs and that is missing or unparseable is itself a gate
   failure, never an unlimited default.  An order that exceeds any
   remaining budget is refused even under a validly signed authority key
   -- the envelope, not any single order, is the ceiling.

   A refused order is not silent.  On any gate-predicate failure or a
   protected-lane conflict, the controller MUST emit a signed REFUSAL
   receipt (an EP-RECEIPT-v1 over the refused order's digest, the
   failing predicate, and the time), so the dispatcher obtains
   verifiable evidence of "no, and here is why," not an absence.  A
   refusal is evidence in the same sense an authorization is, and is
   offline-verifiable by the same parties.










Schrock & Kintzele      Expires 30 December 2026                [Page 3]

Internet-Draft             EP Grid Curtailment                 June 2026


4.  Telemetry Attestation and the Proof-of-Curtailment Bundle

   Power telemetry is signed by an attested meter, and the meter signs
   ONLY physical measurement data: an EP-RECEIPT-v1 over {meter_id,
   unit, samples}, each sample carrying a timestamp, a quality flag, and
   a sequence number.  Any altered sample breaks verification.  The
   meter is a physical witness and MUST NOT carry market rules: a meter
   payload that includes baseline_method_hash MUST be refused.  Changing
   a program's baseline method never requires re-provisioning meters.
   The method binding lives one level up: the Proof-of-Curtailment
   Bundle composes the order, the facility acknowledgment, the attested
   telemetry, and the computed delivered kW*h, with the pinning keys,
   and itself binds order.baseline_method_hash together with the digest
   of the signed meter payload.  Verification (all MUST pass): the order
   verifies against the authority key; the acknowledgment against the
   facility key; the telemetry against the meter key; the meter payload
   carries no baseline_method_hash; bundle.baseline_method_hash equals
   order.baseline_method_hash; bundle.meter_payload_digest equals the
   digest of the signed meter payload; and recomputing delivered kW*h
   from the signed samples equals the claimed value.  Anyone can run
   this offline, with no account.

   Settlement is single-use by consumption, not by convention.  A
   settlement consumes a one-time entitlement keyed by {entitlement_id
   (the envelope being drawn against), event_id (from the order),
   meter_window_digest (the digest of the signed meter payload for the
   settled window)}. A second settlement presenting the same key tuple
   MUST be refused with a typed reason -- the same curtailment event
   cannot be sold twice.  The key is the nonce for EP's one-time
   consumption discipline (the sparse-Merkle consumption profile), so a
   settlement authority operating a witnessed consumption log makes
   double settlement offline-detectable by third parties, the same way
   receipt-nonce double-spend is.  Scope: the consumption check runs
   against the settling authority's own log; reuse of the same metered
   window across programs or authorities is detected by comparing
   meter_window_digest values across logs -- an audit function, not a
   property any single log provides.

5.  Relationship to Other Work

   This is a profile of [I-D.schrock-ep-authorization-receipts]; human
   oversight rides the EP human-oversight profile; long-term
   preservation rides EP Evidence-Record renewal ([RFC4998]-style);
   optional transparency anchoring composes with SCITT/COSE.  It
   composes with -- does not replace -- energy-market dispatch protocols
   (for example OpenADR, IEEE 2030.5), which carry the dispatch while EP
   carries the authorization and the proof.




Schrock & Kintzele      Expires 30 December 2026                [Page 4]

Internet-Draft             EP Grid Curtailment                 June 2026


6.  Security Considerations

   Over-trust is the dominant risk: a valid bundle proves authorization
   and telemetry integrity against a pinned method, not that the
   baseline is physically correct (baseline estimation belongs to the
   program).  Spoofed, stale, and replayed orders are refused fail-
   closed, as are orders exceeding any human-authorized envelope budget
   (per-event power, period energy, event count, event-hours) -- a
   compromised dispatcher key spends only what the envelope already
   authorized, never more.  Double settlement of the same event is
   refused by one-time entitlement consumption keyed by {entitlement_id,
   event_id, meter_window_digest}; reuse of the same metered window
   across programs is auditable by comparing meter window digests across
   consumption logs.  EP is a necessary, not sufficient, condition for
   trustworthy demand response.

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

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

Authors' Addresses

   Iman Schrock
   EMILIA Protocol, Inc.
   United States of America
   Email: team@emiliaprotocol.ai






Schrock & Kintzele      Expires 30 December 2026                [Page 5]

Internet-Draft             EP Grid Curtailment                 June 2026


   Justin Kintzele
   COSA
   United States of America
   Email: jkintzele@jdieselny.com















































Schrock & Kintzele      Expires 30 December 2026                [Page 6]

```
