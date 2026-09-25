# Open coauthor inputs

The candidate applies the architecture agreed in the shared thread and
transcribes Blake Morrison's marked-up Sections 7 through 10 and Drew Dylan's
Section 11. Their supplied author blocks are in the RFCXML. Blake's final five
corrections and Justin Kintzele's frozen RDU101 facts and dispositions are now
incorporated. The exact updated candidate still requires final coauthor review
before it becomes an upload candidate.

## Blake

- Confirmed the RFCXML accurately transcribed the supplied total field
  classification, conduit-context, atomic-record, ownership-fence,
  correlation-field, no-response, and safety requirements.
- Requested and supplied the final Modbus 0x06/0x10, DNP3 qualifier,
  insufficient-authority, control-room label, and citation corrections now in
  this candidate.
- Directed the candidate to keep the public
  `draft-morrison-ot-command-authority-02` reference until `-03` is posted.

## Drew

- Confirm that the RFCXML accurately transcribes the supplied five-state
  matrix, evidence-channel separation, admissibility rule, retry default,
  restart/handoff behavior, aggregation rule, and minimum control-room view.
- Confirm that `effect_observed` is the right disposition for an admissible
  observation showing a missed curtailment, leaving `effect_confirmed` only for
  the in-bounds case.

## Justin

- Froze the target device, RDU101 firmware, SNMPv3 AuthPriv parameters, point
  4365 OID, group 2, four characterized rows, and separate Modbus-meter
  readback facts used in the example.
- Froze the nominal, degraded-communications, missed-bound, conflicting-
  telemetry, unresolved-readback, and independent-interlock dispositions.
- Confirmed TEST-01 was read-only, TEST-02 remains strictly on hold, and no
  energized actuation is claimed.

## All four

- Review and freeze the native deployment-profile fields before executable
  conformance fixtures are added; the candidate states the thirteen required
  cases but deliberately does not invent their fixture values.
- Decide whether the optional pre-dispatch transparency/SCITT text belongs in
  this revision.
- Approve the exact RFCXML and rendered text before any IETF submission. This
  staged packet grants no submission or email authority.
