# Open coauthor inputs

The candidate applies the architecture agreed in the shared thread and
transcribes Blake Morrison's marked-up Sections 7 through 10 and Drew Dylan's
Section 11. Their supplied author blocks are now in the RFCXML. These are the
remaining reviews before the four coauthors can freeze an upload candidate.

## Blake

- Confirm that the RFCXML accurately transcribes the supplied total field
  classification, conduit-context, atomic-record, ownership-fence,
  correlation-field, no-response, and safety requirements.
- Confirm that the four generic Modbus/DNP3 results are sufficiently precise
  while the per-protocol tables remain in the separate transport-binding work.
- Confirm whether the -01 reference should remain on the public
  `draft-morrison-ot-command-authority-02` until `-03` is publicly posted.

## Drew

- Confirm that the RFCXML accurately transcribes the supplied five-state
  matrix, evidence-channel separation, admissibility rule, retry default,
  restart/handoff behavior, aggregation rule, and minimum control-room view.
- Confirm that `effect_observed` is the right disposition for an admissible
  observation showing a missed curtailment, leaving `effect_confirmed` only for
  the in-bounds case.

## Justin

- Check the adapted RDU101 facts, including device model, firmware, object 4365,
  group 2, four control rows, SNMPv3 AuthPriv, and the distinction between an
  RDU101 SetResponse and independent Modbus readback.
- Confirm the nominal, timeout, disagreement, missing-readback, and interlock
  outcomes reflect the supplied example.
- Confirm the no-energized-test wording remains exact enough for public review.

## All four

- Review and freeze the native deployment-profile fields before executable
  conformance fixtures are added; the candidate states the thirteen required
  cases but deliberately does not invent their fixture values.
- Decide whether the optional pre-dispatch transparency/SCITT text belongs in
  this revision.
- Approve the exact RFCXML and rendered text before any IETF submission. This
  staged packet grants no submission or email authority.
