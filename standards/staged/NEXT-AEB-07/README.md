# Action Evidence Boundary -07 review candidate

This packet is a staged review candidate for
`draft-schrock-action-evidence-boundary-07`. It has not been submitted,
published, adopted by a working group, or reviewed by the referenced protocol
owners. Filing requires an explicit decision by the author; nothing in this
packet is a filing.

## Base

The candidate is built from the posted -06 source,
`standards/staged/NEXT-AEB-06/UPLOAD-THIS/draft-schrock-action-evidence-boundary-06.xml`
at commit `69cc928eeb3b39cb8878c9af328da8c3599e86a6` (SHA-256
`82eaf5eea816c037cb8dcb4608c8735a96f09850aad0a6df5bac021964bf17c5`). That file
is byte-identical to the IETF archive copy of -06. Datatracker lists -06 as the
latest revision (posted 2026-09-25T02:15:03Z), and no -07 exists in the
archive, so -07 is the next revision number. See `VALIDATION.md`.

## Substantive changes from -06

Each item below adds or changes a normative requirement. None of them is a
wording-only edit.

1. Same-action in-flight fence (new Section 5.10). The action key is
   (relying party, effecting target identity, action digest). For native
   authorization paths, including handoffs, a new attempt whose action key is
   held by a CONSUMED, RESERVED, DISPATCH_PENDING, INVOKED, or INDETERMINATE
   attempt, or closed by an EXECUTED one, MUST be refused before provider
   entry with the reason `native_action_in_flight` (a key closed by EXECUTED
   MAY instead be reported as `native_action_already_executed`), and the
   refused attempt MUST NOT consume its native authority. This holds even when
   the new attempt carries a fresh native permit, a new native authorization
   identifier, a new handoff, or a new operation identifier. The fence is
   durable, shared across boundary instances, and occupied by an atomic write
   that detects conflicts. Section 5.11 lets the fence and the authority
   reservation be one atomic step or several atomic writes, provided provider
   entry waits for all of them and a refused attempt releases what it wrote
   only after an authenticated durable read. It releases only on
   authenticated FAILED, a durable record proving the attempt was closed
   before provider entry, or authenticated reconciliation to FAILED. EXECUTED keeps it closed. A profile MAY declare an instance field,
   which is material and therefore part of the action digest, to admit
   intentionally repeated actions. Security Considerations cover fresh
   authority for an uncertain action, instance-field misuse, and action-digest
   scope.
2. One native replay identity (Sections 5.9 and 8.5). The -06 "stable replay
   identity" and "native replay unit" are now one value. Its inputs are exactly
   the relying-party-pinned authority namespace, the issuer, and the native
   authorization identifier. The operation identifier, provider idempotency
   key, wire labels such as the native system and profile, wrapper and handoff
   digests, and retry, session, trace, and challenge identifiers are excluded.
   Pins that accept one issuer under several labels share one namespace unless
   each declares its own. Provider idempotency keys derive from the native
   replay identity. The adapter probe now includes a relabelled-grant probe.
3. AuthZEN and COAZ (Sections 5.3 and 7.2). A permit covers only the inputs
   that the pinned mapping projects. AUTHORIZED for the full executor action
   requires every material field to be projected and operation-bound, or
   enforced by a separate pinned check; otherwise correspondence is
   INDETERMINATE and the boundary refuses. When the boundary is not the PEP,
   exact-action binding comes from the handoff over the full action digest,
   not from the permit alone. The semantic-loss report now covers native
   projections.
4. Material field without CAID (Section 2). Materiality is defined through the
   material-field inventory of the pinned native operation profile, with the
   CAID action-type definition added when a cross-format join is selected.
   Operation, idempotency, wrapper, session, trace, challenge, and retry
   identifiers are not material. New terms: PEP, PDP, effect-owning PEP,
   native operation profile, native authorization handoff, action digest,
   action instance, instance field, effecting target identity, authority
   namespace, native replay identity, and action key.
5. Native authorization handoff (new Section 5.8). The draft now specifies what
   a gateway attests and what the boundary verifies, in which order, and under
   which pins. The gateway attests the permit, native source, full action
   digest, relying party, audience, executor, effecting target, validity, and
   revocation identifier. The boundary checks these before any status lookup
   or state write, derives the replay identity itself, and repeats the time
   and status checks before provider entry. The section also states that the
   trust basis moves to the gateway. The encoding stays deployment-pinned;
   the reference encoding is cited informatively. Implementation Status
   describes the direct path as same-team reference code at a pinned commit
   and states the two requirements that code predates.
6. Consistency and references. Reconciliation is now bound to the attempt it
   resolves. The SCITT Permit text in Section 7.3 no longer requires CAID
   unconditionally. The `all_of` and `any_of` members of EP-AEB-REQUIREMENT-v1
   are defined again, and the `evidence-binding` term accepted by the
   reference verifier is defined. References are updated to AEC -06,
   Authorization Receipts -13, and WIMSE HTTP Signatures -07. COAZ and
   COAZ-MCP are pinned to openid/authzen commit
   `78a5165a0048895a345e4ac5b0f2b9c7904bb110`. The stray KLRC mention is
   removed, AIMS is cited as `draft-ietf-wimse-aims-00`, the CAID-02 date is
   corrected to 6 August 2026, and acronyms are expanded on first use.
7. Normative references. Only BCP 14 (RFC 2119, RFC 8174), CAID, and AEC are
   normative. CAID and AEC stay normative because the conditional
   cross-format and multi-leg stages cannot be implemented without them. The
   new fence, replay-identity, and handoff requirements add no normative
   dependency, and every other individual draft and non-IETF specification is
   informative. The document is Informational, so downward-reference rules do
   not apply. RFC publication would still wait on CAID and AEC.

AEB still defines no receipt, token, handoff encoding, policy language, PDP,
or registry.

## Before any filing

- Refresh the date and re-run the checks in `VALIDATION.md`, including the
  Datatracker revision check and the reference-currency check.
- Update Section 15 (Implementation Status) once the reference fix for the
  Section 5.9 replay derivation and the Section 5.10 fence is merged. The
  current text describes commit `69cc928eeb3b39cb8878c9af328da8c3599e86a6`,
  where both are absent. The follow-up branch `fix/pr788-followups`
  implements both: Gate reserves the operation with the native replay key,
  then occupies the action fence in a second atomic reservation, which the
  revised Section 5.11 permits. The PostgreSQL store there also exposes
  `state()`. Re-pin `EP-NATIVE-HANDOFF` and `EP-LIFECYCLE-CORPUS` to the
  merged commit; the corpus there has 26 cases, including fresh authority
  during INDETERMINATE and after EXECUTED, and a relabelled grant. Then
  re-render, regenerate `SHA256SUMS.txt`, and re-run idnits.

## Layout

`UPLOAD-THIS/` contains the candidate XML source. `RENDERS/` contains the text
and HTML produced from that source by xml2rfc. `SHA256SUMS.txt` covers all
three files.

## Claim boundary

References to AuthZEN, COAZ, AP2, OAuth, and WIMSE describe composition with
their native artifacts and do not claim conformance or interoperability with
those specifications. The reference implementation and the synthetic lifecycle
corpus are same-team artifacts, not independent implementations.
