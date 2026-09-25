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
   (relying party, effecting target identity, action digest). For every
   attempt, whatever evidence path admits it (native result, handoff, CAID
   join, or AEC composition), a new attempt whose action key is held by a
   CONSUMED, RESERVED, DISPATCH_PENDING, INVOKED, or INDETERMINATE attempt, or
   closed by an EXECUTED one, MUST be refused before provider entry, and the
   refused attempt MUST NOT consume its authority. Native authorization paths
   report `native_action_in_flight` (a key closed by EXECUTED MAY instead be
   reported as `native_action_already_executed`); other paths report a reason
   that identifies the occupied or closed key. This holds even when the new
   attempt carries a fresh native permit, a new native authorization
   identifier, a new handoff, new evidence, or a new operation identifier. The
   fence is durable, shared across boundary instances, and occupied by an
   atomic write that detects conflicts. Section 5.11 lets the fence and the
   authority reservation be one atomic step or several atomic writes, provided
   provider entry waits for all of them and a refused attempt releases what it
   wrote only after an authenticated durable read. The fence releases only on
   authenticated FAILED, authenticated reconciliation to FAILED, a pre-entry
   stop by the boundary itself whose release it confirmed through an
   authenticated durable read, or authorized pre-entry recovery. EXECUTED keeps
   it closed. A profile MAY declare an instance field, which is material and
   therefore part of the action digest, to admit intentionally repeated
   actions. Security Considerations cover fresh authority for an uncertain
   action, instance-field misuse, and action-digest scope.
2. Pre-entry recovery (Section 5.10). An attempt that stopped before provider
   entry (a crash while CONSUMED or RESERVED, a lost acknowledgement of the
   write that enters DISPATCH_PENDING, an unconfirmed release after a
   pre-entry refusal, or a crash after the action key was occupied but before
   the attempt was recorded) MUST have a recovery operation. It requires
   relying-party recovery authorization bound to that exact attempt and
   releases the action key and the attempt's reservations only when an
   authenticated durable read shows that the attempt never reached
   DISPATCH_PENDING, that the boundary closed it as not entered through an
   atomic transition that no dispatch can follow, or that no attempt record
   exists, and, where the effecting system offers an authenticated lookup,
   that lookup reports that the operation was not received. A record from
   which the original attempt could still dispatch is first closed that way.
   Without that proof the attempt is treated as INDETERMINATE. A pre-entry
   stop is never reconciled to EXECUTED or FAILED.
3. Record ownership and recovery credentials (Sections 5.11 and 5.14). A
   boundary MUST release or close only records whose ownership for the current
   attempt it can prove; an operation-identifier match alone does not prove
   ownership, because operation identifiers can be caller input. One recovery
   authorization bound to an attempt MUST suffice to close every record the
   attempt holds, including its occupation of the action key.
4. Canonical action identity (Section 5.10). Action digests and effecting
   target identities are compared exactly. The native operation profile MUST
   define canonical forms for material fields (amount and currency formats,
   case, white space, Unicode normalization), the party that constructs the
   action MUST apply them, and every boundary instance that can reach one
   effecting target MUST be configured with the same effecting target
   identity. AEB does not claim that a boundary recognizes equivalent
   spellings.
5. One native replay identity (Sections 4, 5.9, and 8.5). The -06 "stable
   replay identity" and "native replay unit" are now one value. Its inputs are
   exactly the relying-party-pinned authority namespace, which defaults to the
   verified issuer value, and the native authorization identifier; when a pin
   declares a namespace, the issuer value is not an input. The operation
   identifier, provider idempotency key, wire labels such as the native system
   and profile, wrapper and handoff digests, and retry, session, trace, and
   challenge identifiers are excluded. Pins for one issuer value share one
   namespace unless every such pin declares its own, and pins whose issuer
   values differ but are equal after normalization (for URLs: scheme and host
   case, default port, trailing slashes) MUST all declare the same namespace,
   or the pin set is refused. Changing a namespace rotates every replay identity under it, so
   in-flight attempts MUST be resolved and consumed grants made unpresentable
   first. Provider idempotency keys derive from the native replay identity.
   The adapter probe now includes a relabelled-grant probe and a probe under a
   second issuer spelling.
6. AuthZEN and COAZ (Sections 5.3 and 7.2). A permit covers only the inputs
   that the pinned mapping projects. AUTHORIZED for the full executor action
   requires every material field to be projected and operation-bound, or
   enforced by a separate pinned check; otherwise correspondence is
   INDETERMINATE and the boundary refuses. When the boundary is not the PEP,
   exact-action binding comes from the handoff over the full action digest,
   not from the permit alone. The semantic-loss report now covers native
   projections.
7. Material field without CAID (Section 2). Materiality is defined through the
   material-field inventory of the pinned native operation profile, with the
   CAID action-type definition added when a cross-format join is selected.
   Operation, idempotency, wrapper, session, trace, challenge, and retry
   identifiers are not material. New terms: PEP, PDP, effect-owning PEP,
   native operation profile, native authorization handoff, action digest,
   action instance, instance field, effecting target identity, authority
   namespace, native replay identity, and action key.
8. Native authorization handoff (new Section 5.8). The draft now specifies what
   a gateway attests and what the boundary verifies, in which order, and under
   which pins. The gateway attests the permit, native source, full action
   digest, relying party, audience, executor, effecting target, validity, and
   revocation identifier. The boundary checks these before any status lookup
   or state write, derives the replay identity itself, and repeats the time
   and status checks before provider entry. The section also states that the
   trust basis moves to the gateway. The encoding stays deployment-pinned;
   the reference encoding is cited informatively. Implementation Status
   describes the verifier and both Gate boundaries as same-team reference
   code at a pinned commit and states what that code does not implement.
9. Consistency and references. Reconciliation is now bound to the attempt it
   resolves. The SCITT Permit text in Section 7.3 no longer requires CAID
   unconditionally. The `all_of` and `any_of` members of EP-AEB-REQUIREMENT-v1
   are defined again, and the `evidence-binding` term accepted by the
   reference verifier is defined. References are updated to AEC -06,
   Authorization Receipts -13, and WIMSE HTTP Signatures -07. COAZ and
   COAZ-MCP are pinned to openid/authzen commit
   `78a5165a0048895a345e4ac5b0f2b9c7904bb110`. The stray KLRC mention is
   removed, AIMS is cited as `draft-ietf-wimse-aims-00`, the CAID-02 date is
   corrected to 6 August 2026, and acronyms are expanded on first use.
10. Normative references. Only BCP 14 (RFC 2119, RFC 8174), CAID, and AEC are
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
- Section 15 (Implementation Status) and the `EP-NATIVE-HANDOFF` and
  `EP-LIFECYCLE-CORPUS` references describe the reference code at commit
  `46b5ec92745d50ea7163301b1141eedd2091fc6e` on branch
  `fix/pr788-followups` (PR #790), which was not merged when this candidate
  was prepared. At that commit both Gate boundaries implement the Section
  5.10 fence and its pre-entry recovery, the verifier derives the label-free
  replay identity and refuses aliased issuer pins without one shared
  namespace, and the handoff keeps its 4.1.0 wire `replay_unit`, which still
  covers the labels. Section 15 also states that the reference Gate has no
  material-field inventory or canonical-form equivalence. Once the branch is
  merged, re-pin both references to the merge commit on `main`, re-render,
  regenerate `SHA256SUMS.txt`, and re-run idnits.

## Layout

`UPLOAD-THIS/` contains the candidate XML source. `RENDERS/` contains the text
and HTML produced from that source by xml2rfc. `SHA256SUMS.txt` covers all
three files.

## Claim boundary

References to AuthZEN, COAZ, AP2, OAuth, and WIMSE describe composition with
their native artifacts and do not claim conformance or interoperability with
those specifications. The reference implementation and the synthetic lifecycle
corpus are same-team artifacts, not independent implementations.
