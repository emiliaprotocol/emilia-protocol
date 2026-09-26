# AEB-07 publication provenance packet

Status: posted on 2026-09-25 as
`draft-schrock-action-evidence-boundary-07` through Datatracker submission
169495 (Datatracker time 2026-09-26T00:11:40Z). It is an active individual
Internet-Draft. It is not a working-group item, an RFC, or IETF endorsement,
and posting is not review by the referenced protocol owners.

The XML under `UPLOAD-THIS/` is the exact submitted -07 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot is
[`../../posted/draft-schrock-action-evidence-boundary-07.xml`](../../posted/draft-schrock-action-evidence-boundary-07.xml);
AEB-06 is retained in `../../archive/`. The publication check is recorded at
the end of `VALIDATION.md`.

## Base

The revision was built from the posted -06 source,
`standards/staged/NEXT-AEB-06/UPLOAD-THIS/draft-schrock-action-evidence-boundary-06.xml`
at commit `69cc928eeb3b39cb8878c9af328da8c3599e86a6` (SHA-256
`82eaf5eea816c037cb8dcb4608c8735a96f09850aad0a6df5bac021964bf17c5`). That file
is byte-identical to the IETF archive copy of -06. When the packet was
prepared, Datatracker listed -06 as the latest revision (posted
2026-09-25T02:15:03Z) and no -07 existed in the archive. See `VALIDATION.md`.

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
   write that enters DISPATCH_PENDING, or an unconfirmed release after a
   pre-entry refusal) MUST have a recovery operation. Records left by a
   crash after the action key was occupied but before the attempt was
   recorded cannot be shown not entered, so they stay held; a boundary
   SHOULD record the attempt before it occupies the action key, so that
   this case cannot arise. Recovery requires relying-party recovery
   authorization bound to that exact attempt and releases the action key
   and the attempt's reservations only when an authenticated durable read
   shows that the attempt never reached DISPATCH_PENDING, or that the
   boundary closed it as not entered through an atomic transition that no
   dispatch can follow and that recorded an explicit not-entered marker,
   and, where the effecting system offers an authenticated lookup, that
   lookup reports that the operation was not received. The absence of an
   attempt record is not proof of non-entry, because a live attempt may not
   yet have written it. A record from which the original
   attempt could still dispatch is first closed that way. Every not-entered
   transition, the boundary's own pre-entry stop and recovery's, records
   that marker in the same atomic write, and the absence of evidence is
   never proof of non-entry: a closed record that carries neither the marker
   nor terminal provider evidence is INDETERMINATE and releases nothing.
   Without that proof the attempt is treated as INDETERMINATE. A pre-entry
   stop is never reconciled to EXECUTED or FAILED. Pre-entry recovery is a
   separate operation that never continues into reconciliation. Its own
   atomic not-entered transition is the linearization point: once it
   succeeds, the original attempt cannot enter DISPATCH_PENDING or dispatch.
   A recovery that loses the transition to the original attempt releases
   nothing, treats the attempt as INDETERMINATE, and never uses its lookup
   result as evidence of the outcome, because that lookup describes a moment
   before dispatch. A boundary that has sent a write that could record an
   attempt as not entered, including one whose result it did not receive,
   MUST NOT dispatch that attempt afterwards, whatever a later read shows
   (Section 5.12). An attempt left in DISPATCH_PENDING without a dispatch
   is INDETERMINATE and is closed only by reconciliation with terminal
   evidence that forecloses any execution, now or later, under its provider
   idempotency key; a point-in-time absence of the operation, even when
   authenticated, does not qualify while a dispatcher may still be live.
   Otherwise it stays held.
3. Record ownership, release ordering, and recovery credentials (Sections
   5.11, 5.12, and 5.14). A boundary MUST release or close only records whose
   ownership for the current attempt it can prove; an operation-identifier
   match alone does not prove ownership, because operation identifiers can be
   caller input. A record that successive attempts can hold, such as a
   reservation keyed by an evaluation, is released, closed, or committed only
   for an attempt proven to be its current owner, for example through a
   durable record keyed by the attempt that marks it as the owner, or
   because the attempt itself created the record and has not handed it back.
   When an attempt record exists, the attempt's records are released, closed, or
   committed only after its terminal or not-entered transition has succeeded
   and been confirmed. Only the store's affirmative result counts as success;
   any other answer is resolved through a durable read, and a lost
   acknowledgement of the write that enters DISPATCH_PENDING never releases
   anything on its own, and a refusal whose writes are not all confirmed
   released is reported as INDETERMINATE, not as a final refusal. Recovery
   authorization MUST be bound to exactly one attempt, never only to an
   operation identifier or another shared value, and every record claimed
   under it must be derived from that attempt. A claim that names no attempt
   is refused before its authorization is evaluated. The attempt identity
   is scoped to the boundary: it includes an identifier of the boundary
   (the same for every instance of one boundary) and, where boundaries of
   different kinds share one store, a component that distinguishes them,
   both in the derivation of every record keyed by the attempt and in the
   scope the authorization is checked against, so two boundaries of the
   same kind that assign the same attempt identifier cannot name each
   other's records. The boundary identifier is never part of the action
   key. One such
   authorization MUST suffice to close every record the attempt holds,
   including its occupation of the action key.
4. Verified terminal evidence (Sections 5.13 and 5.14). A terminal outcome
   that commits or releases the records of an attempt that reached
   DISPATCH_PENDING, from the dispatch or from reconciliation, is accepted
   only after a relying-party-configured verifier authenticates the provider
   evidence and binds it to that attempt, including its provider
   idempotency key. The boundary tells the verifier the purpose of each
   check, a terminal outcome or a pre-entry lookup, and counts only a result
   that affirms that purpose for that attempt. A "not received" lookup is
   evidence only for pre-entry recovery and is never accepted as FAILED for
   an attempt that reached DISPATCH_PENDING, because a dispatch in flight
   can still arrive after it. A boundary without such a verifier keeps a
   dispatched attempt INDETERMINATE. This applies on every boundary and
   evidence path, including the result that the dispatch itself returns: an
   adapter's report of FAILED is not verification. Presented evidence
   carries its kind (terminal outcome or pre-entry lookup) in the
   boundary's own input, and reconciliation and pre-entry recovery each
   refuse the other kind before the verifier runs. The boundary cannot
   detect a verifier that affirms a purpose it did not evaluate or a
   presenter that labels a lookup as a terminal outcome; Section 5.13 puts
   those obligations on the verifier and the presenter, and the Security
   Considerations say that the residual rests with them.
5. Canonical action identity (Section 5.10). Action digests and effecting
   target identities are compared exactly. The native operation profile MUST
   define canonical forms for material fields (amount and currency formats,
   case, white space, Unicode normalization), the party that constructs the
   action MUST apply them, and every boundary instance that can reach one
   effecting target MUST be configured with the same effecting target
   identity. AEB does not claim that a boundary recognizes equivalent
   spellings.
6. One native replay identity (Sections 4, 5.9, and 8.5). The -06 "stable
   replay identity" and "native replay unit" are now one value. Its inputs are
   exactly the relying-party-pinned authority namespace, which defaults to the
   verified issuer value, and the native authorization identifier; when a pin
   declares a namespace, the issuer value is not an input. The operation
   identifier, provider idempotency key, wire labels such as the native system
   and profile, wrapper and handoff digests, and retry, session, trace, and
   challenge identifiers are excluded. One issuer MUST have exactly one
   namespace in a pin set: pins whose issuer values are identical or equal
   after normalization either all omit a declaration with one identical
   issuer value or all declare the same namespace, or the pin set is
   refused.
   Section 4 sets the minimum normalization: URI scheme case, and
   for URLs also host case, a trailing dot on the host, a default port,
   trailing slashes, and a missing "//" after http or https. The reference
   verifier normalizes those and also resolves dot segments in the path
   (and accepts a missing "//" and drops a default port for every special
   URL scheme: http, https, ws, wss, and ftp), and, because it parses those
   schemes as WHATWG URLs, also canonicalizes IPv4 host spellings (for
   example 127.1 and 0x7f.0.0.1) and drops an empty port, compares a URN namespace
   identifier and a DID method name case-insensitively, compares a
   `did:web` host case-insensitively without trailing dots, and compares a
   `spiffe://` trust domain case-insensitively without trailing dots and
   drops trailing slashes from a SPIFFE path. Normalization cannot detect
   every alias. Two different declared namespaces for one issuer value are
   refused. Changing a namespace rotates every replay identity under it, so
   in-flight attempts MUST be resolved and consumed grants made unpresentable
   first. Provider idempotency keys derive from the native replay identity.
   The adapter probe now includes a relabelled-grant probe and a probe under a
   second issuer spelling.
7. AuthZEN and COAZ (Sections 5.3 and 7.2). A permit covers only the inputs
   that the pinned mapping projects. AUTHORIZED for the full executor action
   requires every material field to be projected and operation-bound, or
   enforced by a separate pinned check; otherwise correspondence is
   INDETERMINATE and the boundary refuses. When the boundary is not the PEP,
   exact-action binding comes from the handoff over the full action digest,
   not from the permit alone. The semantic-loss report now covers native
   projections.
8. Material field without CAID (Section 2). Materiality is defined through the
   material-field inventory of the pinned native operation profile, with the
   CAID action-type definition added when a cross-format join is selected.
   Operation, idempotency, wrapper, session, trace, challenge, and retry
   identifiers are not material. New terms: PEP, PDP, effect-owning PEP,
   native operation profile, native authorization handoff, action digest,
   action instance, instance field, effecting target identity, authority
   namespace, native replay identity, and action key.
9. Native authorization handoff (new Section 5.8). The draft now specifies what
   a gateway attests and what the boundary verifies, in which order, and under
   which pins. The gateway attests the permit, native source, full action
   digest, relying party, audience, executor, effecting target, validity, and
   revocation identifier. The boundary checks these before any status lookup
   or state write, derives the replay identity itself, and repeats the time
   and status checks before provider entry. The section also states that the
   trust basis moves to the gateway. The encoding stays deployment-pinned;
   the reference encoding is cited informatively. Implementation Status
   describes the verifier and both Gate boundaries as same-team reference
   code at a pinned commit and states what that code does not implement. It
   says what each boundary keys by attempt: the native boundary keys all
   three of its reservations by attempt, while the composed boundary keys
   only its occupation of the action key by attempt and keys its evaluation
   reservation by evaluation. It also says that both boundaries require an
   operator-configured verifier that is told the purpose of each check and
   verify every terminal provider outcome through it, including the
   dispatch's own result, that presented evidence carries its kind, that
   the reference code cannot tell whether a verifier evaluated the evidence
   or whether evidence was labelled correctly, and that the reference Gate
   fences the replay key of an earlier release for every pinned source
   label.
10. Consistency and references. Reconciliation is now bound to the attempt it
   resolves. The SCITT Permit text in Section 7.3 no longer requires CAID
   unconditionally. The `all_of` and `any_of` members of EP-AEB-REQUIREMENT-v1
   are defined again, and the `evidence-binding` term accepted by the
   reference verifier is defined. References are updated to AEC -06,
   Authorization Receipts -13, and WIMSE HTTP Signatures -07. COAZ and
   COAZ-MCP are pinned to openid/authzen commit
   `78a5165a0048895a345e4ac5b0f2b9c7904bb110`. The stray KLRC mention is
   removed, AIMS is cited as `draft-ietf-wimse-aims-00`, the CAID-02 date is
   corrected to 6 August 2026, and acronyms are expanded on first use.
11. Normative references. Only BCP 14 (RFC 2119, RFC 8174), CAID, and AEC are
   normative. CAID and AEC stay normative because the conditional
   cross-format and multi-leg stages cannot be implemented without them. The
   new fence, replay-identity, and handoff requirements add no normative
   dependency, and every other individual draft and non-IETF specification is
   informative. The document is Informational, so downward-reference rules do
   not apply. RFC publication would still wait on CAID and AEC.

AEB still defines no receipt, token, handoff encoding, policy language, PDP,
or registry.

## Reference pins in the posted text

The `EP-NATIVE-HANDOFF` and `EP-LIFECYCLE-CORPUS` references pin commit
`b1b268e7d0538a9e22e379ddb06f55149d352c3b`, the merge of PR #790 on `main`.
Section 15 describes the reference code at that commit and what it does not
do: for wire compatibility with earlier releases the signed handoff still
carries a `replay_unit` computed over the source labels, which the verifier
checks but never uses as the replay identity, and the reference Gate
implements no material-field inventory and no canonical-form equivalence. It
is same-team reference code, not an independent implementation, and it is
cited informatively.

## Layout

`UPLOAD-THIS/` contains the exact submitted XML source. `RENDERS/` contains the
text and HTML produced from that source by xml2rfc 3.34.0. `SHA256SUMS.txt`
covers all three files.

## Claim boundary

References to AuthZEN, COAZ, AP2, OAuth, and WIMSE describe composition with
their native artifacts and do not claim conformance or interoperability with
those specifications. The reference implementation and the synthetic lifecycle
corpus are same-team artifacts, not independent implementations.
