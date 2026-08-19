# Crossing-record profile: frozen design decisions

Status: frozen 2026-08-18 after adversarial review. Any implementation or
draft that contradicts a decision below is wrong until this file is amended;
amend this file first, with the reason, before shipping the contradiction.
Scope: the versioned AEB crossing-record profile and the Action Evidence
Dossier rendering. Technical invariants only.

## Carrier and provenance

1. (Amended 2026-08-19; original read "the carrier is the Agent
   Accountability Composition." Reason: the record must remain useful
   whichever composition or authorization ecosystem a deployment lives in.)
   The crossing record has NO mandatory carrier. It is a standalone,
   versioned, signed record. The Agent Accountability Composition, the
   Agent Action Capsule, SCITT-registered evidence profiles (including
   Permit/Closure-style records that reference it), and customer-owned
   dossier renderings are OPTIONAL composition and presentation profiles.
   No new generic dossier envelope, stamp format, or lifecycle umbrella
   document is introduced; the dossier is a presentation layer over
   records that verify individually.
2. The record is a PROMOTION of AEB-04 Section 5.6 (the SHOULD-emit signed
   evaluation record) to a MUST with a versioned schema. It is not a new
   authorization theory. AEB remains the state machine.

## Verdicts and state

3. The profile defines NO verdict vocabulary. It references the existing
   multi-axis referee result contract
   (conformance/referee/schemas/runner-result.schema.json): eleven axes with
   bounded reason codes. Any single flattened outcome enum is a regression.
4. The consumption record contains NO outcome. Consumption precedes dispatch.
   Evaluation/admission, the atomic consumption transition, provider entry,
   provider commitment, effect observation, and reconciliation are SEPARATE
   records joined by CAID and operation identifier, never one mutable
   super-receipt.

## Keys and replay

5. Two keys, never one. The lifecycle join is the contract digest (domain-
   separated canonical encoding over the exact action, authorization
   instance, requirement profile, audience, executor, state domain, and
   validity). The fence key is the replay unit. The operation identifier is
   an opaque correlator with no security meaning.
6. Replay prevention is the atomic uniqueness/consumption transition in the
   owning durable state domain (AEB-04 Section 5.8: key never from a
   presenter-selected decoy; unavailable, non-atomic, or ambiguous store =
   refuse). Inclusion proofs and Merkle/SMT constructions make state
   independently checkable; they are never the replay defense.
7. Replay-unit identity is a property of the MAPPING PROFILE, not of an
   implementation. Conformance requires: same native authority under
   different wrappers yields the same replay unit; distinct authorities
   yield distinct units; any two conformant implementations yield
   byte-identical units for the same authority (cross-implementation parity
   vectors, same discipline as cross-language refusal-string parity).
   Different native authority systems emit records conforming to the same
   canonical crossing-record contract and verifier semantics; their complete
   records are not expected to be byte-identical because native provenance,
   authority-instance, evidence, mapping-profile, constraint, and replay-unit
   fields legitimately differ.

## Release and reconciliation

8. Unresolved authority is fenced immediately. Release requires
   authoritative serialized non-entry after a precommitted deadline, under
   the owning store's transaction time, with write-ahead entry markers and
   late-entry refusal (inherited from BCR; not restated). A late entry
   marker after release must be impossible, and there is a vector for it.
9. Reconciliation may report or prove what happened. It may never mint,
   renew, or widen authority.

## Completeness and review

10. The only claimable completeness is boundary-attested completeness
    relative to a pinned requirement profile: the record commits to the
    complete requirement/configuration digests AND the evidence actually
    evaluated, and the atomic transition occurred. Enumeration alone proves
    what the issuer says it examined. Manifest integrity is not
    completeness. Global completeness is not claimable.
11. Post-crossing stamps rely on source heads: append-only source,
    inclusion proof, consistency or monotonic progression, independent or
    freshness-bounded head. The freshness window is a relying-party policy
    knob. Outside it, the source-status axis is STALE, a new crossing is not
    admitted, and any higher-level review or completeness conclusion that
    depends on current source state is INDETERMINATE. These values remain
    separate; staleness is never flattened into one whole-record verdict.
12. Admission requirements and later review requirements are separate
    digests. A review verdict never rewrites an admission verdict and is
    never emitted alone where an admission verdict exists. Every record
    carries an explicit admission-reference state: PRESENT, MISSING,
    NOT_APPLICABLE, or INDETERMINATE. An admitted crossing requires PRESENT
    plus the admission-record digest; MISSING and INDETERMINATE are
    non-authorizing and cannot support a claim that admission occurred. Review
    must distinguish never-present, withheld, and plaintext-deleted-with-
    digest-retained evidence. Redacted entries remain committed leaves
    (DISCLOSED / COMMITTED_UNDISCLOSED); redaction never vanishes.

## Presentation

13. The dossier can be presented and verified offline. It cannot authorize
    a new crossing: a new consequential crossing requires the authoritative
    state domain to agree at that moment.
14. Code and conformance-corpus digests are operator declarations of
    provenance and tested agreement. They do not establish that a deployed
    binary equals the source, and no runtime-attestation requirement is
    introduced.

15. Cross-protocol conformance means one canonical record contract, one
    portable verifier, and the same bounded reason semantics. It does not
    mean that two different authority systems produce the same record bytes
    or that their native grants are semantically equivalent.

## Language

16. Native authority systems are an OPEN SET behind one bounded adapter
    interface (native profile and issuer, verified authority-instance
    digest, exact-action projection, replay-unit derivation, status
    result, constraints and validity, evidence and mapping-profile
    digests). Authorization-server-issued grants (OAuth, WIMSE workload
    and transaction tokens, CIBA-obtained user authorization) and
    non-authorization-server authority (human and quorum receipts,
    bounded-capability receipts, FIDO ceremonies, payment mandates,
    offline mandates, local policy) are treated through the same
    interface. The record preserves native provenance and never claims
    different authority kinds are equivalent; the relying party decides
    which combinations satisfy its requirement.

17. The boundary may NARROW or REFUSE native authority. It may never
    broaden it. The native issuer's decision remains authoritative for
    what it granted (this is AEB-04 Section 5.7's separate local
    authorization decision: SATISFIED alone never triggers execution,
    and local policy adds constraints, never removes them). A crossing
    record is evidence that an exact action crossed once under native
    authority; it is never itself a grant, and presenting one confers no
    authority.

18. The record is born signature-agile: its signature field is the
    EP-SIG-AGILITY-v1 set shape with the required algorithm set committed
    inside the signed bytes, so the profile never needs a classical-only
    to hybrid migration.

19. The following are not claimable about this system in any document:
    non-repudiable, forgery is impossible, proves compliance, and
    unverifiable market or actuarial superlatives. The honest forms are:
    signed and attributable under pinned keys; a signature that does not
    verify under the pinned key is refused; evidence that supports
    compliance assessment. scripts/check-language-governance.ts enforces
    this mechanically.
