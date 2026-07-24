--------------------- MODULE ep_revocation_witness ---------------------
\* Bounded adversarial model for two related fail-closed boundaries:
\*
\*   1. Terminal revocation is accepted only when a pinned, authenticated,
\*      well-formed statement exactly binds the target and is effective at the
\*      trusted evaluation time.  Once accepted, it is permanent.  A fresh
\*      authenticated "not revoked" status is a separate, expiring input and
\*      can never override a terminal revocation.
\*
\*   2. A network-witness stream is the exact
\*         (tenant, gate, witness, capture point)
\*      tuple pinned by the relying party.  Authenticated fresh statements may
\*      advance its sequence monotonically.  Two different authenticated
\*      statement digests at the same accepted sequence poison only that exact
\*      stream.  Poisoning and the accepted head are then permanent, and every
\*      later statement for the stream is refused.
\*
\* Cryptographic verification, canonicalization, clock synchronization,
\* publication availability, and database linearizability are assumptions at
\* this state-machine boundary.  The finite instance contains explicit
\* unpinned, forged, malformed, wrong-target, future, stale, replay, rollback,
\* same-sequence-conflict, and post-poison presentations.  Refusals are real
\* state transitions so TLC action coverage demonstrates non-vacuity.

EXTENDS Naturals, FiniteSets

CONSTANTS
    TargetA, TargetB,
    RevGoodA, RevFutureA, RevUnpinnedA, RevForgedA, RevMalformedA, RevGoodB,
    StatusFreshA, StatusShortA, StatusFutureA, StatusUnpinnedA,
    StatusForgedA, StatusFreshB,
    TenantA, TenantB, GateA, GateB, WitnessA, WitnessB, CaptureA, CaptureB,
    WitnessASeq1, WitnessASeq2, WitnessASeq2Replay,
    WitnessASeq2Conflict, WitnessASeq3,
    WitnessTenantBSeq1, WitnessGateBSeq1, WitnessBSeq1, WitnessCaptureBSeq1,
    WitnessASeq3Unpinned, WitnessASeq3Forged,
    WitnessASeq3Future, WitnessASeq3Stale,
    DigestA1, DigestA2, DigestA2Conflict, DigestA3,
    DigestTenantB1, DigestGateB1, DigestB1, DigestCaptureB1,
    MaxTime, MaxWitnessAge, MaxSequence, MaxSteps

Targets == {TargetA, TargetB}
Times == 0..MaxTime

Revocations == {
    RevGoodA,
    RevFutureA,
    RevUnpinnedA,
    RevForgedA,
    RevMalformedA,
    RevGoodB
}

Statuses == {
    StatusFreshA,
    StatusShortA,
    StatusFutureA,
    StatusUnpinnedA,
    StatusForgedA,
    StatusFreshB
}

StreamA == [
    tenant |-> TenantA,
    gate |-> GateA,
    witness |-> WitnessA,
    capture |-> CaptureA
]

StreamTenantB == [
    tenant |-> TenantB,
    gate |-> GateA,
    witness |-> WitnessA,
    capture |-> CaptureA
]

StreamGateB == [
    tenant |-> TenantA,
    gate |-> GateB,
    witness |-> WitnessA,
    capture |-> CaptureA
]

StreamWitnessB == [
    tenant |-> TenantA,
    gate |-> GateA,
    witness |-> WitnessB,
    capture |-> CaptureA
]

StreamCaptureB == [
    tenant |-> TenantA,
    gate |-> GateA,
    witness |-> WitnessA,
    capture |-> CaptureB
]

Streams == {
    StreamA,
    StreamTenantB,
    StreamGateB,
    StreamWitnessB,
    StreamCaptureB
}

WitnessStatements == {
    WitnessASeq1,
    WitnessASeq2,
    WitnessASeq2Replay,
    WitnessASeq2Conflict,
    WitnessASeq3,
    WitnessTenantBSeq1,
    WitnessGateBSeq1,
    WitnessBSeq1,
    WitnessCaptureBSeq1,
    WitnessASeq3Unpinned,
    WitnessASeq3Forged,
    WitnessASeq3Future,
    WitnessASeq3Stale
}

WitnessDigests == {
    DigestA1,
    DigestA2,
    DigestA2Conflict,
    DigestA3,
    DigestTenantB1,
    DigestGateB1,
    DigestB1,
    DigestCaptureB1
}

NoRevocation == "NO_REVOCATION"
NoStatus == "NO_STATUS"
NoWitnessStatement == "NO_WITNESS_STATEMENT"
NoDigest == "NO_DIGEST"
\* Numeric sentinel keeps TLC's bounded integer interval homogeneous.
NoTime == MaxTime + 1

Verdicts == {"none", "accepted", "refused"}

RevocationRefusalKinds == {
    "malformed_target",
    "target_mismatch",
    "revoker_key_unpinned",
    "bad_signature",
    "not_yet_effective"
}

StatusRefusalKinds == {
    "terminal_revocation",
    "malformed_status",
    "target_mismatch",
    "status_key_unpinned",
    "bad_signature",
    "status_from_future",
    "status_stale"
}

WitnessRefusalKinds == {
    "witness_key_unpinned",
    "bad_signature",
    "observation_from_future",
    "observation_stale",
    "statement_replay",
    "sequence_rollback",
    "sequence_equivocation"
}

\* ---------------------------------------------------------------------
\* Fixed adversarial revocation and status artifacts.
\* ---------------------------------------------------------------------
RevocationTarget(r) ==
    CASE r \in {
             RevGoodA,
             RevFutureA,
             RevUnpinnedA,
             RevForgedA,
             RevMalformedA
         } -> TargetA
      [] r = RevGoodB -> TargetB
      [] OTHER -> TargetA

RevocationEffectiveAt(r) ==
    CASE r = RevFutureA -> 3
      [] OTHER -> 1

RevocationPinned(r) == r # RevUnpinnedA
RevocationSignatureValid(r) == r # RevForgedA
RevocationWellFormed(r) == r # RevMalformedA

RevocationVerifiedAt(r, expectedTarget, evaluationTime) ==
    /\ r \in Revocations
    /\ expectedTarget \in Targets
    /\ RevocationWellFormed(r)
    /\ RevocationTarget(r) = expectedTarget
    /\ RevocationPinned(r)
    /\ RevocationSignatureValid(r)
    /\ RevocationEffectiveAt(r) <= evaluationTime

RevocationRefusalKindAt(r, expectedTarget, evaluationTime) ==
    CASE ~RevocationWellFormed(r) ->
             "malformed_target"
      [] RevocationTarget(r) # expectedTarget ->
             "target_mismatch"
      [] ~RevocationPinned(r) ->
             "revoker_key_unpinned"
      [] ~RevocationSignatureValid(r) ->
             "bad_signature"
      [] RevocationEffectiveAt(r) > evaluationTime ->
             "not_yet_effective"
      [] OTHER -> "not_yet_effective"

StatusTarget(s) ==
    CASE s = StatusFreshB -> TargetB
      [] OTHER -> TargetA

StatusThisUpdate(s) ==
    CASE s = StatusFutureA -> 3
      [] OTHER -> 0

StatusNextUpdate(s) ==
    CASE s = StatusShortA -> 1
      [] s = StatusFutureA -> 5
      [] OTHER -> 2

StatusPinned(s) == s # StatusUnpinnedA
StatusSignatureValid(s) == s # StatusForgedA
StatusWellFormed(s) == s \in Statuses

StatusAuthenticatedFor(s, expectedTarget) ==
    /\ s \in Statuses
    /\ expectedTarget \in Targets
    /\ StatusWellFormed(s)
    /\ StatusTarget(s) = expectedTarget
    /\ StatusPinned(s)
    /\ StatusSignatureValid(s)

StatusFreshAt(s, evaluationTime) ==
    /\ StatusThisUpdate(s) <= evaluationTime
    /\ evaluationTime < StatusNextUpdate(s)

StatusVerifiedFreshAt(s, expectedTarget, evaluationTime) ==
    /\ StatusAuthenticatedFor(s, expectedTarget)
    /\ StatusFreshAt(s, evaluationTime)

\* ---------------------------------------------------------------------
\* Fixed network-witness artifacts.  The conflicting A/2 statement is fully
\* pinned, signed, and fresh: poison cannot be blamed on an auth failure.
\* ---------------------------------------------------------------------
WitnessStream(w) ==
    CASE w = WitnessTenantBSeq1 -> StreamTenantB
      [] w = WitnessGateBSeq1 -> StreamGateB
      [] w = WitnessBSeq1 -> StreamWitnessB
      [] w = WitnessCaptureBSeq1 -> StreamCaptureB
      [] OTHER -> StreamA

WitnessSequence(w) ==
    CASE w \in {
             WitnessASeq1,
             WitnessTenantBSeq1,
             WitnessGateBSeq1,
             WitnessBSeq1,
             WitnessCaptureBSeq1
         } -> 1
      [] w \in {
             WitnessASeq2,
             WitnessASeq2Replay,
             WitnessASeq2Conflict
         } -> 2
      [] OTHER -> 3

WitnessDigest(w) ==
    CASE w = WitnessASeq1 -> DigestA1
      [] w \in {WitnessASeq2, WitnessASeq2Replay} -> DigestA2
      [] w = WitnessASeq2Conflict -> DigestA2Conflict
      [] w = WitnessTenantBSeq1 -> DigestTenantB1
      [] w = WitnessGateBSeq1 -> DigestGateB1
      [] w = WitnessBSeq1 -> DigestB1
      [] w = WitnessCaptureBSeq1 -> DigestCaptureB1
      [] OTHER -> DigestA3

WitnessObservedAt(w) ==
    CASE w \in {
             WitnessASeq1,
             WitnessTenantBSeq1,
             WitnessGateBSeq1,
             WitnessBSeq1,
             WitnessCaptureBSeq1,
             WitnessASeq3Stale
         } -> 0
      [] w \in {
             WitnessASeq2,
             WitnessASeq2Replay,
             WitnessASeq2Conflict
         } -> 1
      [] w = WitnessASeq3Future -> 4
      [] OTHER -> 2

WitnessPinValid(w) == w # WitnessASeq3Unpinned
WitnessSignatureValid(w) == w # WitnessASeq3Forged

WitnessFreshAt(w, evaluationTime) ==
    /\ WitnessObservedAt(w) <= evaluationTime
    /\ evaluationTime <= WitnessObservedAt(w) + MaxWitnessAge

WitnessVerifiedAt(w, evaluationTime) ==
    /\ w \in WitnessStatements
    /\ WitnessStream(w) \in Streams
    /\ WitnessPinValid(w)
    /\ WitnessSignatureValid(w)
    /\ WitnessFreshAt(w, evaluationTime)

\* ---------------------------------------------------------------------
\* State.
\* ---------------------------------------------------------------------
VARIABLES
    now,
    step,

    revoked,
    revokedBy,
    revokedAt,
    lastRevocationVerdict,
    acceptedRevocations,
    refusedRevocationKinds,

    lastStatus,
    lastStatusVerdict,
    acceptedStatuses,
    refusedStatusKinds,

    headSequence,
    headDigest,
    headStatement,
    headAcceptedAt,
    poisoned,
    everPoisoned,
    poisonEvidence,
    poisonedAt,
    lastWitnessStatement,
    lastWitnessVerdict,
    acceptedWitnessStatements,
    refusedWitnessKinds

clockVars == <<now, step>>

revocationVars == <<
    revoked,
    revokedBy,
    revokedAt,
    lastRevocationVerdict,
    acceptedRevocations,
    refusedRevocationKinds
>>

statusVars == <<
    lastStatus,
    lastStatusVerdict,
    acceptedStatuses,
    refusedStatusKinds
>>

witnessVars == <<
    headSequence,
    headDigest,
    headStatement,
    headAcceptedAt,
    poisoned,
    everPoisoned,
    poisonEvidence,
    poisonedAt,
    lastWitnessStatement,
    lastWitnessVerdict,
    acceptedWitnessStatements,
    refusedWitnessKinds
>>

vars == <<clockVars, revocationVars, statusVars, witnessVars>>

CanRelyOnFreshNotRevokedStatus(t) ==
    /\ t \in Targets
    /\ ~revoked[t]
    /\ lastStatusVerdict[t] = "accepted"
    /\ lastStatus[t] \in Statuses
    /\ StatusVerifiedFreshAt(lastStatus[t], t, now)

WitnessAdvanceable(w) ==
    LET s == WitnessStream(w)
    IN /\ WitnessVerifiedAt(w, now)
       /\ ~poisoned[s]
       /\ (headSequence[s] = 0 \/ WitnessSequence(w) > headSequence[s])

WitnessConflict(w) ==
    LET s == WitnessStream(w)
    IN /\ WitnessVerifiedAt(w, now)
       /\ ~poisoned[s]
       /\ headSequence[s] > 0
       /\ WitnessSequence(w) = headSequence[s]
       /\ WitnessDigest(w) # headDigest[s]

WitnessRefusalKind(w) ==
    LET s == WitnessStream(w)
    IN CASE poisoned[s] ->
                "sequence_equivocation"
         [] ~WitnessPinValid(w) ->
                "witness_key_unpinned"
         [] ~WitnessSignatureValid(w) ->
                "bad_signature"
         [] WitnessObservedAt(w) > now ->
                "observation_from_future"
         [] now > WitnessObservedAt(w) + MaxWitnessAge ->
                "observation_stale"
         [] headSequence[s] > 0
              /\ WitnessSequence(w) = headSequence[s]
              /\ WitnessDigest(w) = headDigest[s] ->
                "statement_replay"
         [] headSequence[s] > 0
              /\ WitnessSequence(w) < headSequence[s] ->
                "sequence_rollback"
         [] OTHER -> "sequence_rollback"

AcceptedStreamCount ==
    Cardinality({s \in Streams : headSequence[s] > 0})

\* ---------------------------------------------------------------------
\* Static shape and state invariants.
\* ---------------------------------------------------------------------
ModelShape ==
    /\ Cardinality(Targets) = 2
    /\ Cardinality(Revocations) = 6
    /\ Cardinality(Statuses) = 6
    /\ Cardinality(Streams) = 5
    /\ Cardinality(WitnessStatements) = 13
    /\ Cardinality(WitnessDigests) = 8
    /\ StreamA # StreamTenantB
    /\ StreamA # StreamGateB
    /\ StreamA # StreamWitnessB
    /\ StreamA # StreamCaptureB
    /\ StreamA.tenant # StreamTenantB.tenant
    /\ StreamA.gate = StreamTenantB.gate
    /\ StreamA.witness = StreamTenantB.witness
    /\ StreamA.capture = StreamTenantB.capture
    /\ StreamA.tenant = StreamGateB.tenant
    /\ StreamA.gate # StreamGateB.gate
    /\ StreamA.witness = StreamGateB.witness
    /\ StreamA.capture = StreamGateB.capture
    /\ StreamA.tenant = StreamWitnessB.tenant
    /\ StreamA.gate = StreamWitnessB.gate
    /\ StreamA.witness # StreamWitnessB.witness
    /\ StreamA.capture = StreamWitnessB.capture
    /\ StreamA.tenant = StreamCaptureB.tenant
    /\ StreamA.gate = StreamCaptureB.gate
    /\ StreamA.witness = StreamCaptureB.witness
    /\ StreamA.capture # StreamCaptureB.capture
    /\ MaxTime >= 4
    /\ MaxWitnessAge >= 1
    /\ MaxSequence >= 3
    /\ MaxSteps >= 5
    /\ \A r \in Revocations :
          /\ RevocationTarget(r) \in Targets
          /\ RevocationEffectiveAt(r) \in Times
    /\ \A s \in Statuses :
          /\ StatusTarget(s) \in Targets
          /\ StatusThisUpdate(s) \in 0..5
          /\ StatusNextUpdate(s) \in 0..5
          /\ StatusThisUpdate(s) < StatusNextUpdate(s)
    /\ \A w \in WitnessStatements :
          /\ WitnessStream(w) \in Streams
          /\ WitnessSequence(w) \in 1..MaxSequence
          /\ WitnessDigest(w) \in WitnessDigests
          /\ WitnessObservedAt(w) \in Times
    /\ WitnessSequence(WitnessASeq2)
          = WitnessSequence(WitnessASeq2Conflict)
    /\ WitnessDigest(WitnessASeq2)
          # WitnessDigest(WitnessASeq2Conflict)
    /\ WitnessVerifiedAt(WitnessASeq2, 1)
    /\ WitnessVerifiedAt(WitnessASeq2Conflict, 1)

TypeInvariant ==
    /\ now \in Times
    /\ step \in 0..MaxSteps
    /\ revoked \in [Targets -> BOOLEAN]
    /\ revokedBy \in [Targets -> Revocations \union {NoRevocation}]
    /\ revokedAt \in [Targets -> Times \union {NoTime}]
    /\ lastRevocationVerdict \in [Targets -> Verdicts]
    /\ acceptedRevocations \subseteq Revocations
    /\ refusedRevocationKinds \subseteq RevocationRefusalKinds
    /\ lastStatus \in [Targets -> Statuses \union {NoStatus}]
    /\ lastStatusVerdict \in [Targets -> Verdicts]
    /\ acceptedStatuses \subseteq Statuses
    /\ refusedStatusKinds \subseteq StatusRefusalKinds
    /\ headSequence \in [Streams -> 0..MaxSequence]
    /\ headDigest \in [Streams -> WitnessDigests \union {NoDigest}]
    /\ headStatement \in
         [Streams -> WitnessStatements \union {NoWitnessStatement}]
    /\ headAcceptedAt \in [Streams -> Times \union {NoTime}]
    /\ poisoned \in [Streams -> BOOLEAN]
    /\ everPoisoned \in [Streams -> BOOLEAN]
    /\ poisonEvidence \in
         [Streams -> WitnessStatements \union {NoWitnessStatement}]
    /\ poisonedAt \in [Streams -> Times \union {NoTime}]
    /\ lastWitnessStatement \in
         [Streams -> WitnessStatements \union {NoWitnessStatement}]
    /\ lastWitnessVerdict \in [Streams -> Verdicts]
    /\ acceptedWitnessStatements \subseteq WitnessStatements
    /\ refusedWitnessKinds \subseteq WitnessRefusalKinds

TerminalRevocationStateSound ==
    \A t \in Targets :
        /\ (revoked[t] <=> revokedBy[t] \in Revocations)
        /\ (~revoked[t] =>
              /\ revokedBy[t] = NoRevocation
              /\ revokedAt[t] = NoTime)
        /\ (revoked[t] =>
              /\ revokedAt[t] \in Times
              /\ revokedAt[t] <= now
              /\ RevocationVerifiedAt(revokedBy[t], t, revokedAt[t]))

\* There is deliberately no max-age term here.  Advancing trusted time can
\* make a future revocation effective; it cannot make an effective terminal
\* revocation invalid.
TerminalRevocationDoesNotAgeOut ==
    \A t \in Targets :
        revoked[t] =>
            RevocationVerifiedAt(revokedBy[t], t, now)

FreshStatusRelianceSound ==
    \A t \in Targets :
        CanRelyOnFreshNotRevokedStatus(t) =>
            /\ ~revoked[t]
            /\ StatusAuthenticatedFor(lastStatus[t], t)
            /\ StatusThisUpdate(lastStatus[t]) <= now
            /\ now < StatusNextUpdate(lastStatus[t])

TerminalRevocationOverridesStatus ==
    \A t \in Targets :
        revoked[t] => ~CanRelyOnFreshNotRevokedStatus(t)

WitnessHeadSound ==
    \A s \in Streams :
        /\ (headSequence[s] = 0 <=>
              /\ headDigest[s] = NoDigest
              /\ headStatement[s] = NoWitnessStatement
              /\ headAcceptedAt[s] = NoTime)
        /\ (headSequence[s] > 0 =>
              LET w == headStatement[s]
              IN /\ w \in acceptedWitnessStatements
                 /\ WitnessStream(w) = s
                 /\ WitnessSequence(w) = headSequence[s]
                 /\ WitnessDigest(w) = headDigest[s]
                 /\ headAcceptedAt[s] \in Times
                 /\ WitnessVerifiedAt(w, headAcceptedAt[s]))

PoisonEvidenceSound ==
    \A s \in Streams :
        /\ (~poisoned[s] =>
              /\ poisonEvidence[s] = NoWitnessStatement
              /\ poisonedAt[s] = NoTime)
        /\ (poisoned[s] =>
              LET w == poisonEvidence[s]
              IN /\ w \in WitnessStatements
                 /\ poisonedAt[s] \in Times
                 /\ WitnessVerifiedAt(w, poisonedAt[s])
                 /\ WitnessStream(w) = s
                 /\ WitnessSequence(w) = headSequence[s]
                 /\ WitnessDigest(w) # headDigest[s])

PoisonIrreversibilityState ==
    \A s \in Streams :
        everPoisoned[s] => poisoned[s]

PoisonedStreamClosed ==
    \A s \in Streams :
        poisoned[s] =>
            /\ lastWitnessVerdict[s] = "refused"
            /\ headSequence[s] > 0

AdversaryObservationsTyped ==
    /\ acceptedRevocations \subseteq Revocations
    /\ refusedRevocationKinds \subseteq RevocationRefusalKinds
    /\ acceptedStatuses \subseteq Statuses
    /\ refusedStatusKinds \subseteq StatusRefusalKinds
    /\ acceptedWitnessStatements \subseteq WitnessStatements
    /\ refusedWitnessKinds \subseteq WitnessRefusalKinds

\* ---------------------------------------------------------------------
\* Initial state.
\* ---------------------------------------------------------------------
Init ==
    /\ now = 0
    /\ step = 0

    /\ revoked = [t \in Targets |-> FALSE]
    /\ revokedBy = [t \in Targets |-> NoRevocation]
    /\ revokedAt = [t \in Targets |-> NoTime]
    /\ lastRevocationVerdict = [t \in Targets |-> "none"]
    /\ acceptedRevocations = {}
    /\ refusedRevocationKinds = {}

    /\ lastStatus = [t \in Targets |-> NoStatus]
    /\ lastStatusVerdict = [t \in Targets |-> "none"]
    /\ acceptedStatuses = {}
    /\ refusedStatusKinds = {}

    /\ headSequence = [s \in Streams |-> 0]
    /\ headDigest = [s \in Streams |-> NoDigest]
    /\ headStatement = [s \in Streams |-> NoWitnessStatement]
    /\ headAcceptedAt = [s \in Streams |-> NoTime]
    /\ poisoned = [s \in Streams |-> FALSE]
    /\ everPoisoned = [s \in Streams |-> FALSE]
    /\ poisonEvidence = [s \in Streams |-> NoWitnessStatement]
    /\ poisonedAt = [s \in Streams |-> NoTime]
    /\ lastWitnessStatement = [s \in Streams |-> NoWitnessStatement]
    /\ lastWitnessVerdict = [s \in Streams |-> "none"]
    /\ acceptedWitnessStatements = {}
    /\ refusedWitnessKinds = {}

StepOpen == step < MaxSteps

AdvanceTime ==
    /\ StepOpen
    /\ now < MaxTime
    /\ \E later \in (now + 1)..MaxTime : now' = later
    /\ step' = step + 1
    /\ UNCHANGED <<revocationVars, statusVars, witnessVars>>

\* Deterministic aliases used only by the selected-trace refinement harness.
\* The governed model's Next relation continues to use AdvanceTime.
AdvanceTimeToOne == AdvanceTime /\ now' = 1
AdvanceTimeToMax == AdvanceTime /\ now' = MaxTime

AcceptTerminalRevocation(r, t) ==
    /\ StepOpen
    /\ r \in Revocations
    /\ t \in Targets
    /\ ~revoked[t]
    /\ RevocationVerifiedAt(r, t, now)
    /\ revoked' = [revoked EXCEPT ![t] = TRUE]
    /\ revokedBy' = [revokedBy EXCEPT ![t] = r]
    /\ revokedAt' = [revokedAt EXCEPT ![t] = now]
    /\ lastRevocationVerdict' =
         [lastRevocationVerdict EXCEPT ![t] = "accepted"]
    /\ acceptedRevocations' = acceptedRevocations \union {r}
    /\ UNCHANGED refusedRevocationKinds
    /\ step' = step + 1
    /\ UNCHANGED <<now, statusVars, witnessVars>>

RefuseTerminalRevocation(r, t) ==
    /\ StepOpen
    /\ r \in Revocations
    /\ t \in Targets
    /\ ~RevocationVerifiedAt(r, t, now)
    /\ LET kind == RevocationRefusalKindAt(r, t, now)
       IN /\ kind \in RevocationRefusalKinds
          /\ (kind \notin refusedRevocationKinds
                \/ lastRevocationVerdict[t] # "refused")
          /\ lastRevocationVerdict' =
               [lastRevocationVerdict EXCEPT ![t] = "refused"]
          /\ refusedRevocationKinds' =
               refusedRevocationKinds \union {kind}
    /\ UNCHANGED <<revoked, revokedBy, revokedAt, acceptedRevocations>>
    /\ step' = step + 1
    /\ UNCHANGED <<now, statusVars, witnessVars>>

AcceptFreshStatus(s, t) ==
    /\ StepOpen
    /\ s \in Statuses
    /\ t \in Targets
    /\ ~revoked[t]
    /\ StatusVerifiedFreshAt(s, t, now)
    /\ lastStatus' = [lastStatus EXCEPT ![t] = s]
    /\ lastStatusVerdict' =
         [lastStatusVerdict EXCEPT ![t] = "accepted"]
    /\ acceptedStatuses' = acceptedStatuses \union {s}
    /\ UNCHANGED refusedStatusKinds
    /\ step' = step + 1
    /\ UNCHANGED <<now, revocationVars, witnessVars>>

RefuseStatus(s, t) ==
    /\ StepOpen
    /\ s \in Statuses
    /\ t \in Targets
    /\ ~(~revoked[t] /\ StatusVerifiedFreshAt(s, t, now))
    /\ LET kind ==
           CASE revoked[t] ->
                    "terminal_revocation"
             [] ~StatusWellFormed(s) ->
                    "malformed_status"
             [] StatusTarget(s) # t ->
                    "target_mismatch"
             [] ~StatusPinned(s) ->
                    "status_key_unpinned"
             [] ~StatusSignatureValid(s) ->
                    "bad_signature"
             [] StatusThisUpdate(s) > now ->
                    "status_from_future"
             [] now >= StatusNextUpdate(s) ->
                    "status_stale"
             [] OTHER -> "status_stale"
       IN /\ kind \in StatusRefusalKinds
          /\ (kind \notin refusedStatusKinds
                \/ lastStatusVerdict[t] # "refused")
          /\ lastStatusVerdict' =
               [lastStatusVerdict EXCEPT ![t] = "refused"]
          /\ refusedStatusKinds' = refusedStatusKinds \union {kind}
    /\ UNCHANGED <<lastStatus, acceptedStatuses>>
    /\ step' = step + 1
    /\ UNCHANGED <<now, revocationVars, witnessVars>>

AcceptWitness(w) ==
    /\ StepOpen
    /\ w \in WitnessStatements
    /\ WitnessAdvanceable(w)
    /\ LET s == WitnessStream(w)
       IN /\ headSequence' =
                [headSequence EXCEPT ![s] = WitnessSequence(w)]
          /\ headDigest' =
                [headDigest EXCEPT ![s] = WitnessDigest(w)]
          /\ headStatement' =
                [headStatement EXCEPT ![s] = w]
          /\ headAcceptedAt' =
                [headAcceptedAt EXCEPT ![s] = now]
          /\ lastWitnessStatement' =
                [lastWitnessStatement EXCEPT ![s] = w]
          /\ lastWitnessVerdict' =
                [lastWitnessVerdict EXCEPT ![s] = "accepted"]
    /\ acceptedWitnessStatements' =
         acceptedWitnessStatements \union {w}
    /\ UNCHANGED <<
         poisoned,
         everPoisoned,
         poisonEvidence,
         poisonedAt,
         refusedWitnessKinds
       >>
    /\ step' = step + 1
    /\ UNCHANGED <<now, revocationVars, statusVars>>

PoisonWitnessStream(w) ==
    /\ StepOpen
    /\ w \in WitnessStatements
    /\ WitnessConflict(w)
    /\ LET s == WitnessStream(w)
       IN /\ poisoned' = [poisoned EXCEPT ![s] = TRUE]
          /\ everPoisoned' = [everPoisoned EXCEPT ![s] = TRUE]
          /\ poisonEvidence' = [poisonEvidence EXCEPT ![s] = w]
          /\ poisonedAt' = [poisonedAt EXCEPT ![s] = now]
          /\ lastWitnessStatement' =
                [lastWitnessStatement EXCEPT ![s] = w]
          /\ lastWitnessVerdict' =
                [lastWitnessVerdict EXCEPT ![s] = "refused"]
    /\ refusedWitnessKinds' =
         refusedWitnessKinds \union {"sequence_equivocation"}
    /\ UNCHANGED <<
         headSequence,
         headDigest,
         headStatement,
         headAcceptedAt,
         acceptedWitnessStatements
       >>
    /\ step' = step + 1
    /\ UNCHANGED <<now, revocationVars, statusVars>>

RefuseWitness(w) ==
    /\ StepOpen
    /\ w \in WitnessStatements
    /\ ~WitnessAdvanceable(w)
    /\ ~WitnessConflict(w)
    /\ LET s == WitnessStream(w)
           kind == WitnessRefusalKind(w)
       IN /\ kind \in WitnessRefusalKinds
          /\ (kind \notin refusedWitnessKinds
                \/ lastWitnessStatement[s] # w
                \/ lastWitnessVerdict[s] # "refused")
          /\ lastWitnessStatement' =
                [lastWitnessStatement EXCEPT ![s] = w]
          /\ lastWitnessVerdict' =
                [lastWitnessVerdict EXCEPT ![s] = "refused"]
          /\ refusedWitnessKinds' =
                refusedWitnessKinds \union {kind}
    /\ UNCHANGED <<
         headSequence,
         headDigest,
         headStatement,
         headAcceptedAt,
         poisoned,
         everPoisoned,
         poisonEvidence,
         poisonedAt,
         acceptedWitnessStatements
       >>
    /\ step' = step + 1
    /\ UNCHANGED <<now, revocationVars, statusVars>>

\* Deliberately unsafe operators, excluded from Next. The selected-trace
\* harness uses them as negative controls and requires the named invariant
\* counterexample while the real runtime refuses the corresponding attempt.
UnsafeAcceptFutureRevocation ==
    /\ now = 1
    /\ ~revoked[TargetA]
    /\ revoked' = [revoked EXCEPT ![TargetA] = TRUE]
    /\ revokedBy' = [revokedBy EXCEPT ![TargetA] = RevFutureA]
    /\ revokedAt' = [revokedAt EXCEPT ![TargetA] = now]
    /\ lastRevocationVerdict' =
         [lastRevocationVerdict EXCEPT ![TargetA] = "accepted"]
    /\ acceptedRevocations' =
         acceptedRevocations \union {RevFutureA}
    /\ step' = step + 1
    /\ UNCHANGED <<
         now,
         refusedRevocationKinds,
         statusVars,
         witnessVars
       >>

UnsafeClearWitnessPoison ==
    /\ poisoned[StreamA]
    /\ poisoned' = [poisoned EXCEPT ![StreamA] = FALSE]
    /\ poisonEvidence' =
         [poisonEvidence EXCEPT ![StreamA] = NoWitnessStatement]
    /\ poisonedAt' = [poisonedAt EXCEPT ![StreamA] = NoTime]
    /\ lastWitnessStatement' =
         [lastWitnessStatement EXCEPT ![StreamA] = headStatement[StreamA]]
    /\ lastWitnessVerdict' =
         [lastWitnessVerdict EXCEPT ![StreamA] = "accepted"]
    /\ UNCHANGED <<
         clockVars,
         revocationVars,
         statusVars,
         headSequence,
         headDigest,
         headStatement,
         headAcceptedAt,
         everPoisoned,
         acceptedWitnessStatements,
         refusedWitnessKinds
       >>

\* Keeps the bounded graph deadlock-free after all state-changing steps have
\* been consumed.  Refusal actions above, rather than this idle self-loop, are
\* what make hostile paths visible in TLC action coverage.
Idle ==
    UNCHANGED vars

Next ==
    \/ AdvanceTime
    \/ \E r \in Revocations, t \in Targets :
          AcceptTerminalRevocation(r, t)
    \/ \E r \in Revocations, t \in Targets :
          RefuseTerminalRevocation(r, t)
    \/ \E s \in Statuses, t \in Targets :
          AcceptFreshStatus(s, t)
    \/ \E s \in Statuses, t \in Targets :
          RefuseStatus(s, t)
    \/ \E w \in WitnessStatements : AcceptWitness(w)
    \/ \E w \in WitnessStatements : PoisonWitnessStream(w)
    \/ \E w \in WitnessStatements : RefuseWitness(w)
    \/ Idle

Spec == Init /\ [][Next]_vars

BoundedExploration == step <= MaxSteps

\* ---------------------------------------------------------------------
\* Transition obligations.
\* ---------------------------------------------------------------------
TrustedTimeMonotonic ==
    [][now' >= now]_vars

TerminalRevocationIrreversible ==
    [][\A t \in Targets :
          revoked[t] =>
              /\ revoked'[t]
              /\ revokedBy'[t] = revokedBy[t]
              /\ revokedAt'[t] = revokedAt[t]]_vars

RefusedRevocationIsInert ==
    [][refusedRevocationKinds' # refusedRevocationKinds =>
          /\ revoked' = revoked
          /\ revokedBy' = revokedBy
          /\ revokedAt' = revokedAt
          /\ acceptedRevocations' = acceptedRevocations]_vars

StatusRefusalCannotInstallEvidence ==
    [][refusedStatusKinds' # refusedStatusKinds =>
          /\ lastStatus' = lastStatus
          /\ acceptedStatuses' = acceptedStatuses]_vars

WitnessSequenceMonotonic ==
    [][\A s \in Streams :
          headSequence'[s] >= headSequence[s]]_vars

WitnessAdvanceAuthenticatedFreshPinned ==
    [][\A s \in Streams :
          headSequence'[s] > headSequence[s] =>
              LET w == headStatement'[s]
              IN /\ WitnessStream(w) = s
                 /\ WitnessSequence(w) = headSequence'[s]
                 /\ WitnessDigest(w) = headDigest'[s]
                 /\ WitnessVerifiedAt(w, headAcceptedAt'[s])]_vars

WitnessRefusalCannotAdvance ==
    [][\A s \in Streams :
          lastWitnessVerdict'[s] = "refused" =>
              /\ headSequence'[s] = headSequence[s]
              /\ headDigest'[s] = headDigest[s]
              /\ headStatement'[s] = headStatement[s]]_vars

WitnessPoisonIrreversible ==
    [][\A s \in Streams :
          everPoisoned[s] =>
              /\ poisoned'[s]
              /\ everPoisoned'[s]
              /\ poisonEvidence'[s] = poisonEvidence[s]
              /\ poisonedAt'[s] = poisonedAt[s]]_vars

PoisonedWitnessHeadImmutable ==
    [][\A s \in Streams :
          poisoned[s] =>
              /\ headSequence'[s] = headSequence[s]
              /\ headDigest'[s] = headDigest[s]
              /\ headStatement'[s] = headStatement[s]
              /\ headAcceptedAt'[s] = headAcceptedAt[s]]_vars

PoisonedStreamCannotRestoreAcceptance ==
    [][\A s \in Streams :
          poisoned[s] =>
              lastWitnessVerdict'[s] # "accepted"]_vars

ExactWitnessStreamIsolation ==
    [][\A s1, s2 \in Streams :
          s1 # s2
          /\ (headSequence'[s1] # headSequence[s1]
              \/ poisoned'[s1] # poisoned[s1]
              \/ lastWitnessStatement'[s1] # lastWitnessStatement[s1])
          =>
              /\ headSequence'[s2] = headSequence[s2]
              /\ headDigest'[s2] = headDigest[s2]
              /\ headStatement'[s2] = headStatement[s2]
              /\ headAcceptedAt'[s2] = headAcceptedAt[s2]
              /\ poisoned'[s2] = poisoned[s2]
              /\ everPoisoned'[s2] = everPoisoned[s2]
              /\ poisonEvidence'[s2] = poisonEvidence[s2]
              /\ poisonedAt'[s2] = poisonedAt[s2]
              /\ lastWitnessStatement'[s2] = lastWitnessStatement[s2]
              /\ lastWitnessVerdict'[s2] = lastWitnessVerdict[s2]]_vars

THEOREM Spec => []ModelShape
THEOREM Spec => []TypeInvariant
THEOREM Spec => []TerminalRevocationStateSound
THEOREM Spec => []TerminalRevocationDoesNotAgeOut
THEOREM Spec => []FreshStatusRelianceSound
THEOREM Spec => []TerminalRevocationOverridesStatus
THEOREM Spec => []WitnessHeadSound
THEOREM Spec => []PoisonEvidenceSound
THEOREM Spec => []PoisonIrreversibilityState
THEOREM Spec => []PoisonedStreamClosed
THEOREM Spec => []AdversaryObservationsTyped
THEOREM Spec => TrustedTimeMonotonic
THEOREM Spec => TerminalRevocationIrreversible
THEOREM Spec => RefusedRevocationIsInert
THEOREM Spec => StatusRefusalCannotInstallEvidence
THEOREM Spec => WitnessSequenceMonotonic
THEOREM Spec => WitnessAdvanceAuthenticatedFreshPinned
THEOREM Spec => WitnessRefusalCannotAdvance
THEOREM Spec => WitnessPoisonIrreversible
THEOREM Spec => PoisonedWitnessHeadImmutable
THEOREM Spec => PoisonedStreamCannotRestoreAcceptance
THEOREM Spec => ExactWitnessStreamIsolation

=======================================================================
