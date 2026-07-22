------------------------ MODULE ep_trust_program ------------------------
\* EMILIA Gate Trust Program - bounded approval DAG and execution model.
\*
\* This is a finite model of the state persisted by
\* packages/gate/src/trust-program.ts.  The bounded instance deliberately has
\* heterogeneous policy stages and a diamond-shaped dependency graph:
\*
\*   identity(all) -> screening(any) -----\
\*          \------> legal(all) -----------> approval(2-of-3) -> execution
\*
\* It checks the security boundary rather than verifier internals: evidence is
\* admitted only after an external verifier has authenticated and bound it to
\* the exact stage/seat challenge.  Invalid evidence and stale CAS attempts are
\* modeled as refusal (stuttering) actions.
\*
\* Runtime correspondence:
\*   stageStatus / boundPredecessors  -> initialState + updateUnlocks
\*   seatEvidence / usedEvidence     -> stage.evidence + used_evidence_ids
\*   revision                        -> compareAndSwap expectedRevision
\*   executionStatus / claimOwner    -> claimExecution + claim token owner
\*   indeterminate / reconciliation  -> finalizeExecution +
\*                                      authenticated reconcileExecution
\*   programStatus invalidated       -> invalidateState, no new authority;
\*                                      in-flight effect accounting may close

EXTENDS Naturals, FiniteSets

CONSTANTS
    IdentityStage, ScreeningStage, LegalStage, ApprovalStage,
    IdentitySeat, ScreeningSeatA, ScreeningSeatB, LegalSeat,
    ApprovalSeatA, ApprovalSeatB, ApprovalSeatC,
    Evidence, Owners, MaxRevision

Stages == {IdentityStage, ScreeningStage, LegalStage, ApprovalStage}

Seats == {IdentitySeat, ScreeningSeatA, ScreeningSeatB, LegalSeat,
          ApprovalSeatA, ApprovalSeatB, ApprovalSeatC}

NoEvidence == "none"
NoOwner == "none"

StageStates == {"locked", "collecting", "satisfied", "invalidated"}
ExecutionStates == {"locked", "ready", "claimed", "indeterminate",
                    "executed", "proved_no_effect", "refused", "invalidated"}
PostClaimStates == {"claimed", "indeterminate", "executed",
                    "proved_no_effect", "refused"}
ReconciledTerminalStates == {"executed", "proved_no_effect"}
TerminalExecutionStates == {"executed", "proved_no_effect", "refused"}

Dependencies(s) ==
    CASE s = IdentityStage  -> {}
      [] s = ScreeningStage -> {IdentityStage}
      [] s = LegalStage     -> {IdentityStage}
      [] s = ApprovalStage  -> {ScreeningStage, LegalStage}

StageSeats(s) ==
    CASE s = IdentityStage  -> {IdentitySeat}
      [] s = ScreeningStage -> {ScreeningSeatA, ScreeningSeatB}
      [] s = LegalStage     -> {LegalSeat}
      [] s = ApprovalStage  -> {ApprovalSeatA, ApprovalSeatB, ApprovalSeatC}

RuleKind(s) ==
    CASE s = IdentityStage  -> "all"
      [] s = ScreeningStage -> "any"
      [] s = LegalStage     -> "all"
      [] s = ApprovalStage  -> "threshold"

Required(s) ==
    CASE s = IdentityStage  -> 1
      [] s = ScreeningStage -> 1
      [] s = LegalStage     -> 1
      [] s = ApprovalStage  -> 2

ExecutionDependencies == {ApprovalStage}

VARIABLES
    programStatus,              \* "active" or terminal "invalidated"
    stageStatus,                \* stage -> locked/collecting/satisfied/invalidated
    boundPredecessors,          \* exact predecessor receipt set bound at unlock
    seatEvidence,               \* requirement seat -> accepted evidence id or none
    usedEvidence,               \* globally consumed evidence ids
    receiptIssued,              \* stages whose signed receipt was issued
    executionStatus,            \* locked/ready/claimed/outcome/fence
    claimOwner,                 \* persistent owner of the one execution claim
    claimCount,                 \* 0 or 1; never reset
    terminalSource,             \* none/owner_claim/authenticated_reconciliation
    reconciliationAuthenticated,\* TRUE only after verifier-approved reconciliation
    revision                    \* durable CAS revision

vars == <<programStatus, stageStatus, boundPredecessors, seatEvidence,
          usedEvidence, receiptIssued, executionStatus, claimOwner,
          claimCount, terminalSource, reconciliationAuthenticated, revision>>

payloadVars == <<programStatus, stageStatus, boundPredecessors, seatEvidence,
                 usedEvidence, receiptIssued, executionStatus, claimOwner,
                 claimCount, terminalSource, reconciliationAuthenticated>>

SatisfiedIn(statuses) == {s \in Stages : statuses[s] = "satisfied"}

DependenciesSatisfiedIn(statuses, s) ==
    Dependencies(s) \subseteq SatisfiedIn(statuses)

ExecutionDependenciesSatisfiedIn(statuses) ==
    ExecutionDependencies \subseteq SatisfiedIn(statuses)

ApprovalSeatsIn(assignments, s) ==
    {q \in StageSeats(s) : assignments[q] # NoEvidence}

ApprovalCountIn(assignments, s) ==
    Cardinality(ApprovalSeatsIn(assignments, s))

EvidenceAssignments(assignments, e) ==
    {q \in Seats : assignments[q] = e}

\* ---------------------------------------------------------------------
\* Static bounded-program shape.
\* ---------------------------------------------------------------------
ProgramShape ==
    /\ IdentityStage # ScreeningStage
    /\ IdentityStage # LegalStage
    /\ IdentityStage # ApprovalStage
    /\ ScreeningStage # LegalStage
    /\ ScreeningStage # ApprovalStage
    /\ LegalStage # ApprovalStage
    /\ Cardinality(Evidence) >= 5
    /\ Cardinality(Owners) >= 2
    /\ NoEvidence \notin Evidence
    /\ NoOwner \notin Owners
    /\ MaxRevision >= 9
    /\ \A s \in Stages :
          /\ StageSeats(s) \subseteq Seats
          /\ StageSeats(s) # {}
          /\ Dependencies(s) \subseteq Stages \ {s}
          /\ Required(s) \in 1..Cardinality(StageSeats(s))
    /\ \A s1, s2 \in Stages :
          s1 # s2 => StageSeats(s1) \intersect StageSeats(s2) = {}
    /\ RuleKind(IdentityStage) = "all"
    /\ RuleKind(ScreeningStage) = "any"
    /\ RuleKind(LegalStage) = "all"
    /\ RuleKind(ApprovalStage) = "threshold"
    /\ Required(IdentityStage) = Cardinality(StageSeats(IdentityStage))
    /\ Required(ScreeningStage) = 1
    /\ Required(LegalStage) = Cardinality(StageSeats(LegalStage))
    /\ 1 < Required(ApprovalStage)
    /\ Required(ApprovalStage) < Cardinality(StageSeats(ApprovalStage))

\* ---------------------------------------------------------------------
\* Type and state invariants.
\* ---------------------------------------------------------------------
TypeInvariant ==
    /\ programStatus \in {"active", "invalidated"}
    /\ stageStatus \in [Stages -> StageStates]
    /\ boundPredecessors \in [Stages -> SUBSET Stages]
    /\ seatEvidence \in [Seats -> Evidence \union {NoEvidence}]
    /\ usedEvidence \subseteq Evidence
    /\ receiptIssued \subseteq Stages
    /\ executionStatus \in ExecutionStates
    /\ claimOwner \in Owners \union {NoOwner}
    /\ claimCount \in 0..1
    /\ terminalSource \in {"none", "owner_claim", "authenticated_reconciliation"}
    /\ reconciliationAuthenticated \in BOOLEAN
    /\ revision \in 0..MaxRevision

\* While active, locked/collecting/satisfied are exact derived states: a stage
\* cannot collect before every dependency is satisfied, and it becomes
\* satisfied exactly at its effective threshold.
StageLifecycleConsistent ==
    programStatus = "active" =>
        \A s \in Stages :
            /\ (stageStatus[s] = "locked")
                  <=> ~DependenciesSatisfiedIn(stageStatus, s)
            /\ (stageStatus[s] = "collecting")
                  <=> (DependenciesSatisfiedIn(stageStatus, s)
                       /\ ApprovalCountIn(seatEvidence, s) < Required(s))
            /\ (stageStatus[s] = "satisfied")
                  <=> (DependenciesSatisfiedIn(stageStatus, s)
                       /\ ApprovalCountIn(seatEvidence, s) >= Required(s))

\* An unlocked stage binds exactly the complete dependency set - no missing
\* predecessor and no unrelated predecessor.  Every bound predecessor has an
\* issued stage receipt.
ExactDependencyBinding ==
    programStatus = "active" =>
        /\ receiptIssued = SatisfiedIn(stageStatus)
        /\ \A s \in Stages :
              /\ (stageStatus[s] = "locked" => boundPredecessors[s] = {})
              /\ (stageStatus[s] \in {"collecting", "satisfied"} =>
                    /\ boundPredecessors[s] = Dependencies(s)
                    /\ boundPredecessors[s] \subseteq receiptIssued)

\* usedEvidence is neither an advisory log nor a count.  It is exactly the
\* range of accepted evidence assignments, and one evidence id owns at most one
\* requirement seat across the whole program.
EvidenceUseIsExact ==
    usedEvidence = {e \in Evidence : \E q \in Seats : seatEvidence[q] = e}

EvidenceOneUse ==
    \A e \in Evidence : Cardinality(EvidenceAssignments(seatEvidence, e)) <= 1

\* A partial threshold grants no proportional authority.  Until the 2-of-3
\* approval stage is fully satisfied, execution is locked and unowned.
PartialThresholdZeroAuthority ==
    programStatus = "active" =>
        \A s \in Stages :
            (RuleKind(s) = "threshold"
             /\ ApprovalCountIn(seatEvidence, s) > 0
             /\ ApprovalCountIn(seatEvidence, s) < Required(s)) =>
                /\ stageStatus[s] = "collecting"
                /\ executionStatus = "locked"
                /\ claimCount = 0
                /\ claimOwner = NoOwner

\* Execution authority exists only after the exact terminal dependency set is
\* satisfied.  Once authority exists it is represented by ready or a post-claim
\* state, never by a partially satisfied stage.
ExecutionRequiresExactDependencies ==
    programStatus = "active" =>
        /\ ((executionStatus = "locked")
              <=> ~ExecutionDependenciesSatisfiedIn(stageStatus))
        /\ (executionStatus # "locked" =>
              ExecutionDependenciesSatisfiedIn(stageStatus))

SingleOwnerState ==
    /\ (programStatus = "active" =>
          /\ (claimCount = 0 =>
                /\ claimOwner = NoOwner
                /\ executionStatus \in {"locked", "ready"})
          /\ (claimCount = 1 =>
                /\ claimOwner \in Owners
                /\ executionStatus \in PostClaimStates))
    /\ (programStatus = "invalidated" =>
          /\ (claimCount = 0 =>
                /\ claimOwner = NoOwner
                /\ executionStatus = "invalidated")
          /\ (claimCount = 1 =>
                /\ claimOwner \in Owners
                /\ executionStatus \in PostClaimStates))

IndeterminateStateFence ==
    executionStatus = "indeterminate" =>
        /\ claimCount = 1
        /\ claimOwner \in Owners
        /\ terminalSource = "owner_claim"
        /\ ~reconciliationAuthenticated

AuthenticatedTerminalState ==
    /\ (executionStatus = "proved_no_effect" =>
          /\ terminalSource = "authenticated_reconciliation"
          /\ reconciliationAuthenticated)
    /\ (executionStatus = "executed"
        /\ terminalSource = "authenticated_reconciliation" =>
          reconciliationAuthenticated)

InvalidatedStateIsClosed ==
    programStatus = "invalidated" =>
        /\ \A s \in Stages : stageStatus[s] = "invalidated"
        /\ executionStatus \in {"invalidated"} \union PostClaimStates

\* ---------------------------------------------------------------------
\* Initial state: the instance has already been atomically created at rev 0.
\* Only dependency-free roots collect; every downstream stage is locked.
\* ---------------------------------------------------------------------
Init ==
    /\ programStatus = "active"
    /\ stageStatus = [s \in Stages |->
          IF Dependencies(s) = {} THEN "collecting" ELSE "locked"]
    /\ boundPredecessors = [s \in Stages |-> {}]
    /\ seatEvidence = [q \in Seats |-> NoEvidence]
    /\ usedEvidence = {}
    /\ receiptIssued = {}
    /\ executionStatus = "locked"
    /\ claimOwner = NoOwner
    /\ claimCount = 0
    /\ terminalSource = "none"
    /\ reconciliationAuthenticated = FALSE
    /\ revision = 0

\* ---------------------------------------------------------------------
\* Successful atomic transitions.  expected = revision is the store CAS guard;
\* every durable state change and all derived unlocks commit at revision + 1.
\* ---------------------------------------------------------------------
AdmitEvidence(expected, s, q, e) ==
    /\ programStatus = "active"
    /\ expected = revision
    /\ revision < MaxRevision
    /\ stageStatus[s] = "collecting"
    /\ q \in StageSeats(s)
    /\ seatEvidence[q] = NoEvidence
    /\ e \notin usedEvidence
    /\ LET evidenceAfter == [seatEvidence EXCEPT ![q] = e]
           admittedStatus ==
               [stageStatus EXCEPT ![s] =
                   IF ApprovalCountIn(evidenceAfter, s) >= Required(s)
                   THEN "satisfied"
                   ELSE "collecting"]
           statusAfter ==
               [t \in Stages |->
                   IF admittedStatus[t] = "locked"
                      /\ DependenciesSatisfiedIn(admittedStatus, t)
                   THEN "collecting"
                   ELSE admittedStatus[t]]
           bindingsAfter ==
               [t \in Stages |->
                   IF stageStatus[t] = "locked"
                      /\ statusAfter[t] = "collecting"
                   THEN Dependencies(t)
                   ELSE boundPredecessors[t]]
           receiptsAfter ==
               IF admittedStatus[s] = "satisfied"
               THEN receiptIssued \union {s}
               ELSE receiptIssued
           executionAfter ==
               IF executionStatus = "locked"
                  /\ ExecutionDependenciesSatisfiedIn(statusAfter)
               THEN "ready"
               ELSE executionStatus
       IN /\ seatEvidence' = evidenceAfter
          /\ usedEvidence' = usedEvidence \union {e}
          /\ stageStatus' = statusAfter
          /\ boundPredecessors' = bindingsAfter
          /\ receiptIssued' = receiptsAfter
          /\ executionStatus' = executionAfter
    /\ revision' = revision + 1
    /\ UNCHANGED <<programStatus, claimOwner, claimCount, terminalSource,
                   reconciliationAuthenticated>>

ClaimExecution(expected, owner) ==
    /\ programStatus = "active"
    /\ expected = revision
    /\ revision < MaxRevision
    /\ executionStatus = "ready"
    /\ ExecutionDependenciesSatisfiedIn(stageStatus)
    /\ claimCount = 0
    /\ claimOwner = NoOwner
    /\ executionStatus' = "claimed"
    /\ claimOwner' = owner
    /\ claimCount' = 1
    /\ revision' = revision + 1
    /\ UNCHANGED <<programStatus, stageStatus, boundPredecessors,
                   seatEvidence, usedEvidence, receiptIssued, terminalSource,
                   reconciliationAuthenticated>>

FinalizeExecution(expected, owner, outcome) ==
    /\ expected = revision
    /\ revision < MaxRevision
    /\ executionStatus = "claimed"
    /\ owner = claimOwner
    /\ outcome \in {"executed", "refused", "indeterminate"}
    /\ executionStatus' = outcome
    /\ terminalSource' = "owner_claim"
    /\ revision' = revision + 1
    /\ UNCHANGED <<programStatus, stageStatus, boundPredecessors,
                   seatEvidence, usedEvidence, receiptIssued, claimOwner,
                   claimCount, reconciliationAuthenticated>>

\* Only the authenticated reconciliation action can leave the indeterminate
\* fence for a conclusive effect result.  proved_no_effect is intentionally not
\* a direct owner-finalization outcome.
ReconcileExecution(expected, outcome) ==
    /\ expected = revision
    /\ revision < MaxRevision
    /\ executionStatus = "indeterminate"
    /\ outcome \in ReconciledTerminalStates
    /\ executionStatus' = outcome
    /\ terminalSource' = "authenticated_reconciliation"
    /\ reconciliationAuthenticated' = TRUE
    /\ revision' = revision + 1
    /\ UNCHANGED <<programStatus, stageStatus, boundPredecessors,
                   seatEvidence, usedEvidence, receiptIssued, claimOwner,
                   claimCount>>

\* Invalidation is one atomic CAS transition.  It closes every stage and any
\* not-yet-claimed execution authority.  An already owned claim and its
\* one-way finalization/reconciliation path remain available solely to account
\* for an effect that may already be in flight, matching invalidateState.
Invalidate(expected) ==
    /\ programStatus = "active"
    /\ expected = revision
    /\ revision < MaxRevision
    /\ programStatus' = "invalidated"
    /\ stageStatus' = [s \in Stages |-> "invalidated"]
    /\ executionStatus' =
          IF executionStatus \in {"locked", "ready"}
          THEN "invalidated"
          ELSE executionStatus
    /\ revision' = revision + 1
    /\ UNCHANGED <<boundPredecessors, seatEvidence, usedEvidence,
                   receiptIssued, claimOwner, claimCount, terminalSource,
                   reconciliationAuthenticated>>

\* ---------------------------------------------------------------------
\* Refusal paths.  These are explicit no-ops: failed verification, replay,
\* stale revision, wrong owner, duplicate claim, and unauthenticated
\* reconciliation cannot mutate durable state or consume a revision.
\* ---------------------------------------------------------------------
StaleRevisionAttempt(expected) ==
    /\ expected # revision
    /\ UNCHANGED vars

LockedStageAttempt(s) ==
    /\ programStatus = "active"
    /\ stageStatus[s] = "locked"
    /\ UNCHANGED vars

ReplayEvidenceAttempt(e) ==
    /\ programStatus = "active"
    /\ e \in usedEvidence
    /\ UNCHANGED vars

SecondClaimAttempt(owner) ==
    /\ programStatus = "active"
    /\ owner \in Owners
    /\ executionStatus \in PostClaimStates
    /\ UNCHANGED vars

WrongOwnerFinalizeAttempt(owner) ==
    /\ programStatus = "active"
    /\ executionStatus = "claimed"
    /\ owner # claimOwner
    /\ UNCHANGED vars

UnauthenticatedReconcileAttempt ==
    /\ programStatus = "active"
    /\ executionStatus = "indeterminate"
    /\ UNCHANGED vars

Next ==
    \/ \E expected \in 0..MaxRevision, s \in Stages,
          q \in Seats, e \in Evidence : AdmitEvidence(expected, s, q, e)
    \/ \E expected \in 0..MaxRevision, owner \in Owners :
          ClaimExecution(expected, owner)
    \/ \E expected \in 0..MaxRevision, owner \in Owners,
          outcome \in {"executed", "refused", "indeterminate"} :
          FinalizeExecution(expected, owner, outcome)
    \/ \E expected \in 0..MaxRevision,
          outcome \in ReconciledTerminalStates :
          ReconcileExecution(expected, outcome)
    \/ \E expected \in 0..MaxRevision : Invalidate(expected)
    \/ \E expected \in 0..MaxRevision : StaleRevisionAttempt(expected)
    \/ \E s \in Stages : LockedStageAttempt(s)
    \/ \E e \in Evidence : ReplayEvidenceAttempt(e)
    \/ \E owner \in Owners : SecondClaimAttempt(owner)
    \/ \E owner \in Owners : WrongOwnerFinalizeAttempt(owner)
    \/ UnauthenticatedReconcileAttempt

Spec == Init /\ [][Next]_vars

BoundedExploration == revision <= MaxRevision

\* ---------------------------------------------------------------------
\* Transition properties.
\* ---------------------------------------------------------------------
RevisionMonotonic ==
    [][revision' >= revision]_vars

\* A successful mutation changes payload and advances exactly one revision;
\* every refusal/stutter changes neither.  This rules out torn multi-field
\* transitions and revision-only writes.
AtomicRevisionTransitions ==
    [][ \/ (payloadVars' = payloadVars /\ revision' = revision)
        \/ (payloadVars' # payloadVars /\ revision' = revision + 1) ]_vars

EvidenceUseMonotonic ==
    [][usedEvidence \subseteq usedEvidence']_vars

SatisfiedDoesNotReopen ==
    [][\A s \in Stages :
          stageStatus[s] = "satisfied" =>
              stageStatus'[s] \in {"satisfied", "invalidated"}]_vars

\* Once claimed, the claim count and owner are permanent.  Finalization,
\* reconciliation, and invalidation cannot transfer execution ownership.
ClaimOwnerImmutable ==
    [][claimCount = 1 =>
          /\ claimCount' = 1
          /\ claimOwner' = claimOwner]_vars

ClaimRequiresReady ==
    [][(executionStatus # "claimed" /\ executionStatus' = "claimed") =>
          /\ executionStatus = "ready"
          /\ claimCount = 0
          /\ ExecutionDependenciesSatisfiedIn(stageStatus)]_vars

IndeterminateOnlyReconcilesOrInvalidates ==
    [][(executionStatus = "indeterminate"
        /\ executionStatus' # "indeterminate") =>
          executionStatus' \in ReconciledTerminalStates]_vars

AuthenticatedReconciliationTransition ==
    [][(terminalSource # "authenticated_reconciliation"
        /\ terminalSource' = "authenticated_reconciliation") =>
          /\ executionStatus = "indeterminate"
          /\ executionStatus' \in ReconciledTerminalStates
          /\ reconciliationAuthenticated']_vars

TerminalExecutionIrreversible ==
    [][(executionStatus \in TerminalExecutionStates =>
          executionStatus' = executionStatus)]_vars

\* Invalidation can never resurrect a stage, evidence seat, receipt, or claim.
\* The only permitted non-stuttering transitions are closure of the already
\* owned execution: claimed -> owner outcome, then indeterminate ->
\* authenticated executed/proved_no_effect.  This is effect accounting, not
\* new execution authority.
NoResurrection ==
    [][(programStatus = "invalidated" =>
          /\ programStatus' = "invalidated"
          /\ stageStatus' = stageStatus
          /\ boundPredecessors' = boundPredecessors
          /\ seatEvidence' = seatEvidence
          /\ usedEvidence' = usedEvidence
          /\ receiptIssued' = receiptIssued
          /\ claimOwner' = claimOwner
          /\ claimCount' = claimCount
          /\ CASE executionStatus = "claimed" ->
                    executionStatus' \in {"claimed", "executed", "refused",
                                           "indeterminate"}
               [] executionStatus = "indeterminate" ->
                    executionStatus' \in {"indeterminate", "executed",
                                           "proved_no_effect"}
               [] OTHER -> executionStatus' = executionStatus)]_vars

THEOREM Spec => []TypeInvariant
THEOREM Spec => []ProgramShape
THEOREM Spec => []StageLifecycleConsistent
THEOREM Spec => []ExactDependencyBinding
THEOREM Spec => []EvidenceUseIsExact
THEOREM Spec => []EvidenceOneUse
THEOREM Spec => []PartialThresholdZeroAuthority
THEOREM Spec => []ExecutionRequiresExactDependencies
THEOREM Spec => []SingleOwnerState
THEOREM Spec => []IndeterminateStateFence
THEOREM Spec => []AuthenticatedTerminalState
THEOREM Spec => []InvalidatedStateIsClosed
THEOREM Spec => RevisionMonotonic
THEOREM Spec => AtomicRevisionTransitions
THEOREM Spec => EvidenceUseMonotonic
THEOREM Spec => SatisfiedDoesNotReopen
THEOREM Spec => ClaimOwnerImmutable
THEOREM Spec => ClaimRequiresReady
THEOREM Spec => IndeterminateOnlyReconcilesOrInvalidates
THEOREM Spec => AuthenticatedReconciliationTransition
THEOREM Spec => TerminalExecutionIrreversible
THEOREM Spec => NoResurrection

=============================================================================
