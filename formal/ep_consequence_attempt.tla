---------------------- MODULE ep_consequence_attempt ----------------------
\* Proposal-to-Effect consequence-attempt custody model.
\*
\* This is a bounded state-machine abstraction of the owner-fenced durable
\* attempt store and its ordering against the AEB one-time-consumption store.
\* It models custody, recovery, provider entry, and reconciliation:
\*
\*   AEB AVAILABLE -> RESERVED ---------------------------> CONSUMED
\*                       |                                      |
\*                       | reserve attempt                      | before commit
\*                       v                                      v
\*   attempt RESERVED -> INVOKING -> INDETERMINATE -> COMMITTED
\*                                      |    |
\*                                      |    |-> ESCALATED (AEB stays fenced)
\*                                      v
\*                                   RELEASED -> AEB AVAILABLE
\*
\* Attempt IDs are server-allocated record keys. Owners are opaque model
\* values: the model makes no secrecy claim, only equality/CAS ownership
\* claims. Recovery includes the PostgreSQL transition used by the runtime:
\* only an expired lease can rotate ownership; RESERVED stays RESERVED, while
\* INVOKING and INDETERMINATE recover as INDETERMINATE. Provider evidence is
\* an ideal authenticated input; cryptographic verification and
\* canonicalization are outside this state-machine abstraction.
\*
\* Bounded-model-checking scope:
\*   - two attempt IDs and two request bindings;
\*   - three owner handles, allowing two custody rotations;
\*   - five fixed evidence items, including one unauthenticated item;
\*   - one abstract AEB authority state per exact request binding;
\*   - a Boolean live/stale lease abstraction, not a wall-clock model;
\*   - no liveness, availability, database, cryptographic, or unbounded proof.

EXTENDS Naturals, FiniteSets

CONSTANTS
    AttemptA, AttemptB,
    RequestA, RequestB,
    OwnerA, OwnerB, OwnerC,
    EvidenceCommitA,
    EvidenceReleaseA,
    EvidenceEscalateA,
    EvidenceCommitB,
    EvidenceUnauthenticatedA

AttemptIds == {AttemptA, AttemptB}
Requests == {RequestA, RequestB}
Owners == {OwnerA, OwnerB, OwnerC}
Evidence == {
    EvidenceCommitA,
    EvidenceReleaseA,
    EvidenceEscalateA,
    EvidenceCommitB,
    EvidenceUnauthenticatedA
}

AttemptStates == {
    "RESERVED",
    "INVOKING",
    "INDETERMINATE",
    "COMMITTED",
    "RELEASED",
    "ESCALATED"
}

TerminalStates == {"COMMITTED", "RELEASED", "ESCALATED"}
UncertainStates == {"INVOKING", "INDETERMINATE"}
ProviderOutcomes == {"COMMITTED", "NOT_COMMITTED", "ESCALATED"}
AebStates == {"AVAILABLE", "RESERVED", "CONSUMED"}

NoRequest == "NO_REQUEST"
NoOwner == "NO_OWNER"
NoEvidence == "NO_EVIDENCE"

\* Fixed evidence attributes for the bounded instance. EvidenceUnauthenticatedA
\* is exact for AttemptA/RequestA but lacks authentication, so authentication is
\* independently load-bearing from exact-attempt matching.
EvidenceAuthenticated(e) == e # EvidenceUnauthenticatedA

EvidenceAttempt(e) ==
    CASE e \in {
             EvidenceCommitA,
             EvidenceReleaseA,
             EvidenceEscalateA,
             EvidenceUnauthenticatedA
         } -> AttemptA
      [] e = EvidenceCommitB -> AttemptB

EvidenceRequest(e) ==
    CASE e \in {
             EvidenceCommitA,
             EvidenceReleaseA,
             EvidenceEscalateA,
             EvidenceUnauthenticatedA
         } -> RequestA
      [] e = EvidenceCommitB -> RequestB

EvidenceOutcome(e) ==
    CASE e \in {EvidenceCommitA, EvidenceCommitB, EvidenceUnauthenticatedA}
         -> "COMMITTED"
      [] e = EvidenceReleaseA -> "NOT_COMMITTED"
      [] e = EvidenceEscalateA -> "ESCALATED"

OutcomeState(outcome) ==
    CASE outcome = "COMMITTED" -> "COMMITTED"
      [] outcome = "NOT_COMMITTED" -> "RELEASED"
      [] outcome = "ESCALATED" -> "ESCALATED"

VARIABLES
    allocated,               \* attempt IDs that have a durable record
    attemptState,            \* live state for each allocated attempt ID
    requestOf,               \* immutable exact request binding
    aebState,                \* AEB one-time authority per exact request
    ownerOf,                 \* current opaque CAS owner
    ownerGeneration,         \* monotonic recovery/CAS generation
    staleOwners,             \* owners fenced by recovery
    leaseStale,              \* DB lease snapshot: FALSE is still live
    providerEntered,         \* whether the provider callback was entered
    effectMayHaveHappened,   \* replay-safety uncertainty bit
    invokeCount,             \* provider-invocation authority uses
    pendingCommitEvidence,   \* exact evidence used to consume AEB first
    reconciliationEvidence  \* authenticated exact-attempt terminal evidence

vars == <<
    allocated,
    attemptState,
    requestOf,
    aebState,
    ownerOf,
    ownerGeneration,
    staleOwners,
    leaseStale,
    providerEntered,
    effectMayHaveHappened,
    invokeCount,
    pendingCommitEvidence,
    reconciliationEvidence
>>

\* -----------------------------------------------------------------------
\* Safety invariants
\* -----------------------------------------------------------------------

TypeInvariant ==
    /\ allocated \subseteq AttemptIds
    /\ attemptState \in [AttemptIds -> AttemptStates]
    /\ requestOf \in [AttemptIds -> Requests \union {NoRequest}]
    /\ aebState \in [Requests -> AebStates]
    /\ ownerOf \in [AttemptIds -> Owners \union {NoOwner}]
    /\ ownerGeneration \in [AttemptIds -> 0..Cardinality(Owners)]
    /\ staleOwners \in [AttemptIds -> SUBSET Owners]
    /\ leaseStale \in [AttemptIds -> BOOLEAN]
    /\ providerEntered \in [AttemptIds -> BOOLEAN]
    /\ effectMayHaveHappened \in [AttemptIds -> BOOLEAN]
    \* The wider finite domain keeps InvokeAtMostOnce independent from typing.
    /\ invokeCount \in [AttemptIds -> 0..2]
    /\ pendingCommitEvidence \in
         [AttemptIds -> Evidence \union {NoEvidence}]
    /\ reconciliationEvidence \in [AttemptIds -> Evidence \union {NoEvidence}]

\* Unallocated TLC slots are not live attempt states. They remain clean until
\* their unique attempt ID is atomically allocated.
DormantSlotsClean ==
    \A a \in AttemptIds \ allocated :
        /\ requestOf[a] = NoRequest
        /\ ownerOf[a] = NoOwner
        /\ ownerGeneration[a] = 0
        /\ staleOwners[a] = {}
        /\ leaseStale[a] = FALSE
        /\ providerEntered[a] = FALSE
        /\ effectMayHaveHappened[a] = FALSE
        /\ invokeCount[a] = 0
        /\ pendingCommitEvidence[a] = NoEvidence
        /\ reconciliationEvidence[a] = NoEvidence

\* One durable record exists per attempt ID by construction (allocated is a
\* set indexed by AttemptIds). The request uniqueness guard additionally
\* prevents blind replay by allocating a fresh attempt ID for the same exact
\* request.
UniqueAttemptRequestBinding ==
    \A a, b \in allocated :
        requestOf[a] = requestOf[b] => a = b

\* Recovery cannot cycle an old owner back into custody, and its generation is
\* exactly the number of owners it has fenced.
StaleOwnerExcluded ==
    \A a \in allocated :
        /\ ownerOf[a] \in Owners
        /\ ownerOf[a] \notin staleOwners[a]
        /\ ownerGeneration[a] = Cardinality(staleOwners[a])

\* The state, invocation count, and uncertainty bit remain mutually
\* consistent. INVOKING is already unsafe to replay: provider entry may race
\* the caller's observation even when providerEntered is not yet recorded.
LifecycleConsistency ==
    \A a \in allocated :
        /\ (attemptState[a] = "RESERVED" =>
              /\ invokeCount[a] = 0
              /\ providerEntered[a] = FALSE
              /\ effectMayHaveHappened[a] = FALSE)
        /\ (attemptState[a] \in UncertainStates =>
              /\ invokeCount[a] = 1
              /\ effectMayHaveHappened[a] = TRUE)
        /\ (attemptState[a] = "COMMITTED" =>
              /\ invokeCount[a] = 1
              /\ effectMayHaveHappened[a] = TRUE)
        /\ (attemptState[a] = "RELEASED" =>
              /\ invokeCount[a] = 1
              /\ effectMayHaveHappened[a] = FALSE)
        /\ (attemptState[a] = "ESCALATED" =>
              /\ invokeCount[a] = 1
              /\ effectMayHaveHappened[a] = TRUE)
        /\ (providerEntered[a] => invokeCount[a] = 1)

InvokeAtMostOnce ==
    \A a \in allocated : invokeCount[a] <= 1

UncertainAttemptBlocksReplay ==
    \A a \in allocated :
        attemptState[a] \in UncertainStates =>
            /\ invokeCount[a] = 1
            /\ effectMayHaveHappened[a] = TRUE

\* Any stored reconciliation evidence must be authenticated, bind the exact
\* attempt ID and immutable request, and map to the recorded terminal state.
\* Direct synchronous COMMITTED and known-not-invoked RELEASED transitions
\* intentionally carry NoEvidence; they are not recovery reconciliation.
AuthenticatedExactAttemptReconciliation ==
    \A a \in allocated :
        LET e == reconciliationEvidence[a]
        IN e # NoEvidence =>
            /\ attemptState[a] \in TerminalStates
            /\ EvidenceAuthenticated(e)
            /\ EvidenceAttempt(e) = a
            /\ EvidenceRequest(e) = requestOf[a]
            /\ attemptState[a] = OutcomeState(EvidenceOutcome(e))

\* COMMITTED provider evidence is verified before AEB is consumed. This
\* pending value abstracts that in-process, pre-terminal window; it is not a
\* claim that provider evidence is durably stored before the attempt CAS.
PendingCommitEvidenceSound ==
    \A a \in allocated :
        LET e == pendingCommitEvidence[a]
        IN e # NoEvidence =>
            /\ attemptState[a] = "INDETERMINATE"
            /\ aebState[requestOf[a]] = "CONSUMED"
            /\ reconciliationEvidence[a] = NoEvidence
            /\ EvidenceAuthenticated(e)
            /\ EvidenceAttempt(e) = a
            /\ EvidenceRequest(e) = requestOf[a]
            /\ EvidenceOutcome(e) = "COMMITTED"

TerminalOutcomeConsistency ==
    \A a \in allocated :
        /\ (attemptState[a] = "COMMITTED" => effectMayHaveHappened[a])
        /\ (attemptState[a] = "RELEASED" => ~effectMayHaveHappened[a])
        /\ (attemptState[a] = "ESCALATED" => effectMayHaveHappened[a])
        /\ (attemptState[a] \in TerminalStates =>
              pendingCommitEvidence[a] = NoEvidence)

\* The AEB reservation is acquired before an attempt and remains fenced while
\* provider outcome is unknown. A RELEASED attempt may briefly retain RESERVED
\* while the separately owner-fenced AEB release completes. Likewise, AEB is
\* CONSUMED before the attempt's final COMMITTED CAS.
AebAttemptCoupling ==
    \A a \in allocated :
        LET authority == aebState[requestOf[a]]
        IN /\ (attemptState[a] = "RESERVED" =>
                  authority = "RESERVED")
           /\ (attemptState[a] = "INVOKING" =>
                  authority = "RESERVED")
           /\ (attemptState[a] = "INDETERMINATE" =>
                  authority \in {"RESERVED", "CONSUMED"})
           /\ (attemptState[a] = "COMMITTED" =>
                  authority = "CONSUMED")
           /\ (attemptState[a] = "RELEASED" =>
                  authority \in {"RESERVED", "AVAILABLE"})
           /\ (attemptState[a] = "ESCALATED" =>
                  authority = "RESERVED")

CommittedRequiresAebConsumed ==
    \A a \in allocated :
        attemptState[a] = "COMMITTED" =>
            aebState[requestOf[a]] = "CONSUMED"

ProviderInvocationRequiresAebAuthority ==
    \A a \in allocated :
        invokeCount[a] > 0 /\ attemptState[a] # "RELEASED" =>
            aebState[requestOf[a]] \in {"RESERVED", "CONSUMED"}

ConsumedAebHasAttempt ==
    \A request \in Requests :
        aebState[request] = "CONSUMED" =>
            \E a \in allocated :
                /\ requestOf[a] = request
                /\ attemptState[a] \in {"INDETERMINATE", "COMMITTED"}

\* -----------------------------------------------------------------------
\* Transition-level safety properties
\* -----------------------------------------------------------------------

AttemptAllocationAndBindingStable ==
    [][ \A a \in allocated :
          /\ a \in allocated'
          /\ requestOf'[a] = requestOf[a] ]_vars

\* Attempt allocation can only attach to authority already reserved for the
\* same immutable request. Reserve does not manufacture AEB authority.
AttemptReservationRequiresAebReserved ==
    [][ \A a \in AttemptIds \ allocated :
          a \in allocated' =>
              /\ aebState[requestOf'[a]] = "RESERVED"
              /\ aebState'[requestOf'[a]] = "RESERVED" ]_vars

OwnerRotationFencesPriorOwner ==
    [][ \A a \in allocated :
          ownerOf'[a] # ownerOf[a] =>
              /\ leaseStale[a]
              /\ ~leaseStale'[a]
              /\ ownerOf[a] \in staleOwners'[a]
              /\ ownerOf'[a] \notin staleOwners'[a]
              /\ ownerGeneration'[a] = ownerGeneration[a] + 1
              /\ IF attemptState[a] = "RESERVED"
                    THEN attemptState'[a] = "RESERVED"
                    ELSE /\ attemptState[a] \in UncertainStates
                         /\ attemptState'[a] = "INDETERMINATE" ]_vars

\* This is the direct safety statement for the SQL predicate
\* lease_expires_at <= clock_timestamp(): a live lease cannot lose ownership.
RecoveryCannotTakeLiveLease ==
    [][ \A a \in allocated :
          ~leaseStale[a] => ownerOf'[a] = ownerOf[a] ]_vars

InvocationCountMonotonic ==
    [][ \A a \in AttemptIds : invokeCount'[a] >= invokeCount[a] ]_vars

\* No transition may consume invocation authority again while the effect may
\* already have happened.
NoBlindReplayWhileUncertain ==
    [][ \A a \in allocated :
          attemptState[a] \in UncertainStates =>
              invokeCount'[a] = invokeCount[a] ]_vars

EffectUncertaintyOnlyClearsToReleased ==
    [][ \A a \in allocated :
          effectMayHaveHappened[a] /\ ~effectMayHaveHappened'[a] =>
              attemptState'[a] = "RELEASED" ]_vars

TerminalStateIrreversibility ==
    [][ \A a \in allocated :
          attemptState[a] \in TerminalStates =>
              attemptState'[a] = attemptState[a] ]_vars

ReconciliationStartsIndeterminate ==
    [][ \A a \in allocated :
          reconciliationEvidence[a] = NoEvidence
            /\ reconciliationEvidence'[a] # NoEvidence =>
              attemptState[a] = "INDETERMINATE" ]_vars

ReconciliationEvidenceImmutable ==
    [][ \A a \in allocated :
          reconciliationEvidence[a] # NoEvidence =>
              reconciliationEvidence'[a] = reconciliationEvidence[a] ]_vars

\* AEB consumption is a pre-terminal step, after invocation authority has
\* already been consumed, and a consumed one-time authority never reopens.
AebConsumptionAfterInvocation ==
    [][ \A request \in Requests :
          aebState[request] = "RESERVED"
            /\ aebState'[request] = "CONSUMED" =>
              \E a \in allocated :
                  /\ requestOf[a] = request
                  /\ attemptState[a] = "INDETERMINATE"
                  /\ invokeCount[a] = 1 ]_vars

AebConsumedNeverReopens ==
    [][ \A request \in Requests :
          aebState[request] = "CONSUMED" =>
              aebState'[request] = "CONSUMED" ]_vars

\* RESERVED may return to AVAILABLE only before any attempt was allocated, or
\* after the exact bound attempt is already RELEASED.
AebReleaseCoupledToReleasedAttempt ==
    [][ \A request \in Requests :
          aebState[request] = "RESERVED"
            /\ aebState'[request] = "AVAILABLE" =>
              \/ ~\E a \in allocated : requestOf[a] = request
              \/ \E a \in allocated :
                    /\ requestOf[a] = request
                    /\ attemptState[a] = "RELEASED" ]_vars

\* -----------------------------------------------------------------------
\* Initial state
\* -----------------------------------------------------------------------

Init ==
    /\ allocated = {}
    /\ attemptState = [a \in AttemptIds |-> "RESERVED"]
    /\ requestOf = [a \in AttemptIds |-> NoRequest]
    /\ aebState = [request \in Requests |-> "AVAILABLE"]
    /\ ownerOf = [a \in AttemptIds |-> NoOwner]
    /\ ownerGeneration = [a \in AttemptIds |-> 0]
    /\ staleOwners = [a \in AttemptIds |-> {}]
    /\ leaseStale = [a \in AttemptIds |-> FALSE]
    /\ providerEntered = [a \in AttemptIds |-> FALSE]
    /\ effectMayHaveHappened = [a \in AttemptIds |-> FALSE]
    /\ invokeCount = [a \in AttemptIds |-> 0]
    /\ pendingCommitEvidence = [a \in AttemptIds |-> NoEvidence]
    /\ reconciliationEvidence = [a \in AttemptIds |-> NoEvidence]

\* -----------------------------------------------------------------------
\* Successful CAS transitions
\* -----------------------------------------------------------------------

\* AEB authority is reserved before attempting durable consequence custody.
\* If allocation or reservation fails, the still-unbound authority can release.
ReserveAeb(request) ==
    /\ aebState[request] = "AVAILABLE"
    /\ ~\E a \in allocated : requestOf[a] = request
    /\ aebState' = [aebState EXCEPT ![request] = "RESERVED"]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, ownerOf, ownerGeneration,
         staleOwners, leaseStale, providerEntered, effectMayHaveHappened,
         invokeCount, pendingCommitEvidence, reconciliationEvidence
       >>

ReleaseUnboundAeb(request) ==
    /\ aebState[request] = "RESERVED"
    /\ ~\E a \in allocated : requestOf[a] = request
    /\ aebState' = [aebState EXCEPT ![request] = "AVAILABLE"]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, ownerOf, ownerGeneration,
         staleOwners, leaseStale, providerEntered, effectMayHaveHappened,
         invokeCount, pendingCommitEvidence, reconciliationEvidence
       >>

Reserve(a, request, owner) ==
    /\ a \notin allocated
    /\ ~\E existing \in allocated : requestOf[existing] = request
    /\ aebState[request] = "RESERVED"
    /\ allocated' = allocated \union {a}
    /\ attemptState' = [attemptState EXCEPT ![a] = "RESERVED"]
    /\ requestOf' = [requestOf EXCEPT ![a] = request]
    /\ ownerOf' = [ownerOf EXCEPT ![a] = owner]
    /\ ownerGeneration' = [ownerGeneration EXCEPT ![a] = 0]
    /\ staleOwners' = [staleOwners EXCEPT ![a] = {}]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ providerEntered' = [providerEntered EXCEPT ![a] = FALSE]
    /\ effectMayHaveHappened' =
         [effectMayHaveHappened EXCEPT ![a] = FALSE]
    /\ invokeCount' = [invokeCount EXCEPT ![a] = 0]
    /\ pendingCommitEvidence' =
         [pendingCommitEvidence EXCEPT ![a] = NoEvidence]
    /\ reconciliationEvidence' =
         [reconciliationEvidence EXCEPT ![a] = NoEvidence]
    /\ UNCHANGED aebState

BeginInvocation(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "RESERVED"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ invokeCount[a] = 0
    /\ attemptState' = [attemptState EXCEPT ![a] = "INVOKING"]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ effectMayHaveHappened' =
         [effectMayHaveHappened EXCEPT ![a] = TRUE]
    /\ invokeCount' = [invokeCount EXCEPT ![a] = 1]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, providerEntered, pendingCommitEvidence,
         reconciliationEvidence
       >>

\* The provider callback can be entered at most once. The uncertainty bit was
\* already raised by BeginInvocation because caller observation and provider
\* entry are not atomic.
EnterProvider(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INVOKING"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ providerEntered[a] = FALSE
    /\ providerEntered' = [providerEntered EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, aebState, ownerOf,
         ownerGeneration, staleOwners, leaseStale,
         effectMayHaveHappened, invokeCount, pendingCommitEvidence,
         reconciliationEvidence
       >>

FreezeIndeterminate(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INVOKING"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ attemptState' = [attemptState EXCEPT ![a] = "INDETERMINATE"]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, providerEntered, effectMayHaveHappened, invokeCount,
         pendingCommitEvidence, reconciliationEvidence
       >>

\* Abstract wall-clock passage and heartbeat renewal as an explicit Boolean
\* race. The current owner may renew even after expiry if it wins the CAS race;
\* if recovery wins first, the old owner is fenced by its owner digest.
ExpireLease(a) ==
    /\ a \in allocated
    /\ attemptState[a] \notin TerminalStates
    /\ ~leaseStale[a]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, aebState, ownerOf,
         ownerGeneration, staleOwners, providerEntered,
         effectMayHaveHappened, invokeCount, pendingCommitEvidence,
         reconciliationEvidence
       >>

HeartbeatLease(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] \notin TerminalStates
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, aebState, ownerOf,
         ownerGeneration, staleOwners, providerEntered,
         effectMayHaveHappened, invokeCount, pendingCommitEvidence,
         reconciliationEvidence
       >>

\* A successful server-authorized recovery mirrors recover_attempt: the
\* expected lease snapshot must be stale, RESERVED remains RESERVED, and both
\* INVOKING and INDETERMINATE recover as INDETERMINATE.
RecoverCustody(a, nextOwner) ==
    /\ a \in allocated
    /\ attemptState[a] \in {"RESERVED", "INVOKING", "INDETERMINATE"}
    /\ leaseStale[a]
    /\ nextOwner \in Owners
    /\ nextOwner # ownerOf[a]
    /\ nextOwner \notin staleOwners[a]
    /\ attemptState' =
         [attemptState EXCEPT
             ![a] = IF @ = "RESERVED" THEN @ ELSE "INDETERMINATE"]
    /\ ownerOf' = [ownerOf EXCEPT ![a] = nextOwner]
    /\ ownerGeneration' =
         [ownerGeneration EXCEPT ![a] = @ + 1]
    /\ staleOwners' =
         [staleOwners EXCEPT ![a] = @ \union {ownerOf[a]}]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, providerEntered,
         effectMayHaveHappened, invokeCount, pendingCommitEvidence,
         reconciliationEvidence
       >>

\* A synchronous success consumes one-time AEB authority before the attempt's
\* COMMITTED CAS. A failed attempt CAS therefore leaves the repairable
\* INDETERMINATE + CONSUMED intermediate state.
ConsumeAebAfterProvider(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ providerEntered[a] = TRUE
    /\ pendingCommitEvidence[a] = NoEvidence
    /\ aebState' =
         [aebState EXCEPT ![requestOf[a]] = "CONSUMED"]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, ownerOf, ownerGeneration,
         staleOwners, leaseStale, providerEntered, effectMayHaveHappened,
         invokeCount, pendingCommitEvidence, reconciliationEvidence
       >>

\* Authenticated COMMITTED evidence follows the same pre-terminal AEB ordering.
\* The evidence is held as a validated pending input until the atomic attempt
\* reconciliation stores it and changes the attempt state.
PrepareCommittedEvidence(a, presentedOwner, evidence) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ pendingCommitEvidence[a] = NoEvidence
    /\ reconciliationEvidence[a] = NoEvidence
    /\ EvidenceAuthenticated(evidence)
    /\ EvidenceAttempt(evidence) = a
    /\ EvidenceRequest(evidence) = requestOf[a]
    /\ EvidenceOutcome(evidence) = "COMMITTED"
    /\ aebState' =
         [aebState EXCEPT ![requestOf[a]] = "CONSUMED"]
    /\ providerEntered' = [providerEntered EXCEPT ![a] = TRUE]
    /\ pendingCommitEvidence' =
         [pendingCommitEvidence EXCEPT ![a] = evidence]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, ownerOf, ownerGeneration,
         staleOwners, leaseStale, effectMayHaveHappened, invokeCount,
         reconciliationEvidence
       >>

CommitSynchronousResult(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "CONSUMED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ providerEntered[a] = TRUE
    /\ pendingCommitEvidence[a] = NoEvidence
    /\ reconciliationEvidence[a] = NoEvidence
    /\ attemptState' = [attemptState EXCEPT ![a] = "COMMITTED"]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, providerEntered, effectMayHaveHappened, invokeCount,
         pendingCommitEvidence, reconciliationEvidence
       >>

CommitPreparedEvidence(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "CONSUMED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ pendingCommitEvidence[a] # NoEvidence
    /\ reconciliationEvidence[a] = NoEvidence
    /\ attemptState' = [attemptState EXCEPT ![a] = "COMMITTED"]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ pendingCommitEvidence' =
         [pendingCommitEvidence EXCEPT ![a] = NoEvidence]
    /\ reconciliationEvidence' =
         [reconciliationEvidence EXCEPT
             ![a] = pendingCommitEvidence[a]]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, providerEntered, effectMayHaveHappened, invokeCount
       >>

\* The effect callback was provably never entered, so release is safe without
\* provider reconciliation evidence.
ReleaseBeforeProviderEntry(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ providerEntered[a] = FALSE
    /\ pendingCommitEvidence[a] = NoEvidence
    /\ reconciliationEvidence[a] = NoEvidence
    /\ attemptState' = [attemptState EXCEPT ![a] = "RELEASED"]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ effectMayHaveHappened' =
         [effectMayHaveHappened EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, providerEntered, invokeCount, pendingCommitEvidence,
         reconciliationEvidence
       >>

\* NOT_COMMITTED and ESCALATED terminalize the attempt first. A successful
\* NOT_COMMITTED reconciliation then releases AEB in a separate transition;
\* ESCALATED deliberately leaves authority RESERVED and non-replayable.
ReconcileNonCommittedEvidence(a, presentedOwner, evidence) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ presentedOwner = ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ pendingCommitEvidence[a] = NoEvidence
    /\ EvidenceAuthenticated(evidence)
    /\ EvidenceAttempt(evidence) = a
    /\ EvidenceRequest(evidence) = requestOf[a]
    /\ EvidenceOutcome(evidence) # "COMMITTED"
    /\ LET outcome == EvidenceOutcome(evidence)
           terminal == OutcomeState(outcome)
       IN /\ attemptState' =
                [attemptState EXCEPT ![a] = terminal]
          /\ providerEntered' =
                [providerEntered EXCEPT
                    ![a] = IF outcome = "NOT_COMMITTED"
                           THEN @
                           ELSE TRUE]
          /\ effectMayHaveHappened' =
                [effectMayHaveHappened EXCEPT
                    ![a] = outcome # "NOT_COMMITTED"]
          /\ reconciliationEvidence' =
                [reconciliationEvidence EXCEPT ![a] = evidence]
    /\ leaseStale' = [leaseStale EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<
         allocated, requestOf, aebState, ownerOf, ownerGeneration,
         staleOwners, invokeCount, pendingCommitEvidence
       >>

ReleaseAebForReleased(a) ==
    /\ a \in allocated
    /\ attemptState[a] = "RELEASED"
    /\ aebState[requestOf[a]] = "RESERVED"
    /\ aebState' =
         [aebState EXCEPT ![requestOf[a]] = "AVAILABLE"]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, ownerOf, ownerGeneration,
         staleOwners, leaseStale, providerEntered, effectMayHaveHappened,
         invokeCount, pendingCommitEvidence, reconciliationEvidence
       >>

\* -----------------------------------------------------------------------
\* Adversarial/refusal actions. Each is deliberately a no-op, matching the
\* existing formal convention for reachable-but-inert denied operations.
\* -----------------------------------------------------------------------

DuplicateAttemptOrRequest(a, request, owner) ==
    /\ a \in allocated
       \/ \E existing \in allocated : requestOf[existing] = request
    /\ UNCHANGED vars

WrongOwnerCASAttempt(a, presentedOwner) ==
    /\ a \in allocated
    /\ presentedOwner \in Owners
    /\ presentedOwner # ownerOf[a]
    /\ presentedOwner \notin staleOwners[a]
    /\ UNCHANGED vars

StaleOwnerCASAttempt(a, presentedOwner) ==
    /\ a \in allocated
    /\ presentedOwner \in staleOwners[a]
    /\ UNCHANGED vars

InvalidReconciliationAttempt(a, presentedOwner, evidence) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ presentedOwner = ownerOf[a]
    /\ ~(
         /\ EvidenceAuthenticated(evidence)
         /\ EvidenceAttempt(evidence) = a
         /\ EvidenceRequest(evidence) = requestOf[a]
       )
    /\ UNCHANGED vars

TerminalReopenAttempt(a, presentedOwner) ==
    /\ a \in allocated
    /\ attemptState[a] \in TerminalStates
    /\ presentedOwner = ownerOf[a]
    /\ UNCHANGED vars

DeniedRecoveryAttempt(a) ==
    /\ a \in allocated
    /\ attemptState[a] \notin TerminalStates
    /\ UNCHANGED vars

DeniedLiveLeaseRecoveryAttempt(a) ==
    /\ a \in allocated
    /\ attemptState[a] \notin TerminalStates
    /\ ~leaseStale[a]
    /\ UNCHANGED vars

\* -----------------------------------------------------------------------
\* Next-state relation
\* -----------------------------------------------------------------------

Next ==
    \/ \E request \in Requests : ReserveAeb(request)
    \/ \E request \in Requests : ReleaseUnboundAeb(request)
    \/ \E a \in AttemptIds, request \in Requests, owner \in Owners :
         Reserve(a, request, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         BeginInvocation(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         EnterProvider(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         FreezeIndeterminate(a, owner)
    \/ \E a \in AttemptIds : ExpireLease(a)
    \/ \E a \in AttemptIds, owner \in Owners :
         HeartbeatLease(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         RecoverCustody(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         ConsumeAebAfterProvider(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners, evidence \in Evidence :
         PrepareCommittedEvidence(a, owner, evidence)
    \/ \E a \in AttemptIds, owner \in Owners :
         CommitSynchronousResult(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         CommitPreparedEvidence(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         ReleaseBeforeProviderEntry(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners, evidence \in Evidence :
         ReconcileNonCommittedEvidence(a, owner, evidence)
    \/ \E a \in AttemptIds : ReleaseAebForReleased(a)
    \* adversarial no-ops
    \/ \E a \in AttemptIds, request \in Requests, owner \in Owners :
         DuplicateAttemptOrRequest(a, request, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         WrongOwnerCASAttempt(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners :
         StaleOwnerCASAttempt(a, owner)
    \/ \E a \in AttemptIds, owner \in Owners, evidence \in Evidence :
         InvalidReconciliationAttempt(a, owner, evidence)
    \/ \E a \in AttemptIds, owner \in Owners :
         TerminalReopenAttempt(a, owner)
    \/ \E a \in AttemptIds : DeniedRecoveryAttempt(a)
    \/ \E a \in AttemptIds : DeniedLiveLeaseRecoveryAttempt(a)

Spec == Init /\ [][Next]_vars

\* Every variable domain is finite. This explicit constraint records the
\* bounded recovery depth used by TLC.
BoundedExploration ==
    \A a \in AttemptIds :
        ownerGeneration[a] <= Cardinality(Owners) - 1

\* -----------------------------------------------------------------------
\* Theorems stated for documentation; TLC checks the configured finite model.
\* -----------------------------------------------------------------------

THEOREM Spec => []TypeInvariant
THEOREM Spec => []DormantSlotsClean
THEOREM Spec => []UniqueAttemptRequestBinding
THEOREM Spec => []StaleOwnerExcluded
THEOREM Spec => []LifecycleConsistency
THEOREM Spec => []InvokeAtMostOnce
THEOREM Spec => []UncertainAttemptBlocksReplay
THEOREM Spec => []AuthenticatedExactAttemptReconciliation
THEOREM Spec => []PendingCommitEvidenceSound
THEOREM Spec => []TerminalOutcomeConsistency
THEOREM Spec => []AebAttemptCoupling
THEOREM Spec => []CommittedRequiresAebConsumed
THEOREM Spec => []ProviderInvocationRequiresAebAuthority
THEOREM Spec => []ConsumedAebHasAttempt
THEOREM Spec => AttemptAllocationAndBindingStable
THEOREM Spec => AttemptReservationRequiresAebReserved
THEOREM Spec => OwnerRotationFencesPriorOwner
THEOREM Spec => RecoveryCannotTakeLiveLease
THEOREM Spec => InvocationCountMonotonic
THEOREM Spec => NoBlindReplayWhileUncertain
THEOREM Spec => EffectUncertaintyOnlyClearsToReleased
THEOREM Spec => TerminalStateIrreversibility
THEOREM Spec => ReconciliationStartsIndeterminate
THEOREM Spec => ReconciliationEvidenceImmutable
THEOREM Spec => AebConsumptionAfterInvocation
THEOREM Spec => AebConsumedNeverReopens
THEOREM Spec => AebReleaseCoupledToReleasedAttempt

=============================================================================
