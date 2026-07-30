---------------- MODULE ep_bounded_execution_program_v1 ----------------
\* EP-BOUNDED-EXECUTION-PROGRAM-v1 finite control model.
\*
\* The configured program is a closed three-node DAG. Admission reserves one
\* occurrence and every named budget dimension atomically. Provider entry moves
\* all of those charges from reserved to consumed. Release is possible only
\* before provider entry and restores every reservation; INDETERMINATE keeps the
\* occurrence and all charges consumed and cannot satisfy a dependency.
\*
\* Supersession abstracts canonical signature verification into
\* SignatureValid(program) and exact predecessor-digest binding into
\* Supersedes(program). Only a newly signed, predecessor-bound version may
\* become active. The predecessor may have invoking, indeterminate, or terminal
\* work, but no RESERVED work. No budget, occurrence, or terminal result is
\* carried into the successor.
\*
\* Every reserved occurrence also seals a deterministic AdmissionSnapshot
\* execution_program resource over tenant, program digest, node, occurrence,
\* and expiry. That binding is immutable: it cannot be stripped or relinked,
\* and explicit ordinary-path probes must stutter on a linked admission.
\*
\* Program registration also atomically fences the modeled
\* <<tenant, authorization_digest>> key. A pre-existing unconsumed ordinary
\* reservation blocks registration. Once registration owns the key, an
\* ordinary reserve using that authorization must stutter as program_required.
\*
\* Program SUSPENDED, REVOKED, and expiry transitions atomically release all
\* pre-entry reservations while leaving post-entry occurrence state and
\* consumed budget untouched. Admission expiry never exceeds program expiry.
\* Supersession requires an opaque verification-context identity distinct from
\* the predecessor context, and each program is bounded by a configured total
\* occurrence count in addition to its per-node ceilings.
\*
\* TLC checks this configured finite state graph. It does not prove signature
\* cryptography, canonicalization, storage linearizability or durability,
\* provider truth, complete mediation, or refinement to the TypeScript runtime.

EXTENDS Naturals, FiniteSets

CONSTANTS
    POriginal, PSignedSuccessor, PUnsignedSuccessor,
    NInspect, NRemediate, NVerify,
    Attempts, RiskPoints,
    Occurrence1, Occurrence2, Occurrence3, Occurrence4,
    TenantA, ExpiryA, ExpiryB,
    AuthorizationDigestA,
    NoProgram, NoNode, NoBinding

Programs == {POriginal, PSignedSuccessor, PUnsignedSuccessor}
Nodes == {NInspect, NRemediate, NVerify}
BudgetDimensions == {Attempts, RiskPoints}
Occurrences == {Occurrence1, Occurrence2, Occurrence3, Occurrence4}
Expiries == {ExpiryA, ExpiryB}

ProgramStatuses ==
    {"UNREGISTERED", "ACTIVE", "SUSPENDED", "REVOKED", "SUPERSEDED"}
ProgramHeadStatuses == {"ACTIVE", "SUSPENDED", "REVOKED"}
ProgramTimeStates == {"BEFORE_EXPIRY", "EXPIRED"}
OccurrenceStates ==
    {"UNUSED", "RESERVED", "RELEASED", "INVOKING", "INDETERMINATE",
     "COMMITTED", "PROVEN_NOT_COMMITTED"}
TerminalOutcomes == {"COMMITTED", "PROVEN_NOT_COMMITTED"}
ConsumedStates ==
    {"INVOKING", "INDETERMINATE", "COMMITTED", "PROVEN_NOT_COMMITTED"}
CountedOccurrenceStates == {"RESERVED"} \union ConsumedStates
ClosedOccurrenceStates == TerminalOutcomes \union {"RELEASED"}
OrdinaryAuthorizationStates == {"NONE", "RESERVED", "RELEASED", "CONSUMED"}

MaxBudget == 4

ProgramVersion(p) ==
    CASE p = POriginal -> 1
      [] p \in {PSignedSuccessor, PUnsignedSuccessor} -> 2

Supersedes(p) ==
    CASE p = POriginal -> NoProgram
      [] p \in {PSignedSuccessor, PUnsignedSuccessor} -> POriginal

SignatureValid(p) == p \in {POriginal, PSignedSuccessor}

ProgramAuthorizationDigest(p) == AuthorizationDigestA
AuthorizationFenceKey == <<TenantA, AuthorizationDigestA>>

Predecessors(n) ==
    CASE n = NInspect -> {}
      [] n = NRemediate -> {NInspect}
      [] n = NVerify -> {NRemediate}

NodeRank(n) ==
    CASE n = NInspect -> 0
      [] n = NRemediate -> 1
      [] n = NVerify -> 2

AcceptedDependencyOutcomes(n, predecessor) ==
    CASE n = NRemediate /\ predecessor = NInspect -> {"COMMITTED"}
      [] n = NVerify /\ predecessor = NRemediate -> TerminalOutcomes
      [] OTHER -> {}

OccurrenceCeiling(n) ==
    CASE n = NInspect -> 2
      [] n \in {NRemediate, NVerify} -> 1

TotalOccurrenceLimit ==
    OccurrenceCeiling(NInspect)
      + OccurrenceCeiling(NRemediate)
      + OccurrenceCeiling(NVerify)

BudgetLimit(p, dimension) ==
    CASE p = POriginal /\ dimension = Attempts -> 3
      [] p = POriginal /\ dimension = RiskPoints -> 4
      [] p = PSignedSuccessor /\ dimension = Attempts -> 2
      [] p = PSignedSuccessor /\ dimension = RiskPoints -> 3
      [] p = PUnsignedSuccessor -> 2

Charge(n, dimension) ==
    CASE n = NInspect -> 1
      [] n = NRemediate /\ dimension = Attempts -> 1
      [] n = NRemediate /\ dimension = RiskPoints -> 2
      [] n = NVerify -> 1
      [] OTHER -> 0

AdmissionExpiry(o) ==
    IF o \in {Occurrence1, Occurrence2} THEN ExpiryA ELSE ExpiryB

AlternateExpiry(o) ==
    IF AdmissionExpiry(o) = ExpiryA THEN ExpiryB ELSE ExpiryA

ProgramExpiry(p) == ExpiryB

ExpiryRank(expiry) ==
    CASE expiry = ExpiryA -> 1
      [] expiry = ExpiryB -> 2

CandidateAdmissionBinding(p, n, o, expiry) ==
    [tenant |-> TenantA,
     program_digest |-> p,
     node |-> n,
     occurrence |-> o,
     expiry |-> expiry]

ExecutionProgramAdmissionBinding(p, n, o) ==
    CandidateAdmissionBinding(p, n, o, AdmissionExpiry(o))

AdmissionBindings ==
    {CandidateAdmissionBinding(p, n, o, expiry) :
        p \in Programs, n \in Nodes, o \in Occurrences, expiry \in Expiries}

VARIABLES
    programStatus,
    headProgram,
    supersededBy,
    budgetReserved,
    budgetConsumed,
    occurrenceState,
    occurrenceProgram,
    occurrenceNode,
    admissionBinding,
    authorizationOwner,
    ordinaryAuthorizationState,
    programTime

vars ==
    <<programStatus, headProgram, supersededBy,
      budgetReserved, budgetConsumed,
      occurrenceState, occurrenceProgram, occurrenceNode, admissionBinding,
      authorizationOwner, ordinaryAuthorizationState, programTime>>

CurrentProgram(p) ==
    /\ p \in Programs
    /\ headProgram = p
    /\ programStatus[p] = "ACTIVE"
    /\ programTime[p] = "BEFORE_EXPIRY"

OccurrencesFor(p, n, states) ==
    {o \in Occurrences :
        occurrenceProgram[o] = p
        /\ occurrenceNode[o] = n
        /\ occurrenceState[o] \in states}

OccurrenceUseCount(p, n) ==
    Cardinality(OccurrencesFor(p, n, CountedOccurrenceStates))

TotalOccurrenceCount(p) ==
    Cardinality({o \in Occurrences : occurrenceProgram[o] = p})

DependencySatisfied(p, n, predecessor) ==
    \E o \in Occurrences :
        /\ occurrenceProgram[o] = p
        /\ occurrenceNode[o] = predecessor
        /\ occurrenceState[o] \in AcceptedDependencyOutcomes(n, predecessor)

NodeReachable(p, n) ==
    \A predecessor \in Predecessors(n) :
        DependencySatisfied(p, n, predecessor)

BudgetCanReserve(p, n) ==
    \A dimension \in BudgetDimensions :
        budgetReserved[p][dimension]
          + budgetConsumed[p][dimension]
          + Charge(n, dimension)
        <= BudgetLimit(p, dimension)

NoReservedWork(p) ==
    ~\E o \in Occurrences :
        occurrenceProgram[o] = p /\ occurrenceState[o] = "RESERVED"

ReleaseReservedOccurrenceState(p) ==
    [o \in Occurrences |->
      IF occurrenceProgram[o] = p /\ occurrenceState[o] = "RESERVED"
      THEN "RELEASED"
      ELSE occurrenceState[o]]

ChargeCount(p, dimension, states, amount) ==
    Cardinality(
        {o \in Occurrences :
            occurrenceProgram[o] = p
            /\ occurrenceState[o] \in states
            /\ Charge(occurrenceNode[o], dimension) = amount})

ExpectedCharge(p, dimension, states) ==
    ChargeCount(p, dimension, states, 1)
      + (2 * ChargeCount(p, dimension, states, 2))

\* ---------------------------------------------------------------------
\* State invariants
\* ---------------------------------------------------------------------

TypeInvariant ==
    /\ Cardinality(Programs) = 3
    /\ Cardinality(Nodes) = 3
    /\ Cardinality(BudgetDimensions) = 2
    /\ Cardinality(Occurrences) = 4
    /\ Cardinality(Occurrences) = TotalOccurrenceLimit
    /\ Cardinality(Expiries) = 2
    /\ NoProgram \notin Programs
    /\ NoNode \notin Nodes
    /\ NoBinding \notin AdmissionBindings
    /\ programStatus \in [Programs -> ProgramStatuses]
    /\ headProgram \in Programs \union {NoProgram}
    /\ supersededBy \in [Programs -> Programs \union {NoProgram}]
    /\ budgetReserved \in [Programs -> [BudgetDimensions -> 0..MaxBudget]]
    /\ budgetConsumed \in [Programs -> [BudgetDimensions -> 0..MaxBudget]]
    /\ occurrenceState \in [Occurrences -> OccurrenceStates]
    /\ occurrenceProgram \in [Occurrences -> Programs \union {NoProgram}]
    /\ occurrenceNode \in [Occurrences -> Nodes \union {NoNode}]
    /\ admissionBinding \in [Occurrences -> AdmissionBindings \union {NoBinding}]
    /\ authorizationOwner \in Programs \union {NoProgram}
    /\ ordinaryAuthorizationState \in OrdinaryAuthorizationStates
    /\ programTime \in [Programs -> ProgramTimeStates]

ClosedDAG ==
    /\ Predecessors(NInspect) = {}
    /\ Predecessors(NRemediate) = {NInspect}
    /\ Predecessors(NVerify) = {NRemediate}
    /\ \A n \in Nodes : Predecessors(n) \subseteq Nodes
    /\ \A n \in Nodes :
         \A predecessor \in Predecessors(n) :
             NodeRank(predecessor) < NodeRank(n)

SingleActiveHead ==
    IF headProgram = NoProgram
    THEN \A p \in Programs : programStatus[p] \notin ProgramHeadStatuses
    ELSE /\ programStatus[headProgram] \in ProgramHeadStatuses
         /\ \A p \in Programs :
              programStatus[p] \in ProgramHeadStatuses => p = headProgram

OnlySignedProgramsCanBeActive ==
    \A p \in Programs :
      programStatus[p] \in ProgramHeadStatuses => SignatureValid(p)

AuthorizationFenceConsistent ==
    /\ (authorizationOwner = NoProgram) = (headProgram = NoProgram)
    /\ authorizationOwner \in Programs =>
         /\ programStatus[authorizationOwner] \in ProgramHeadStatuses
         /\ headProgram = authorizationOwner
         /\ ProgramAuthorizationDigest(authorizationOwner)
              = AuthorizationDigestA
         /\ ordinaryAuthorizationState # "RESERVED"

SupersessionChainValid ==
    \A p \in Programs :
        programStatus[p] = "SUPERSEDED" =>
          /\ supersededBy[p] \in Programs
          /\ SignatureValid(supersededBy[p])
          /\ Supersedes(supersededBy[p]) = p
          /\ ProgramVersion(supersededBy[p]) = ProgramVersion(p) + 1

UnregisteredProgramsAreFresh ==
    \A p \in Programs :
        programStatus[p] = "UNREGISTERED" =>
          /\ supersededBy[p] = NoProgram
          /\ \A dimension \in BudgetDimensions :
               /\ budgetReserved[p][dimension] = 0
               /\ budgetConsumed[p][dimension] = 0
          /\ ~\E o \in Occurrences : occurrenceProgram[o] = p

OccurrenceBindingsComplete ==
    \A o \in Occurrences :
        IF occurrenceState[o] = "UNUSED"
        THEN /\ occurrenceProgram[o] = NoProgram
             /\ occurrenceNode[o] = NoNode
        ELSE /\ occurrenceProgram[o] \in Programs
             /\ occurrenceNode[o] \in Nodes

ProgramAdmissionBindingExact ==
    \A o \in Occurrences :
        IF occurrenceState[o] = "UNUSED"
        THEN admissionBinding[o] = NoBinding
        ELSE admissionBinding[o]
               = ExecutionProgramAdmissionBinding(
                   occurrenceProgram[o], occurrenceNode[o], o)

OccurrenceCeilingsHold ==
    \A p \in Programs :
        \A n \in Nodes : OccurrenceUseCount(p, n) <= OccurrenceCeiling(n)

TotalOccurrencesBounded ==
    \A p \in Programs : TotalOccurrenceCount(p) <= TotalOccurrenceLimit

AdmissionExpiryWithinProgramExpiry ==
    \A o \in Occurrences :
      occurrenceState[o] # "UNUSED" =>
        ExpiryRank(admissionBinding[o].expiry)
          <= ExpiryRank(ProgramExpiry(occurrenceProgram[o]))

BudgetConservation ==
    \A p \in Programs :
        \A dimension \in BudgetDimensions :
          /\ budgetReserved[p][dimension]
               + budgetConsumed[p][dimension] <= BudgetLimit(p, dimension)
          /\ budgetReserved[p][dimension] >= 0
          /\ budgetConsumed[p][dimension] >= 0

BudgetAccountingExact ==
    \A p \in Programs :
        \A dimension \in BudgetDimensions :
          /\ budgetReserved[p][dimension]
               = ExpectedCharge(p, dimension, {"RESERVED"})
          /\ budgetConsumed[p][dimension]
               = ExpectedCharge(p, dimension, ConsumedStates)

AdmittedNodesHaveTerminalDependencies ==
    \A o \in Occurrences :
        occurrenceState[o] \in CountedOccurrenceStates =>
          NodeReachable(occurrenceProgram[o], occurrenceNode[o])

IndeterminateNeverSatisfiesDependency ==
    \A p \in Programs :
      \A n \in Nodes :
        \A predecessor \in Predecessors(n) :
          ( /\ \E o \in Occurrences :
                   occurrenceProgram[o] = p
                   /\ occurrenceNode[o] = predecessor
                   /\ occurrenceState[o] = "INDETERMINATE"
            /\ ~DependencySatisfied(p, n, predecessor) )
          => ~NodeReachable(p, n)

SupersededProgramsHaveNoReservedWork ==
    \A p \in Programs : programStatus[p] = "SUPERSEDED" => NoReservedWork(p)

UnavailableProgramsHaveNoReservedWork ==
    \A p \in Programs :
      (programStatus[p] \in {"SUSPENDED", "REVOKED"}
        \/ programTime[p] = "EXPIRED") => NoReservedWork(p)

\* ---------------------------------------------------------------------
\* Initial state
\* ---------------------------------------------------------------------

Init ==
    /\ programStatus = [p \in Programs |-> "UNREGISTERED"]
    /\ headProgram = NoProgram
    /\ supersededBy = [p \in Programs |-> NoProgram]
    /\ budgetReserved =
         [p \in Programs |-> [dimension \in BudgetDimensions |-> 0]]
    /\ budgetConsumed =
         [p \in Programs |-> [dimension \in BudgetDimensions |-> 0]]
    /\ occurrenceState = [o \in Occurrences |-> "UNUSED"]
    /\ occurrenceProgram = [o \in Occurrences |-> NoProgram]
    /\ occurrenceNode = [o \in Occurrences |-> NoNode]
    /\ admissionBinding = [o \in Occurrences |-> NoBinding]
    /\ authorizationOwner = NoProgram
    /\ ordinaryAuthorizationState = "NONE"
    /\ programTime = [p \in Programs |-> "BEFORE_EXPIRY"]

\* ---------------------------------------------------------------------
\* Reserve, consume, release, outcome, and supersession transitions
\* ---------------------------------------------------------------------

ReserveOrdinaryAuthorization ==
    /\ authorizationOwner = NoProgram
    /\ ordinaryAuthorizationState = "NONE"
    /\ ordinaryAuthorizationState' = "RESERVED"
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, programTime>>

ReleaseOrdinaryAuthorization ==
    /\ ordinaryAuthorizationState = "RESERVED"
    /\ authorizationOwner = NoProgram
    /\ ordinaryAuthorizationState' = "RELEASED"
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, programTime>>

ConsumeOrdinaryAuthorization ==
    /\ ordinaryAuthorizationState = "RESERVED"
    /\ authorizationOwner = NoProgram
    /\ ordinaryAuthorizationState' = "CONSUMED"
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, programTime>>

RegisterOriginalProgram ==
    /\ headProgram = NoProgram
    /\ authorizationOwner = NoProgram
    /\ programStatus[POriginal] = "UNREGISTERED"
    /\ SignatureValid(POriginal)
    /\ ProgramAuthorizationDigest(POriginal) = AuthorizationDigestA
    /\ ordinaryAuthorizationState # "RESERVED"
    /\ programStatus' = [programStatus EXCEPT ![POriginal] = "ACTIVE"]
    /\ headProgram' = POriginal
    /\ authorizationOwner' = POriginal
    /\ UNCHANGED
         <<supersededBy, budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, ordinaryAuthorizationState, programTime>>

OrdinaryReservationBlocksProgramRegistration ==
    ordinaryAuthorizationState = "RESERVED" =>
      ~ENABLED RegisterOriginalProgram

FencedAuthorizationBlocksOrdinaryReserve ==
    authorizationOwner \in Programs =>
      ~ENABLED ReserveOrdinaryAuthorization

ReserveOccurrence(p, n, o) ==
    /\ CurrentProgram(p)
    /\ n \in Nodes
    /\ o \in Occurrences
    /\ occurrenceState[o] = "UNUSED"
    /\ NodeReachable(p, n)
    /\ OccurrenceUseCount(p, n) < OccurrenceCeiling(n)
    /\ BudgetCanReserve(p, n)
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = "RESERVED"]
    /\ occurrenceProgram' = [occurrenceProgram EXCEPT ![o] = p]
    /\ occurrenceNode' = [occurrenceNode EXCEPT ![o] = n]
    /\ admissionBinding' =
         [admissionBinding EXCEPT
            ![o] = ExecutionProgramAdmissionBinding(p, n, o)]
    /\ budgetReserved' =
         [budgetReserved EXCEPT
            ![p] =
              [dimension \in BudgetDimensions |->
                 budgetReserved[p][dimension] + Charge(n, dimension)]]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy, budgetConsumed,
           authorizationOwner, ordinaryAuthorizationState, programTime>>

ReserveRoot(p, o) == ReserveOccurrence(p, NInspect, o)
ReserveDependent(p, o) == ReserveOccurrence(p, NRemediate, o)
ReserveLeaf(p, o) == ReserveOccurrence(p, NVerify, o)

\* Coverage witnesses make non-root DAG reachability non-vacuous without
\* adding an observation variable to the protocol state.
WitnessDependentReachable(p) ==
    /\ CurrentProgram(p)
    /\ NodeReachable(p, NRemediate)
    /\ UNCHANGED vars

WitnessLeafReachable(p) ==
    /\ CurrentProgram(p)
    /\ NodeReachable(p, NVerify)
    /\ UNCHANGED vars

ReleaseOccurrence(o) ==
    /\ o \in Occurrences
    /\ occurrenceState[o] = "RESERVED"
    /\ CurrentProgram(occurrenceProgram[o])
    /\ LET p == occurrenceProgram[o]
           n == occurrenceNode[o]
       IN budgetReserved' =
            [budgetReserved EXCEPT
               ![p] =
                 [dimension \in BudgetDimensions |->
                    budgetReserved[p][dimension] - Charge(n, dimension)]]
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = "RELEASED"]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy, budgetConsumed,
           occurrenceProgram, occurrenceNode, admissionBinding,
           authorizationOwner, ordinaryAuthorizationState, programTime>>

\* beginInvocation is the single atomic reserved-to-consumed linearization.
BeginInvocation(o) ==
    /\ o \in Occurrences
    /\ occurrenceState[o] = "RESERVED"
    /\ CurrentProgram(occurrenceProgram[o])
    /\ LET p == occurrenceProgram[o]
           n == occurrenceNode[o]
       IN /\ budgetReserved' =
                [budgetReserved EXCEPT
                   ![p] =
                     [dimension \in BudgetDimensions |->
                        budgetReserved[p][dimension] - Charge(n, dimension)]]
          /\ budgetConsumed' =
                [budgetConsumed EXCEPT
                   ![p] =
                     [dimension \in BudgetDimensions |->
                        budgetConsumed[p][dimension] + Charge(n, dimension)]]
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = "INVOKING"]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           occurrenceProgram, occurrenceNode, admissionBinding,
           authorizationOwner, ordinaryAuthorizationState, programTime>>

MarkIndeterminate(o) ==
    /\ o \in Occurrences
    /\ occurrenceState[o] = "INVOKING"
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = "INDETERMINATE"]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, ordinaryAuthorizationState,
           programTime>>

RecordTerminalOutcome(o, outcome) ==
    /\ o \in Occurrences
    /\ outcome \in TerminalOutcomes
    /\ occurrenceState[o] = "INVOKING"
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = outcome]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, ordinaryAuthorizationState,
           programTime>>

ReconcileActiveIndeterminate(o, outcome) ==
    /\ occurrenceState[o] = "INDETERMINATE"
    /\ CurrentProgram(occurrenceProgram[o])
    /\ outcome \in TerminalOutcomes
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = outcome]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, ordinaryAuthorizationState,
           programTime>>

ReconcileSupersededIndeterminate(o, outcome) ==
    /\ occurrenceState[o] = "INDETERMINATE"
    /\ programStatus[occurrenceProgram[o]] = "SUPERSEDED"
    /\ outcome \in TerminalOutcomes
    /\ occurrenceState' = [occurrenceState EXCEPT ![o] = outcome]
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy,
           budgetReserved, budgetConsumed, occurrenceProgram, occurrenceNode,
           admissionBinding, authorizationOwner, ordinaryAuthorizationState,
           programTime>>

DeactivateProgram(p, targetStatus) ==
    /\ CurrentProgram(p)
    /\ targetStatus \in {"SUSPENDED", "REVOKED"}
    /\ programStatus' = [programStatus EXCEPT ![p] = targetStatus]
    /\ budgetReserved' =
         [budgetReserved EXCEPT
           ![p] = [dimension \in BudgetDimensions |-> 0]]
    /\ occurrenceState' = ReleaseReservedOccurrenceState(p)
    /\ UNCHANGED
         <<headProgram, supersededBy, budgetConsumed,
           occurrenceProgram, occurrenceNode, admissionBinding,
           authorizationOwner, ordinaryAuthorizationState, programTime>>

ExpireProgram(p) ==
    /\ headProgram = p
    /\ programStatus[p] \in ProgramHeadStatuses
    /\ programTime[p] = "BEFORE_EXPIRY"
    /\ programTime' = [programTime EXCEPT ![p] = "EXPIRED"]
    /\ budgetReserved' =
         [budgetReserved EXCEPT
           ![p] = [dimension \in BudgetDimensions |-> 0]]
    /\ occurrenceState' = ReleaseReservedOccurrenceState(p)
    /\ UNCHANGED
         <<programStatus, headProgram, supersededBy, budgetConsumed,
           occurrenceProgram, occurrenceNode, admissionBinding,
           authorizationOwner, ordinaryAuthorizationState>>

SupersedeSigned(old, successor, verificationContext) ==
    /\ CurrentProgram(old)
    /\ successor \in Programs
    /\ verificationContext \in Programs
    /\ programStatus[successor] = "UNREGISTERED"
    /\ SignatureValid(successor)
    /\ Supersedes(successor) = old
    /\ ProgramVersion(successor) = ProgramVersion(old) + 1
    /\ ProgramAuthorizationDigest(successor)
         = ProgramAuthorizationDigest(old)
    /\ verificationContext = successor
    /\ verificationContext # old
    /\ authorizationOwner = old
    /\ programTime[successor] = "BEFORE_EXPIRY"
    /\ NoReservedWork(old)
    /\ \A dimension \in BudgetDimensions :
         /\ budgetReserved[successor][dimension] = 0
         /\ budgetConsumed[successor][dimension] = 0
    /\ programStatus' =
         [programStatus EXCEPT
            ![old] = "SUPERSEDED",
            ![successor] = "ACTIVE"]
    /\ headProgram' = successor
    /\ supersededBy' = [supersededBy EXCEPT ![old] = successor]
    /\ authorizationOwner' = successor
    /\ UNCHANGED
         <<budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, ordinaryAuthorizationState, programTime>>

\* ---------------------------------------------------------------------
\* Explicit refusal probes. They stutter, but TLC coverage must show that the
\* rejected conditions are reachable in the exhaustive graph.
\* ---------------------------------------------------------------------

RejectIndeterminateDependency(p, o) ==
    /\ CurrentProgram(p)
    /\ occurrenceState[o] = "UNUSED"
    /\ \E predecessorOccurrence \in Occurrences :
         /\ occurrenceProgram[predecessorOccurrence] = p
         /\ occurrenceNode[predecessorOccurrence] = NInspect
         /\ occurrenceState[predecessorOccurrence] = "INDETERMINATE"
    /\ ~NodeReachable(p, NRemediate)
    /\ OccurrenceUseCount(p, NRemediate) < OccurrenceCeiling(NRemediate)
    /\ BudgetCanReserve(p, NRemediate)
    /\ UNCHANGED vars

RejectOccurrenceCeiling(p, o) ==
    /\ CurrentProgram(p)
    /\ occurrenceState[o] = "UNUSED"
    /\ NodeReachable(p, NInspect)
    /\ OccurrenceUseCount(p, NInspect) = OccurrenceCeiling(NInspect)
    /\ BudgetCanReserve(p, NInspect)
    /\ UNCHANGED vars

RejectBudgetExhaustion(p, o) ==
    /\ CurrentProgram(p)
    /\ occurrenceState[o] = "UNUSED"
    /\ NodeReachable(p, NVerify)
    /\ OccurrenceUseCount(p, NVerify) < OccurrenceCeiling(NVerify)
    /\ ~BudgetCanReserve(p, NVerify)
    /\ UNCHANGED vars

RejectUnsignedSupersession(old, successor) ==
    /\ CurrentProgram(old)
    /\ successor \in Programs
    /\ programStatus[successor] = "UNREGISTERED"
    /\ ~SignatureValid(successor)
    /\ Supersedes(successor) = old
    /\ ProgramVersion(successor) = ProgramVersion(old) + 1
    /\ authorizationOwner = old
    /\ NoReservedWork(old)
    /\ UNCHANGED vars

RejectReusedSupersessionContext(old, successor) ==
    /\ CurrentProgram(old)
    /\ successor \in Programs
    /\ programStatus[successor] = "UNREGISTERED"
    /\ SignatureValid(successor)
    /\ Supersedes(successor) = old
    /\ ProgramVersion(successor) = ProgramVersion(old) + 1
    /\ ProgramAuthorizationDigest(successor)
         = ProgramAuthorizationDigest(old)
    /\ authorizationOwner = old
    /\ NoReservedWork(old)
    \* The attempted verification context is old, not successor.
    /\ old # successor
    /\ UNCHANGED vars

WitnessSuspendedProgram(p) ==
    /\ headProgram = p
    /\ programStatus[p] = "SUSPENDED"
    /\ UNCHANGED vars

WitnessRevokedProgram(p) ==
    /\ headProgram = p
    /\ programStatus[p] = "REVOKED"
    /\ UNCHANGED vars

WitnessExpiredProgram(p) ==
    /\ headProgram = p
    /\ programTime[p] = "EXPIRED"
    /\ UNCHANGED vars

WitnessUnavailableAfterProviderEntry(p) ==
    /\ headProgram = p
    /\ (programStatus[p] \in {"SUSPENDED", "REVOKED"}
          \/ programTime[p] = "EXPIRED")
    /\ \E o \in Occurrences :
         occurrenceProgram[o] = p /\ occurrenceState[o] \in ConsumedStates
    /\ UNCHANGED vars

RejectRegistrationWithOrdinaryReservation ==
    /\ headProgram = NoProgram
    /\ authorizationOwner = NoProgram
    /\ programStatus[POriginal] = "UNREGISTERED"
    /\ ordinaryAuthorizationState = "RESERVED"
    /\ UNCHANGED vars

RejectOrdinaryReserveAfterRegistration ==
    /\ authorizationOwner \in Programs
    /\ ProgramAuthorizationDigest(authorizationOwner) = AuthorizationDigestA
    /\ UNCHANGED vars

RejectRelinkedAdmission(o) ==
    /\ o \in Occurrences
    /\ occurrenceState[o] # "UNUSED"
    /\ admissionBinding[o] # NoBinding
    /\ CandidateAdmissionBinding(
         PUnsignedSuccessor, NVerify, o, AlternateExpiry(o))
         # admissionBinding[o]
    /\ UNCHANGED vars

RejectOrdinaryPathForLinkedAdmission(o) ==
    /\ o \in Occurrences
    /\ occurrenceState[o] = "RESERVED"
    /\ admissionBinding[o]
         = ExecutionProgramAdmissionBinding(
             occurrenceProgram[o], occurrenceNode[o], o)
    /\ UNCHANGED vars

Next ==
    \/ ReserveOrdinaryAuthorization
    \/ ReleaseOrdinaryAuthorization
    \/ ConsumeOrdinaryAuthorization
    \/ RegisterOriginalProgram
    \/ \E p \in Programs, o \in Occurrences : ReserveRoot(p, o)
    \/ \E p \in Programs, o \in Occurrences : ReserveDependent(p, o)
    \/ \E p \in Programs, o \in Occurrences : ReserveLeaf(p, o)
    \/ \E p \in Programs : WitnessDependentReachable(p)
    \/ \E p \in Programs : WitnessLeafReachable(p)
    \/ \E o \in Occurrences : ReleaseOccurrence(o)
    \/ \E o \in Occurrences : BeginInvocation(o)
    \/ \E o \in Occurrences : MarkIndeterminate(o)
    \/ \E o \in Occurrences, outcome \in TerminalOutcomes :
         RecordTerminalOutcome(o, outcome)
    \/ \E o \in Occurrences, outcome \in TerminalOutcomes :
         ReconcileActiveIndeterminate(o, outcome)
    \/ \E o \in Occurrences, outcome \in TerminalOutcomes :
         ReconcileSupersededIndeterminate(o, outcome)
    \/ \E p \in Programs, targetStatus \in {"SUSPENDED", "REVOKED"} :
         DeactivateProgram(p, targetStatus)
    \/ \E p \in Programs : ExpireProgram(p)
    \/ \E old \in Programs, successor \in Programs,
          verificationContext \in Programs :
         SupersedeSigned(old, successor, verificationContext)
    \/ \E p \in Programs, o \in Occurrences :
         RejectIndeterminateDependency(p, o)
    \/ \E p \in Programs, o \in Occurrences :
         RejectOccurrenceCeiling(p, o)
    \/ \E p \in Programs, o \in Occurrences :
         RejectBudgetExhaustion(p, o)
    \/ \E old \in Programs, successor \in Programs :
         RejectUnsignedSupersession(old, successor)
    \/ \E old \in Programs, successor \in Programs :
         RejectReusedSupersessionContext(old, successor)
    \/ \E p \in Programs : WitnessSuspendedProgram(p)
    \/ \E p \in Programs : WitnessRevokedProgram(p)
    \/ \E p \in Programs : WitnessExpiredProgram(p)
    \/ \E p \in Programs : WitnessUnavailableAfterProviderEntry(p)
    \/ RejectRegistrationWithOrdinaryReservation
    \/ RejectOrdinaryReserveAfterRegistration
    \/ \E o \in Occurrences : RejectRelinkedAdmission(o)
    \/ \E o \in Occurrences : RejectOrdinaryPathForLinkedAdmission(o)

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------
\* Transition properties
\* ---------------------------------------------------------------------

ReserveChargesEveryDimension ==
    [][\A p \in Programs, n \in Nodes, o \in Occurrences :
         ReserveOccurrence(p, n, o) =>
           \A dimension \in BudgetDimensions :
             budgetReserved'[p][dimension]
               = budgetReserved[p][dimension] + Charge(n, dimension)]_vars

BeginConsumesEveryDimension ==
    [][\A o \in Occurrences :
         BeginInvocation(o) =>
           LET p == occurrenceProgram[o]
               n == occurrenceNode[o]
           IN \A dimension \in BudgetDimensions :
                /\ budgetReserved'[p][dimension]
                     = budgetReserved[p][dimension] - Charge(n, dimension)
                /\ budgetConsumed'[p][dimension]
                     = budgetConsumed[p][dimension] + Charge(n, dimension)]_vars

ReleaseRestoresEveryDimension ==
    [][\A o \in Occurrences :
         ReleaseOccurrence(o) =>
           LET p == occurrenceProgram[o]
               n == occurrenceNode[o]
           IN \A dimension \in BudgetDimensions :
                /\ budgetReserved'[p][dimension]
                     = budgetReserved[p][dimension] - Charge(n, dimension)
                /\ budgetConsumed'[p][dimension]
                     = budgetConsumed[p][dimension]]_vars

ConsumedBudgetNeverRefunds ==
    [][\A p \in Programs :
         \A dimension \in BudgetDimensions :
           budgetConsumed'[p][dimension] >= budgetConsumed[p][dimension]]_vars

ClosedOccurrencesNeverReopen ==
    [][\A o \in Occurrences :
         occurrenceState[o] \in ClosedOccurrenceStates =>
           occurrenceState'[o] = occurrenceState[o]]_vars

AdmissionBindingNeverRelinks ==
    [][\A o \in Occurrences :
         admissionBinding[o] # NoBinding =>
           admissionBinding'[o] = admissionBinding[o]]_vars

BeginRequiresAvailableProgram ==
    [][\A o \in Occurrences :
         BeginInvocation(o) =>
           /\ programStatus[occurrenceProgram[o]] = "ACTIVE"
           /\ programTime[occurrenceProgram[o]] = "BEFORE_EXPIRY"]_vars

DeactivationReleasesPreEntryPreservesPostEntry ==
    [][\A p \in Programs, targetStatus \in {"SUSPENDED", "REVOKED"} :
         DeactivateProgram(p, targetStatus) =>
           /\ \A dimension \in BudgetDimensions :
                /\ budgetReserved'[p][dimension] = 0
                /\ budgetConsumed'[p][dimension]
                     = budgetConsumed[p][dimension]
           /\ \A o \in Occurrences :
                /\ (occurrenceProgram[o] = p
                      /\ occurrenceState[o] = "RESERVED") =>
                     occurrenceState'[o] = "RELEASED"
                /\ (occurrenceProgram[o] = p
                      /\ occurrenceState[o] \in ConsumedStates) =>
                     occurrenceState'[o] = occurrenceState[o]]_vars

ProgramExpiryDoesNotStrandReservations ==
    [][\A p \in Programs :
         ExpireProgram(p) =>
           /\ programTime'[p] = "EXPIRED"
           /\ \A dimension \in BudgetDimensions :
                /\ budgetReserved'[p][dimension] = 0
                /\ budgetConsumed'[p][dimension]
                     = budgetConsumed[p][dimension]
           /\ \A o \in Occurrences :
                /\ (occurrenceProgram[o] = p
                      /\ occurrenceState[o] = "RESERVED") =>
                     occurrenceState'[o] = "RELEASED"
                /\ (occurrenceProgram[o] = p
                      /\ occurrenceState[o] \in ConsumedStates) =>
                     occurrenceState'[o] = occurrenceState[o]]_vars

ProgramRegistrationFencesAuthorizationAtomically ==
    [][RegisterOriginalProgram =>
         /\ programStatus'[POriginal] = "ACTIVE"
         /\ headProgram' = POriginal
         /\ authorizationOwner' = POriginal
         /\ AuthorizationFenceKey = <<TenantA, AuthorizationDigestA>>]_vars

SignedSupersessionStartsFresh ==
    [][\A old \in Programs, successor \in Programs,
          verificationContext \in Programs :
         SupersedeSigned(old, successor, verificationContext) =>
           /\ headProgram' = successor
           /\ programStatus'[old] = "SUPERSEDED"
           /\ programStatus'[successor] = "ACTIVE"
           /\ SignatureValid(successor)
           /\ Supersedes(successor) = old
           /\ verificationContext = successor
           /\ verificationContext # old
           /\ authorizationOwner' = successor
           /\ programTime'[successor] = "BEFORE_EXPIRY"
           /\ \A dimension \in BudgetDimensions :
                /\ budgetReserved'[successor][dimension] = 0
                /\ budgetConsumed'[successor][dimension] = 0]_vars

THEOREM Spec => []TypeInvariant
THEOREM Spec => []ClosedDAG
THEOREM Spec => []SingleActiveHead
THEOREM Spec => []OnlySignedProgramsCanBeActive
THEOREM Spec => []AuthorizationFenceConsistent
THEOREM Spec => []OrdinaryReservationBlocksProgramRegistration
THEOREM Spec => []FencedAuthorizationBlocksOrdinaryReserve
THEOREM Spec => []SupersessionChainValid
THEOREM Spec => []UnregisteredProgramsAreFresh
THEOREM Spec => []OccurrenceBindingsComplete
THEOREM Spec => []ProgramAdmissionBindingExact
THEOREM Spec => []OccurrenceCeilingsHold
THEOREM Spec => []TotalOccurrencesBounded
THEOREM Spec => []AdmissionExpiryWithinProgramExpiry
THEOREM Spec => []BudgetConservation
THEOREM Spec => []BudgetAccountingExact
THEOREM Spec => []AdmittedNodesHaveTerminalDependencies
THEOREM Spec => []IndeterminateNeverSatisfiesDependency
THEOREM Spec => []SupersededProgramsHaveNoReservedWork
THEOREM Spec => []UnavailableProgramsHaveNoReservedWork
THEOREM Spec => ReserveChargesEveryDimension
THEOREM Spec => BeginConsumesEveryDimension
THEOREM Spec => ReleaseRestoresEveryDimension
THEOREM Spec => ConsumedBudgetNeverRefunds
THEOREM Spec => ClosedOccurrencesNeverReopen
THEOREM Spec => AdmissionBindingNeverRelinks
THEOREM Spec => BeginRequiresAvailableProgram
THEOREM Spec => DeactivationReleasesPreEntryPreservesPostEntry
THEOREM Spec => ProgramExpiryDoesNotStrandReservations
THEOREM Spec => ProgramRegistrationFencesAuthorizationAtomically
THEOREM Spec => SignedSupersessionStartsFresh

=============================================================================
