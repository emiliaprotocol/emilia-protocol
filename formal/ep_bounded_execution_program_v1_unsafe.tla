------------- MODULE ep_bounded_execution_program_v1_unsafe -------------
\* Deliberately weakened negative control.
\*
\* UnsafeActivateUnsigned removes only the trusted-signature requirement from
\* supersession while retaining the predecessor and version bindings. TLC MUST
\* falsify OnlySignedProgramsCanBeActive. This is not a protocol design.

EXTENDS Naturals, FiniteSets

CONSTANTS
    POriginal, PSignedSuccessor, PUnsignedSuccessor,
    NInspect, NRemediate, NVerify,
    Attempts, RiskPoints,
    Occurrence1, Occurrence2, Occurrence3, Occurrence4,
    TenantA, ExpiryA, ExpiryB,
    AuthorizationDigestA,
    NoProgram, NoNode, NoBinding

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

base ==
    INSTANCE ep_bounded_execution_program_v1
      WITH POriginal <- POriginal,
           PSignedSuccessor <- PSignedSuccessor,
           PUnsignedSuccessor <- PUnsignedSuccessor,
           NInspect <- NInspect,
           NRemediate <- NRemediate,
           NVerify <- NVerify,
           Attempts <- Attempts,
           RiskPoints <- RiskPoints,
           Occurrence1 <- Occurrence1,
           Occurrence2 <- Occurrence2,
           Occurrence3 <- Occurrence3,
           Occurrence4 <- Occurrence4,
           TenantA <- TenantA,
           ExpiryA <- ExpiryA,
           ExpiryB <- ExpiryB,
           AuthorizationDigestA <- AuthorizationDigestA,
           NoProgram <- NoProgram,
           NoNode <- NoNode,
           NoBinding <- NoBinding,
           programStatus <- programStatus,
           headProgram <- headProgram,
           supersededBy <- supersededBy,
           budgetReserved <- budgetReserved,
           budgetConsumed <- budgetConsumed,
           occurrenceState <- occurrenceState,
           occurrenceProgram <- occurrenceProgram,
           occurrenceNode <- occurrenceNode,
           admissionBinding <- admissionBinding,
           authorizationOwner <- authorizationOwner,
           ordinaryAuthorizationState <- ordinaryAuthorizationState,
           programTime <- programTime

UnsafeActivateUnsigned(old, successor) ==
    /\ base!CurrentProgram(old)
    /\ successor \in base!Programs
    /\ programStatus[successor] = "UNREGISTERED"
    /\ ~base!SignatureValid(successor)
    /\ base!Supersedes(successor) = old
    /\ base!ProgramVersion(successor) = base!ProgramVersion(old) + 1
    /\ authorizationOwner = old
    /\ base!NoReservedWork(old)
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

UnsafeNext ==
    \/ base!Next
    \/ \E old \in base!Programs, successor \in base!Programs :
         UnsafeActivateUnsigned(old, successor)

Spec == base!Init /\ [][UnsafeNext]_vars

\* Aliases allow the safe and unsafe modules to share one configuration.
TypeInvariant == base!TypeInvariant
ClosedDAG == base!ClosedDAG
SingleActiveHead == base!SingleActiveHead
OnlySignedProgramsCanBeActive == base!OnlySignedProgramsCanBeActive
AuthorizationFenceConsistent == base!AuthorizationFenceConsistent
OrdinaryReservationBlocksProgramRegistration ==
    base!OrdinaryReservationBlocksProgramRegistration
FencedAuthorizationBlocksOrdinaryReserve ==
    base!FencedAuthorizationBlocksOrdinaryReserve
SupersessionChainValid == base!SupersessionChainValid
UnregisteredProgramsAreFresh == base!UnregisteredProgramsAreFresh
OccurrenceBindingsComplete == base!OccurrenceBindingsComplete
ProgramAdmissionBindingExact == base!ProgramAdmissionBindingExact
OccurrenceCeilingsHold == base!OccurrenceCeilingsHold
TotalOccurrencesBounded == base!TotalOccurrencesBounded
AdmissionExpiryWithinProgramExpiry ==
    base!AdmissionExpiryWithinProgramExpiry
BudgetConservation == base!BudgetConservation
BudgetAccountingExact == base!BudgetAccountingExact
AdmittedNodesHaveTerminalDependencies ==
    base!AdmittedNodesHaveTerminalDependencies
IndeterminateNeverSatisfiesDependency ==
    base!IndeterminateNeverSatisfiesDependency
SupersededProgramsHaveNoReservedWork ==
    base!SupersededProgramsHaveNoReservedWork
UnavailableProgramsHaveNoReservedWork ==
    base!UnavailableProgramsHaveNoReservedWork
ReserveChargesEveryDimension == base!ReserveChargesEveryDimension
BeginConsumesEveryDimension == base!BeginConsumesEveryDimension
ReleaseRestoresEveryDimension == base!ReleaseRestoresEveryDimension
ConsumedBudgetNeverRefunds == base!ConsumedBudgetNeverRefunds
ClosedOccurrencesNeverReopen == base!ClosedOccurrencesNeverReopen
AdmissionBindingNeverRelinks == base!AdmissionBindingNeverRelinks
BeginRequiresAvailableProgram == base!BeginRequiresAvailableProgram
DeactivationReleasesPreEntryPreservesPostEntry ==
    base!DeactivationReleasesPreEntryPreservesPostEntry
ProgramExpiryDoesNotStrandReservations ==
    base!ProgramExpiryDoesNotStrandReservations
ProgramRegistrationFencesAuthorizationAtomically ==
    base!ProgramRegistrationFencesAuthorizationAtomically
SignedSupersessionStartsFresh == base!SignedSupersessionStartsFresh

=============================================================================
