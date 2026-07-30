------ MODULE ep_bounded_execution_program_v1_authorization_fence_unsafe ------
\* Deliberately weakened authorization-fence negative control.
\*
\* The mutation registers POriginal while an ordinary reservation still owns
\* the same <<tenant, authorization_digest>> authority. TLC MUST falsify
\* AuthorizationFenceConsistent. This is not a protocol design.

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

UnsafeRegisterOverOrdinaryReservation ==
    /\ headProgram = NoProgram
    /\ authorizationOwner = NoProgram
    /\ programStatus[POriginal] = "UNREGISTERED"
    /\ ordinaryAuthorizationState = "RESERVED"
    /\ programStatus' = [programStatus EXCEPT ![POriginal] = "ACTIVE"]
    /\ headProgram' = POriginal
    /\ authorizationOwner' = POriginal
    /\ UNCHANGED
         <<supersededBy, budgetReserved, budgetConsumed,
           occurrenceState, occurrenceProgram, occurrenceNode,
           admissionBinding, ordinaryAuthorizationState, programTime>>

UnsafeNext == base!Next \/ UnsafeRegisterOverOrdinaryReservation

Spec == base!Init /\ [][UnsafeNext]_vars

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
