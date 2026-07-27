---------------- MODULE ep_gate_qualification_v2_unsafe ----------------
\* Deliberately weakened negative control for Gate Qualification v2.
\*
\* UnsafeNext adds one forbidden transition: it supersedes a qualification
\* after provider entry made the outcome INDETERMINATE. The replacement still
\* obeys the architecture freeze (same operation/CAID/action/request/auth and
\* a new admission), isolating the intended lifecycle mutation. TLC MUST
\* falsify SupersessionOnlyWhileReserved. This is not a protocol design.

EXTENDS Naturals

CONSTANTS
    QOriginal, QReplacement, QRemedy,
    TenantA,
    OperationPrimary, OperationRemedy,
    CaidOriginal, CaidConflict, CaidRemedy,
    ActionPrimary, ActionRemedy,
    RequestPrimary, RequestConflict, RequestRemedy,
    AuthorizationPrimary, AuthorizationRemedy,
    AdmissionOriginal, AdmissionReplacement,
    AdmissionConflictCAID, AdmissionConflictRequest, AdmissionRemedy,
    AdmissionUnauthenticated, AdmissionStale,
    ProviderCommittedOriginal,
    ProviderNotCommittedBeforeEntryOriginal,
    ProviderNotCommittedAfterEntryOriginal,
    EffectConvergedOriginal,
    EffectDivergedBeforeEntryOriginal,
    EffectDivergedAfterEntryOriginal,
    ProviderCommittedReplacement, EffectDivergedReplacement,
    ProviderCommittedRemedy, EffectConvergedRemedy,
    EvidenceUnauthenticatedOriginal, EvidenceWrongBindingOriginal

VARIABLES
    status,
    qualificationAccepted,
    qualificationCurrent,
    tenantOf,
    operationOf,
    caidOf,
    actionOf,
    requestOf,
    authorizationOf,
    admissionOf,
    authorityState,
    entryState,
    invocationCount,
    providerEvidence,
    effectEvidence,
    providerOutcome,
    effectOutcome,
    supersededBy,
    remedyOf

vars ==
    <<status, qualificationAccepted, qualificationCurrent,
      tenantOf, operationOf, caidOf, actionOf, requestOf, authorizationOf,
      admissionOf, authorityState, entryState, invocationCount,
      providerEvidence, effectEvidence, providerOutcome, effectOutcome,
      supersededBy, remedyOf>>

base ==
    INSTANCE ep_gate_qualification_v2
      WITH QOriginal <- QOriginal,
           QReplacement <- QReplacement,
           QRemedy <- QRemedy,
           TenantA <- TenantA,
           OperationPrimary <- OperationPrimary,
           OperationRemedy <- OperationRemedy,
           CaidOriginal <- CaidOriginal,
           CaidConflict <- CaidConflict,
           CaidRemedy <- CaidRemedy,
           ActionPrimary <- ActionPrimary,
           ActionRemedy <- ActionRemedy,
           RequestPrimary <- RequestPrimary,
           RequestConflict <- RequestConflict,
           RequestRemedy <- RequestRemedy,
           AuthorizationPrimary <- AuthorizationPrimary,
           AuthorizationRemedy <- AuthorizationRemedy,
           AdmissionOriginal <- AdmissionOriginal,
           AdmissionReplacement <- AdmissionReplacement,
           AdmissionConflictCAID <- AdmissionConflictCAID,
           AdmissionConflictRequest <- AdmissionConflictRequest,
           AdmissionRemedy <- AdmissionRemedy,
           AdmissionUnauthenticated <- AdmissionUnauthenticated,
           AdmissionStale <- AdmissionStale,
           ProviderCommittedOriginal <- ProviderCommittedOriginal,
           ProviderNotCommittedBeforeEntryOriginal <-
             ProviderNotCommittedBeforeEntryOriginal,
           ProviderNotCommittedAfterEntryOriginal <-
             ProviderNotCommittedAfterEntryOriginal,
           EffectConvergedOriginal <- EffectConvergedOriginal,
           EffectDivergedBeforeEntryOriginal <-
             EffectDivergedBeforeEntryOriginal,
           EffectDivergedAfterEntryOriginal <-
             EffectDivergedAfterEntryOriginal,
           ProviderCommittedReplacement <- ProviderCommittedReplacement,
           EffectDivergedReplacement <- EffectDivergedReplacement,
           ProviderCommittedRemedy <- ProviderCommittedRemedy,
           EffectConvergedRemedy <- EffectConvergedRemedy,
           EvidenceUnauthenticatedOriginal <- EvidenceUnauthenticatedOriginal,
           EvidenceWrongBindingOriginal <- EvidenceWrongBindingOriginal,
           status <- status,
           qualificationAccepted <- qualificationAccepted,
           qualificationCurrent <- qualificationCurrent,
           tenantOf <- tenantOf,
           operationOf <- operationOf,
           caidOf <- caidOf,
           actionOf <- actionOf,
           requestOf <- requestOf,
           authorizationOf <- authorizationOf,
           admissionOf <- admissionOf,
           authorityState <- authorityState,
           entryState <- entryState,
           invocationCount <- invocationCount,
           providerEvidence <- providerEvidence,
           effectEvidence <- effectEvidence,
           providerOutcome <- providerOutcome,
           effectOutcome <- effectOutcome,
           supersededBy <- supersededBy,
           remedyOf <- remedyOf

\* This mutation keeps all canonical operation bindings exact, but illegally
\* releases consumed authority and labels a post-entry original SUPERSEDED.
LateSupersessionAfterProviderEntry(old, replacement, admission) ==
    /\ old \in base!QualificationIds
    /\ replacement \in base!QualificationIds
    /\ old # replacement
    /\ status[old] = "INDETERMINATE"
    /\ status[replacement] = "EMPTY"
    /\ providerEvidence[old] = base!NoEvidence
    /\ effectEvidence[old] = base!NoEvidence
    /\ providerOutcome[old] = "UNKNOWN"
    /\ effectOutcome[old] = "UNKNOWN"
    /\ base!ValidAdmission(replacement, admission)
    /\ base!AdmissionKind(admission) = "SUPERSESSION"
    /\ base!SameCanonicalOperationAdmission(old, admission)
    /\ admission # admissionOf[old]
    /\ status' =
         [status EXCEPT
             ![old] = "SUPERSEDED",
             ![replacement] = "RESERVED"]
    /\ qualificationAccepted' =
         [qualificationAccepted EXCEPT ![replacement] = TRUE]
    /\ qualificationCurrent' =
         [qualificationCurrent EXCEPT
             ![old] = FALSE,
             ![replacement] = TRUE]
    /\ tenantOf' =
         [tenantOf EXCEPT
             ![replacement] = base!AdmissionTenant(admission)]
    /\ operationOf' =
         [operationOf EXCEPT
             ![replacement] = base!AdmissionOperation(admission)]
    /\ caidOf' =
         [caidOf EXCEPT ![replacement] = base!AdmissionCAID(admission)]
    /\ actionOf' =
         [actionOf EXCEPT
             ![replacement] = base!AdmissionAction(admission)]
    /\ requestOf' =
         [requestOf EXCEPT
             ![replacement] = base!AdmissionRequest(admission)]
    /\ authorizationOf' =
         [authorizationOf EXCEPT
             ![replacement] = base!AdmissionAuthorization(admission)]
    /\ admissionOf' = [admissionOf EXCEPT ![replacement] = admission]
    /\ authorityState' =
         [authorityState EXCEPT
             ![old] = "RELEASED",
             ![replacement] = "RESERVED"]
    /\ entryState' =
         [entryState EXCEPT ![replacement] = "NOT_ENTERED"]
    /\ invocationCount' =
         [invocationCount EXCEPT ![replacement] = 0]
    /\ providerEvidence' =
         [providerEvidence EXCEPT ![replacement] = base!NoEvidence]
    /\ effectEvidence' =
         [effectEvidence EXCEPT ![replacement] = base!NoEvidence]
    /\ providerOutcome' =
         [providerOutcome EXCEPT ![replacement] = "UNKNOWN"]
    /\ effectOutcome' =
         [effectOutcome EXCEPT ![replacement] = "UNKNOWN"]
    /\ supersededBy' =
         [supersededBy EXCEPT
             ![old] = replacement,
             ![replacement] = base!NoQualification]
    /\ remedyOf' =
         [remedyOf EXCEPT ![replacement] = base!NoQualification]

UnsafeNext ==
    \/ base!Next
    \/ \E old \in base!QualificationIds,
          replacement \in base!QualificationIds,
          admission \in base!Admissions :
         LateSupersessionAfterProviderEntry(old, replacement, admission)

Spec == base!Init /\ [][UnsafeNext]_vars

\* Aliases let the safe and unsafe modules share one checked configuration.
TypeInvariant == base!TypeInvariant
SupersessionOnlyWhileReserved == base!SupersessionOnlyWhileReserved
DistinctFrozenDomains == base!DistinctFrozenDomains
EmptySlotsClean == base!EmptySlotsClean
QualificationAcceptedAndCurrent == base!QualificationAcceptedAndCurrent
LifecycleConsistency == base!LifecycleConsistency
AtomicReservation == base!AtomicReservation
OneLiveTenantOperation == base!OneLiveTenantOperation
SameOperationRequiresCanonicalIdentity ==
    base!SameOperationRequiresCanonicalIdentity
AuthorityConsumedBeforeInvoking == base!AuthorityConsumedBeforeInvoking
PostEntryIsIndeterminateOrResolved ==
    base!PostEntryIsIndeterminateOrResolved
InvokeAtMostOnce == base!InvokeAtMostOnce
AuthenticatedExactEvidence == base!AuthenticatedExactEvidence
OutcomeAxesMatchEvidence == base!OutcomeAxesMatchEvidence
ResolvedRequiresAuthenticatedEvidence ==
    base!ResolvedRequiresAuthenticatedEvidence
CommittedDivergedIsValidResolution ==
    base!CommittedDivergedIsValidResolution
AcceptedNotEnteredEvidenceNeverEntered ==
    base!AcceptedNotEnteredEvidenceNeverEntered
SupersessionBindingExact == base!SupersessionBindingExact
RemedyRequiresFreshIdentityAndAuthorization ==
    base!RemedyRequiresFreshIdentityAndAuthorization
AdmissionAndReserveAreAtomic == base!AdmissionAndReserveAreAtomic
BeginInvocationConsumesAuthority == base!BeginInvocationConsumesAuthority
ProviderEntryCreatesIndeterminate == base!ProviderEntryCreatesIndeterminate
NotEnteredEvidencePrecludesProviderEntry ==
    base!NotEnteredEvidencePrecludesProviderEntry
NoBlindRetryAfterInvocation == base!NoBlindRetryAfterInvocation
SupersessionTransitionStartsReserved ==
    base!SupersessionTransitionStartsReserved
SupersessionRotatesOnlyAdmission == base!SupersessionRotatesOnlyAdmission
BindingsFrozenAfterAdmission == base!BindingsFrozenAfterAdmission
EvidenceAndOutcomesImmutable == base!EvidenceAndOutcomesImmutable
TerminalStateIrreversible == base!TerminalStateIrreversible

=============================================================================
