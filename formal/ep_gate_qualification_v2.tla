-------------------- MODULE ep_gate_qualification_v2 --------------------
\* EMILIA Gate Qualification v2 bounded lifecycle model.
\*
\* The architecture freezes a tenant-scoped operation identity across
\* supersession. A superseding qualification receives a new admission_id but
\* retains the original operation_id, CAID, canonical action/request, and
\* authorization. Reusing that operation with a different CAID or canonical
\* request is refused. Only a remedy is a new operation with a new CAID,
\* action/request, admission, and authorization.
\*
\* beginInvocation consumes one-time authority while provider entry is still
\* NOT_ENTERED. Authenticated provider and effect evidence remain independent
\* axes: in particular, provider COMMITTED plus effect DIVERGED is reachable.
\* Once accepted evidence says NOT_ENTERED, no later transition may enter the
\* provider boundary for that qualification.
\*
\* Signatures, evidence truth, clocks, storage linearizability/durability,
\* provider truth, and implementation refinement are abstracted. TLC checks
\* the configured finite control model, not an unbounded theorem.

EXTENDS Naturals, FiniteSets

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

QualificationIds == {QOriginal, QReplacement, QRemedy}
Tenants == {TenantA}
Operations == {OperationPrimary, OperationRemedy}
CAIDs == {CaidOriginal, CaidConflict, CaidRemedy}
Actions == {ActionPrimary, ActionRemedy}
Requests == {RequestPrimary, RequestConflict, RequestRemedy}
Authorizations == {AuthorizationPrimary, AuthorizationRemedy}
Admissions ==
    {AdmissionOriginal, AdmissionReplacement,
     AdmissionConflictCAID, AdmissionConflictRequest, AdmissionRemedy,
     AdmissionUnauthenticated, AdmissionStale}
Evidence ==
    {ProviderCommittedOriginal,
     ProviderNotCommittedBeforeEntryOriginal,
     ProviderNotCommittedAfterEntryOriginal,
     EffectConvergedOriginal,
     EffectDivergedBeforeEntryOriginal,
     EffectDivergedAfterEntryOriginal,
     ProviderCommittedReplacement, EffectDivergedReplacement,
     ProviderCommittedRemedy, EffectConvergedRemedy,
     EvidenceUnauthenticatedOriginal, EvidenceWrongBindingOriginal}

NoQualification == "NO_QUALIFICATION"
NoTenant == "NO_TENANT"
NoOperation == "NO_OPERATION"
NoCAID == "NO_CAID"
NoAction == "NO_ACTION"
NoRequest == "NO_REQUEST"
NoAuthorization == "NO_AUTHORIZATION"
NoAdmission == "NO_ADMISSION"
NoEvidence == "NO_EVIDENCE"

Statuses ==
    {"EMPTY", "RESERVED", "INVOKING", "INDETERMINATE",
     "RESOLVED", "SUPERSEDED"}
LiveStatuses == {"RESERVED", "INVOKING", "INDETERMINATE"}
TerminalStatuses == {"RESOLVED", "SUPERSEDED"}
AuthorityStates == {"NONE", "RESERVED", "CONSUMED", "RELEASED"}
EntryStates == {"NOT_ENTERED", "ENTERED"}
EvidenceKinds == {"PROVIDER", "EFFECT"}
ProviderOutcomes == {"UNKNOWN", "COMMITTED", "NOT_COMMITTED"}
EffectOutcomes == {"UNKNOWN", "CONVERGED", "DIVERGED"}

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

\* -----------------------------------------------------------------------
\* Frozen admission inputs
\* -----------------------------------------------------------------------

AdmissionKind(a) ==
    CASE a \in {AdmissionReplacement,
                 AdmissionConflictCAID,
                 AdmissionConflictRequest} -> "SUPERSESSION"
      [] a = AdmissionRemedy -> "REMEDY"
      [] OTHER -> "PRIMARY"

AdmissionQualification(a) ==
    CASE a \in {AdmissionReplacement,
                 AdmissionConflictCAID,
                 AdmissionConflictRequest} -> QReplacement
      [] a = AdmissionRemedy -> QRemedy
      [] OTHER -> QOriginal

AdmissionTenant(a) == TenantA

\* Supersession and both conflict probes reuse the tenant-scoped operation.
AdmissionOperation(a) ==
    IF a = AdmissionRemedy THEN OperationRemedy ELSE OperationPrimary

AdmissionCAID(a) ==
    CASE a = AdmissionRemedy -> CaidRemedy
      [] a = AdmissionConflictCAID -> CaidConflict
      [] OTHER -> CaidOriginal

AdmissionAction(a) ==
    IF a = AdmissionRemedy THEN ActionRemedy ELSE ActionPrimary

AdmissionRequest(a) ==
    CASE a = AdmissionRemedy -> RequestRemedy
      [] a = AdmissionConflictRequest -> RequestConflict
      [] OTHER -> RequestPrimary

AdmissionAuthorization(a) ==
    IF a = AdmissionRemedy
    THEN AuthorizationRemedy
    ELSE AuthorizationPrimary

AdmissionAuthenticated(a) == a # AdmissionUnauthenticated
AdmissionAccepted(a) == a # AdmissionUnauthenticated
AdmissionCurrent(a) == a # AdmissionStale

ValidAdmission(q, a) ==
    /\ a \in Admissions
    /\ AdmissionQualification(a) = q
    /\ AdmissionAuthenticated(a)
    /\ AdmissionAccepted(a)
    /\ AdmissionCurrent(a)

SameCanonicalOperationAdmission(old, admission) ==
    /\ AdmissionTenant(admission) = tenantOf[old]
    /\ AdmissionOperation(admission) = operationOf[old]
    /\ AdmissionCAID(admission) = caidOf[old]
    /\ AdmissionAction(admission) = actionOf[old]
    /\ AdmissionRequest(admission) = requestOf[old]
    /\ AdmissionAuthorization(admission) = authorizationOf[old]

\* -----------------------------------------------------------------------
\* Authenticated exact-binding evidence inputs
\* -----------------------------------------------------------------------

EvidenceKind(e) ==
    IF e \in {ProviderCommittedOriginal,
              ProviderNotCommittedBeforeEntryOriginal,
              ProviderNotCommittedAfterEntryOriginal,
              ProviderCommittedReplacement,
              ProviderCommittedRemedy,
              EvidenceUnauthenticatedOriginal}
    THEN "PROVIDER"
    ELSE "EFFECT"

EvidenceQualification(e) ==
    CASE e \in {ProviderCommittedReplacement,
                 EffectDivergedReplacement,
                 EvidenceWrongBindingOriginal} -> QReplacement
      [] e \in {ProviderCommittedRemedy, EffectConvergedRemedy} -> QRemedy
      [] OTHER -> QOriginal

EvidenceTenant(e) == TenantA

EvidenceOperation(e) ==
    IF e \in {ProviderCommittedRemedy, EffectConvergedRemedy}
    THEN OperationRemedy
    ELSE OperationPrimary

EvidenceCAID(e) ==
    IF e \in {ProviderCommittedRemedy, EffectConvergedRemedy}
    THEN CaidRemedy
    ELSE CaidOriginal

EvidenceAction(e) ==
    IF e \in {ProviderCommittedRemedy, EffectConvergedRemedy}
    THEN ActionRemedy
    ELSE ActionPrimary

EvidenceRequest(e) ==
    IF e \in {ProviderCommittedRemedy, EffectConvergedRemedy}
    THEN RequestRemedy
    ELSE RequestPrimary

EvidenceAuthorization(e) ==
    IF e \in {ProviderCommittedRemedy, EffectConvergedRemedy}
    THEN AuthorizationRemedy
    ELSE AuthorizationPrimary

EvidenceAdmission(e) ==
    CASE e \in {ProviderCommittedReplacement,
                 EffectDivergedReplacement} -> AdmissionReplacement
      [] e \in {ProviderCommittedRemedy,
                 EffectConvergedRemedy} -> AdmissionRemedy
      [] OTHER -> AdmissionOriginal

EvidenceAuthenticated(e) == e # EvidenceUnauthenticatedOriginal

EvidenceEntry(e) ==
    IF e \in {ProviderNotCommittedBeforeEntryOriginal,
              EffectDivergedBeforeEntryOriginal}
    THEN "NOT_ENTERED"
    ELSE "ENTERED"

EvidenceProviderOutcome(e) ==
    IF e \in {ProviderNotCommittedBeforeEntryOriginal,
              ProviderNotCommittedAfterEntryOriginal}
    THEN "NOT_COMMITTED"
    ELSE "COMMITTED"

EvidenceEffectOutcome(e) ==
    IF e \in {EffectDivergedBeforeEntryOriginal,
              EffectDivergedAfterEntryOriginal,
              EffectDivergedReplacement,
              EvidenceWrongBindingOriginal}
    THEN "DIVERGED"
    ELSE "CONVERGED"

EvidenceExactFor(q, e) ==
    /\ e \in Evidence
    /\ EvidenceAuthenticated(e)
    /\ EvidenceQualification(e) = q
    /\ EvidenceTenant(e) = tenantOf[q]
    /\ EvidenceOperation(e) = operationOf[q]
    /\ EvidenceCAID(e) = caidOf[q]
    /\ EvidenceAction(e) = actionOf[q]
    /\ EvidenceRequest(e) = requestOf[q]
    /\ EvidenceAuthorization(e) = authorizationOf[q]
    /\ EvidenceAdmission(e) = admissionOf[q]

ValidProviderEvidence(q, e) ==
    /\ EvidenceExactFor(q, e)
    /\ EvidenceKind(e) = "PROVIDER"
    /\ EvidenceEntry(e) = entryState[q]
    /\ EvidenceProviderOutcome(e) \in
         (ProviderOutcomes \ {"UNKNOWN"})

ValidEffectEvidence(q, e) ==
    /\ EvidenceExactFor(q, e)
    /\ EvidenceKind(e) = "EFFECT"
    /\ EvidenceEntry(e) = entryState[q]
    /\ EvidenceEffectOutcome(e) \in (EffectOutcomes \ {"UNKNOWN"})

AcceptedNotEnteredEvidence(q) ==
    \/ /\ providerEvidence[q] # NoEvidence
       /\ EvidenceEntry(providerEvidence[q]) = "NOT_ENTERED"
    \/ /\ effectEvidence[q] # NoEvidence
       /\ EvidenceEntry(effectEvidence[q]) = "NOT_ENTERED"

\* -----------------------------------------------------------------------
\* State predicates
\* -----------------------------------------------------------------------

LiveFor(t, operation) ==
    {q \in QualificationIds :
        /\ status[q] \in LiveStatuses
        /\ tenantOf[q] = t
        /\ operationOf[q] = operation}

TypeInvariant ==
    /\ status \in [QualificationIds -> Statuses]
    /\ qualificationAccepted \in [QualificationIds -> BOOLEAN]
    /\ qualificationCurrent \in [QualificationIds -> BOOLEAN]
    /\ tenantOf \in [QualificationIds -> Tenants \union {NoTenant}]
    /\ operationOf \in [QualificationIds -> Operations \union {NoOperation}]
    /\ caidOf \in [QualificationIds -> CAIDs \union {NoCAID}]
    /\ actionOf \in [QualificationIds -> Actions \union {NoAction}]
    /\ requestOf \in [QualificationIds -> Requests \union {NoRequest}]
    /\ authorizationOf
         \in [QualificationIds -> Authorizations \union {NoAuthorization}]
    /\ admissionOf \in [QualificationIds -> Admissions \union {NoAdmission}]
    /\ authorityState \in [QualificationIds -> AuthorityStates]
    /\ entryState \in [QualificationIds -> EntryStates]
    /\ invocationCount \in [QualificationIds -> 0..1]
    /\ providerEvidence \in [QualificationIds -> Evidence \union {NoEvidence}]
    /\ effectEvidence \in [QualificationIds -> Evidence \union {NoEvidence}]
    /\ providerOutcome \in [QualificationIds -> ProviderOutcomes]
    /\ effectOutcome \in [QualificationIds -> EffectOutcomes]
    /\ supersededBy
         \in [QualificationIds -> QualificationIds \union {NoQualification}]
    /\ remedyOf
         \in [QualificationIds -> QualificationIds \union {NoQualification}]

DistinctFrozenDomains ==
    /\ Cardinality(QualificationIds) = 3
    /\ Cardinality(Operations) = 2
    /\ Cardinality(CAIDs) = 3
    /\ Cardinality(Actions) = 2
    /\ Cardinality(Requests) = 3
    /\ Cardinality(Authorizations) = 2
    /\ Cardinality(Admissions) = 7
    /\ Cardinality(Evidence) = 12
    /\ NoQualification \notin QualificationIds
    /\ NoTenant \notin Tenants
    /\ NoOperation \notin Operations
    /\ NoCAID \notin CAIDs
    /\ NoAction \notin Actions
    /\ NoRequest \notin Requests
    /\ NoAuthorization \notin Authorizations
    /\ NoAdmission \notin Admissions
    /\ NoEvidence \notin Evidence

EmptySlotsClean ==
    \A q \in QualificationIds :
        status[q] = "EMPTY" =>
            /\ ~qualificationAccepted[q]
            /\ ~qualificationCurrent[q]
            /\ tenantOf[q] = NoTenant
            /\ operationOf[q] = NoOperation
            /\ caidOf[q] = NoCAID
            /\ actionOf[q] = NoAction
            /\ requestOf[q] = NoRequest
            /\ authorizationOf[q] = NoAuthorization
            /\ admissionOf[q] = NoAdmission
            /\ authorityState[q] = "NONE"
            /\ entryState[q] = "NOT_ENTERED"
            /\ invocationCount[q] = 0
            /\ providerEvidence[q] = NoEvidence
            /\ effectEvidence[q] = NoEvidence
            /\ providerOutcome[q] = "UNKNOWN"
            /\ effectOutcome[q] = "UNKNOWN"
            /\ supersededBy[q] = NoQualification
            /\ remedyOf[q] = NoQualification

QualificationAcceptedAndCurrent ==
    \A q \in QualificationIds :
        /\ (qualificationAccepted[q] <=> status[q] # "EMPTY")
        /\ (qualificationCurrent[q] <=> status[q] \in LiveStatuses)

LifecycleConsistency ==
    \A q \in QualificationIds :
        CASE status[q] = "EMPTY" ->
                 /\ authorityState[q] = "NONE"
                 /\ invocationCount[q] = 0
                 /\ entryState[q] = "NOT_ENTERED"
          [] status[q] = "RESERVED" ->
                 /\ authorityState[q] = "RESERVED"
                 /\ invocationCount[q] = 0
                 /\ entryState[q] = "NOT_ENTERED"
                 /\ providerEvidence[q] = NoEvidence
                 /\ effectEvidence[q] = NoEvidence
                 /\ providerOutcome[q] = "UNKNOWN"
                 /\ effectOutcome[q] = "UNKNOWN"
                 /\ supersededBy[q] = NoQualification
          [] status[q] = "INVOKING" ->
                 /\ authorityState[q] = "CONSUMED"
                 /\ invocationCount[q] = 1
                 /\ entryState[q] = "NOT_ENTERED"
          [] status[q] = "INDETERMINATE" ->
                 /\ authorityState[q] = "CONSUMED"
                 /\ invocationCount[q] = 1
                 /\ entryState[q] = "ENTERED"
          [] status[q] = "RESOLVED" ->
                 /\ authorityState[q] = "CONSUMED"
                 /\ invocationCount[q] = 1
                 /\ providerOutcome[q] # "UNKNOWN"
                 /\ effectOutcome[q] # "UNKNOWN"
          [] status[q] = "SUPERSEDED" ->
                 /\ authorityState[q] = "RELEASED"
                 /\ invocationCount[q] = 0
                 /\ entryState[q] = "NOT_ENTERED"
                 /\ providerEvidence[q] = NoEvidence
                 /\ effectEvidence[q] = NoEvidence
                 /\ providerOutcome[q] = "UNKNOWN"
                 /\ effectOutcome[q] = "UNKNOWN"
                 /\ supersededBy[q] # NoQualification

AtomicReservation ==
    \A q \in QualificationIds :
        status[q] = "RESERVED" =>
            /\ qualificationAccepted[q]
            /\ qualificationCurrent[q]
            /\ authorityState[q] = "RESERVED"
            /\ entryState[q] = "NOT_ENTERED"
            /\ invocationCount[q] = 0

OneLiveTenantOperation ==
    \A t \in Tenants, operation \in Operations :
        Cardinality(LiveFor(t, operation)) <= 1

SameOperationRequiresCanonicalIdentity ==
    \A left \in QualificationIds, right \in QualificationIds :
        /\ qualificationAccepted[left]
        /\ qualificationAccepted[right]
        /\ tenantOf[left] = tenantOf[right]
        /\ operationOf[left] = operationOf[right]
        => /\ caidOf[left] = caidOf[right]
           /\ actionOf[left] = actionOf[right]
           /\ requestOf[left] = requestOf[right]
           /\ authorizationOf[left] = authorizationOf[right]

AuthorityConsumedBeforeInvoking ==
    \A q \in QualificationIds :
        status[q] \in {"INVOKING", "INDETERMINATE", "RESOLVED"} =>
            authorityState[q] = "CONSUMED"

PostEntryIsIndeterminateOrResolved ==
    \A q \in QualificationIds :
        entryState[q] = "ENTERED" =>
            status[q] \in {"INDETERMINATE", "RESOLVED"}

InvokeAtMostOnce ==
    \A q \in QualificationIds : invocationCount[q] <= 1

AuthenticatedExactEvidence ==
    \A q \in QualificationIds :
        /\ (providerEvidence[q] # NoEvidence =>
              ValidProviderEvidence(q, providerEvidence[q]))
        /\ (effectEvidence[q] # NoEvidence =>
              ValidEffectEvidence(q, effectEvidence[q]))

OutcomeAxesMatchEvidence ==
    \A q \in QualificationIds :
        /\ (providerEvidence[q] = NoEvidence
              <=> providerOutcome[q] = "UNKNOWN")
        /\ (providerEvidence[q] # NoEvidence =>
              providerOutcome[q] =
                EvidenceProviderOutcome(providerEvidence[q]))
        /\ (effectEvidence[q] = NoEvidence
              <=> effectOutcome[q] = "UNKNOWN")
        /\ (effectEvidence[q] # NoEvidence =>
              effectOutcome[q] = EvidenceEffectOutcome(effectEvidence[q]))

ResolvedRequiresAuthenticatedEvidence ==
    \A q \in QualificationIds :
        status[q] = "RESOLVED" =>
            /\ providerEvidence[q] # NoEvidence
            /\ effectEvidence[q] # NoEvidence
            /\ ValidProviderEvidence(q, providerEvidence[q])
            /\ ValidEffectEvidence(q, effectEvidence[q])
            /\ providerOutcome[q] =
                 EvidenceProviderOutcome(providerEvidence[q])
            /\ effectOutcome[q] = EvidenceEffectOutcome(effectEvidence[q])

\* This invariant deliberately does not couple the two outcome axes.
CommittedDivergedIsValidResolution ==
    \A q \in QualificationIds :
        /\ providerOutcome[q] = "COMMITTED"
        /\ effectOutcome[q] = "DIVERGED"
        => status[q] \in {"INDETERMINATE", "RESOLVED"}

AcceptedNotEnteredEvidenceNeverEntered ==
    \A q \in QualificationIds :
        AcceptedNotEnteredEvidence(q) => entryState[q] = "NOT_ENTERED"

\* A SUPERSEDED state is reachable only from an uninvoked RESERVED record.
\* The unsafe comparison module deliberately violates this invariant.
SupersessionOnlyWhileReserved ==
    \A q \in QualificationIds :
        status[q] = "SUPERSEDED" =>
            /\ invocationCount[q] = 0
            /\ entryState[q] = "NOT_ENTERED"
            /\ authorityState[q] = "RELEASED"

SupersessionBindingExact ==
    \A old \in QualificationIds :
        status[old] = "SUPERSEDED" =>
            LET replacement == supersededBy[old]
            IN /\ replacement \in QualificationIds
               /\ qualificationAccepted[replacement]
               /\ tenantOf[replacement] = tenantOf[old]
               /\ operationOf[replacement] = operationOf[old]
               /\ caidOf[replacement] = caidOf[old]
               /\ actionOf[replacement] = actionOf[old]
               /\ requestOf[replacement] = requestOf[old]
               /\ authorizationOf[replacement] = authorizationOf[old]
               /\ admissionOf[replacement] # admissionOf[old]
               /\ remedyOf[replacement] = NoQualification

RemedyRequiresFreshIdentityAndAuthorization ==
    \A q \in QualificationIds :
        remedyOf[q] # NoQualification =>
            LET original == remedyOf[q]
            IN /\ original \in QualificationIds
               /\ qualificationAccepted[original]
               /\ tenantOf[q] = tenantOf[original]
               /\ operationOf[q] # operationOf[original]
               /\ caidOf[q] # caidOf[original]
               /\ actionOf[q] # actionOf[original]
               /\ requestOf[q] # requestOf[original]
               /\ authorizationOf[q] # authorizationOf[original]
               /\ admissionOf[q] # admissionOf[original]

\* -----------------------------------------------------------------------
\* Initial state
\* -----------------------------------------------------------------------

Init ==
    /\ status = [q \in QualificationIds |-> "EMPTY"]
    /\ qualificationAccepted = [q \in QualificationIds |-> FALSE]
    /\ qualificationCurrent = [q \in QualificationIds |-> FALSE]
    /\ tenantOf = [q \in QualificationIds |-> NoTenant]
    /\ operationOf = [q \in QualificationIds |-> NoOperation]
    /\ caidOf = [q \in QualificationIds |-> NoCAID]
    /\ actionOf = [q \in QualificationIds |-> NoAction]
    /\ requestOf = [q \in QualificationIds |-> NoRequest]
    /\ authorizationOf = [q \in QualificationIds |-> NoAuthorization]
    /\ admissionOf = [q \in QualificationIds |-> NoAdmission]
    /\ authorityState = [q \in QualificationIds |-> "NONE"]
    /\ entryState = [q \in QualificationIds |-> "NOT_ENTERED"]
    /\ invocationCount = [q \in QualificationIds |-> 0]
    /\ providerEvidence = [q \in QualificationIds |-> NoEvidence]
    /\ effectEvidence = [q \in QualificationIds |-> NoEvidence]
    /\ providerOutcome = [q \in QualificationIds |-> "UNKNOWN"]
    /\ effectOutcome = [q \in QualificationIds |-> "UNKNOWN"]
    /\ supersededBy = [q \in QualificationIds |-> NoQualification]
    /\ remedyOf = [q \in QualificationIds |-> NoQualification]

\* -----------------------------------------------------------------------
\* Lifecycle transitions
\* -----------------------------------------------------------------------

AdmitAndReserve(q, admission) ==
    /\ q \in QualificationIds
    /\ status[q] = "EMPTY"
    /\ ValidAdmission(q, admission)
    /\ AdmissionKind(admission) = "PRIMARY"
    /\ LiveFor(AdmissionTenant(admission),
               AdmissionOperation(admission)) = {}
    /\ status' = [status EXCEPT ![q] = "RESERVED"]
    /\ qualificationAccepted' =
         [qualificationAccepted EXCEPT ![q] = TRUE]
    /\ qualificationCurrent' =
         [qualificationCurrent EXCEPT ![q] = TRUE]
    /\ tenantOf' = [tenantOf EXCEPT ![q] = AdmissionTenant(admission)]
    /\ operationOf' =
         [operationOf EXCEPT ![q] = AdmissionOperation(admission)]
    /\ caidOf' = [caidOf EXCEPT ![q] = AdmissionCAID(admission)]
    /\ actionOf' = [actionOf EXCEPT ![q] = AdmissionAction(admission)]
    /\ requestOf' = [requestOf EXCEPT ![q] = AdmissionRequest(admission)]
    /\ authorizationOf' =
         [authorizationOf EXCEPT ![q] = AdmissionAuthorization(admission)]
    /\ admissionOf' = [admissionOf EXCEPT ![q] = admission]
    /\ authorityState' = [authorityState EXCEPT ![q] = "RESERVED"]
    /\ entryState' = [entryState EXCEPT ![q] = "NOT_ENTERED"]
    /\ invocationCount' = [invocationCount EXCEPT ![q] = 0]
    /\ providerEvidence' = [providerEvidence EXCEPT ![q] = NoEvidence]
    /\ effectEvidence' = [effectEvidence EXCEPT ![q] = NoEvidence]
    /\ providerOutcome' = [providerOutcome EXCEPT ![q] = "UNKNOWN"]
    /\ effectOutcome' = [effectOutcome EXCEPT ![q] = "UNKNOWN"]
    /\ supersededBy' = [supersededBy EXCEPT ![q] = NoQualification]
    /\ remedyOf' = [remedyOf EXCEPT ![q] = NoQualification]

SupersedeReserved(old, replacement, admission) ==
    /\ old \in QualificationIds
    /\ replacement \in QualificationIds
    /\ old # replacement
    /\ status[old] = "RESERVED"
    /\ status[replacement] = "EMPTY"
    /\ ValidAdmission(replacement, admission)
    /\ AdmissionKind(admission) = "SUPERSESSION"
    /\ SameCanonicalOperationAdmission(old, admission)
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
         [tenantOf EXCEPT ![replacement] = AdmissionTenant(admission)]
    /\ operationOf' =
         [operationOf EXCEPT ![replacement] = AdmissionOperation(admission)]
    /\ caidOf' =
         [caidOf EXCEPT ![replacement] = AdmissionCAID(admission)]
    /\ actionOf' =
         [actionOf EXCEPT ![replacement] = AdmissionAction(admission)]
    /\ requestOf' =
         [requestOf EXCEPT ![replacement] = AdmissionRequest(admission)]
    /\ authorizationOf' =
         [authorizationOf EXCEPT
             ![replacement] = AdmissionAuthorization(admission)]
    /\ admissionOf' = [admissionOf EXCEPT ![replacement] = admission]
    /\ authorityState' =
         [authorityState EXCEPT
             ![old] = "RELEASED",
             ![replacement] = "RESERVED"]
    /\ entryState' = [entryState EXCEPT ![replacement] = "NOT_ENTERED"]
    /\ invocationCount' = [invocationCount EXCEPT ![replacement] = 0]
    /\ providerEvidence' =
         [providerEvidence EXCEPT ![replacement] = NoEvidence]
    /\ effectEvidence' = [effectEvidence EXCEPT ![replacement] = NoEvidence]
    /\ providerOutcome' =
         [providerOutcome EXCEPT ![replacement] = "UNKNOWN"]
    /\ effectOutcome' = [effectOutcome EXCEPT ![replacement] = "UNKNOWN"]
    /\ supersededBy' =
         [supersededBy EXCEPT
             ![old] = replacement,
             ![replacement] = NoQualification]
    /\ remedyOf' = [remedyOf EXCEPT ![replacement] = NoQualification]

AdmitRemedy(remedy, original, admission) ==
    /\ remedy \in QualificationIds
    /\ original \in QualificationIds
    /\ remedy # original
    /\ status[remedy] = "EMPTY"
    /\ status[original] \in {"INDETERMINATE", "RESOLVED"}
    /\ ValidAdmission(remedy, admission)
    /\ AdmissionKind(admission) = "REMEDY"
    /\ AdmissionTenant(admission) = tenantOf[original]
    /\ AdmissionOperation(admission) # operationOf[original]
    /\ AdmissionCAID(admission) # caidOf[original]
    /\ AdmissionAction(admission) # actionOf[original]
    /\ AdmissionRequest(admission) # requestOf[original]
    /\ AdmissionAuthorization(admission) # authorizationOf[original]
    /\ admission # admissionOf[original]
    /\ LiveFor(AdmissionTenant(admission),
               AdmissionOperation(admission)) = {}
    /\ status' = [status EXCEPT ![remedy] = "RESERVED"]
    /\ qualificationAccepted' =
         [qualificationAccepted EXCEPT ![remedy] = TRUE]
    /\ qualificationCurrent' =
         [qualificationCurrent EXCEPT ![remedy] = TRUE]
    /\ tenantOf' =
         [tenantOf EXCEPT ![remedy] = AdmissionTenant(admission)]
    /\ operationOf' =
         [operationOf EXCEPT ![remedy] = AdmissionOperation(admission)]
    /\ caidOf' = [caidOf EXCEPT ![remedy] = AdmissionCAID(admission)]
    /\ actionOf' =
         [actionOf EXCEPT ![remedy] = AdmissionAction(admission)]
    /\ requestOf' =
         [requestOf EXCEPT ![remedy] = AdmissionRequest(admission)]
    /\ authorizationOf' =
         [authorizationOf EXCEPT
             ![remedy] = AdmissionAuthorization(admission)]
    /\ admissionOf' = [admissionOf EXCEPT ![remedy] = admission]
    /\ authorityState' =
         [authorityState EXCEPT ![remedy] = "RESERVED"]
    /\ entryState' = [entryState EXCEPT ![remedy] = "NOT_ENTERED"]
    /\ invocationCount' = [invocationCount EXCEPT ![remedy] = 0]
    /\ providerEvidence' = [providerEvidence EXCEPT ![remedy] = NoEvidence]
    /\ effectEvidence' = [effectEvidence EXCEPT ![remedy] = NoEvidence]
    /\ providerOutcome' = [providerOutcome EXCEPT ![remedy] = "UNKNOWN"]
    /\ effectOutcome' = [effectOutcome EXCEPT ![remedy] = "UNKNOWN"]
    /\ supersededBy' =
         [supersededBy EXCEPT ![remedy] = NoQualification]
    /\ remedyOf' = [remedyOf EXCEPT ![remedy] = original]

\* Authority consumption and transition to INVOKING are one atomic action.
BeginInvocation(q) ==
    /\ q \in QualificationIds
    /\ status[q] = "RESERVED"
    /\ qualificationAccepted[q]
    /\ qualificationCurrent[q]
    /\ authorityState[q] = "RESERVED"
    /\ entryState[q] = "NOT_ENTERED"
    /\ invocationCount[q] = 0
    /\ status' = [status EXCEPT ![q] = "INVOKING"]
    /\ authorityState' = [authorityState EXCEPT ![q] = "CONSUMED"]
    /\ invocationCount' = [invocationCount EXCEPT ![q] = 1]
    /\ UNCHANGED <<
         qualificationAccepted, qualificationCurrent,
         tenantOf, operationOf, caidOf, actionOf, requestOf,
         authorizationOf, admissionOf, entryState,
         providerEvidence, effectEvidence, providerOutcome, effectOutcome,
         supersededBy, remedyOf
       >>

\* Any already-accepted evidence at this point necessarily attests
\* NOT_ENTERED and permanently closes this provider-entry transition.
EnterProvider(q) ==
    /\ q \in QualificationIds
    /\ status[q] = "INVOKING"
    /\ authorityState[q] = "CONSUMED"
    /\ entryState[q] = "NOT_ENTERED"
    /\ invocationCount[q] = 1
    /\ ~AcceptedNotEnteredEvidence(q)
    /\ status' = [status EXCEPT ![q] = "INDETERMINATE"]
    /\ entryState' = [entryState EXCEPT ![q] = "ENTERED"]
    /\ UNCHANGED <<
         qualificationAccepted, qualificationCurrent,
         tenantOf, operationOf, caidOf, actionOf, requestOf,
         authorizationOf, admissionOf, authorityState, invocationCount,
         providerEvidence, effectEvidence, providerOutcome, effectOutcome,
         supersededBy, remedyOf
       >>

AcceptProviderEvidence(q, evidence) ==
    /\ q \in QualificationIds
    /\ status[q] \in {"INVOKING", "INDETERMINATE"}
    /\ providerEvidence[q] = NoEvidence
    /\ providerOutcome[q] = "UNKNOWN"
    /\ ValidProviderEvidence(q, evidence)
    /\ providerEvidence' = [providerEvidence EXCEPT ![q] = evidence]
    /\ providerOutcome' =
         [providerOutcome EXCEPT
             ![q] = EvidenceProviderOutcome(evidence)]
    /\ UNCHANGED <<
         status, qualificationAccepted, qualificationCurrent,
         tenantOf, operationOf, caidOf, actionOf, requestOf,
         authorizationOf, admissionOf, authorityState, entryState,
         invocationCount, effectEvidence, effectOutcome,
         supersededBy, remedyOf
       >>

AcceptEffectEvidence(q, evidence) ==
    /\ q \in QualificationIds
    /\ status[q] \in {"INVOKING", "INDETERMINATE"}
    /\ effectEvidence[q] = NoEvidence
    /\ effectOutcome[q] = "UNKNOWN"
    /\ ValidEffectEvidence(q, evidence)
    /\ effectEvidence' = [effectEvidence EXCEPT ![q] = evidence]
    /\ effectOutcome' =
         [effectOutcome EXCEPT ![q] = EvidenceEffectOutcome(evidence)]
    /\ UNCHANGED <<
         status, qualificationAccepted, qualificationCurrent,
         tenantOf, operationOf, caidOf, actionOf, requestOf,
         authorizationOf, admissionOf, authorityState, entryState,
         invocationCount, providerEvidence, providerOutcome,
         supersededBy, remedyOf
       >>

\* Partition evidence acceptance by attested provider-entry state. The named
\* wrappers make both pre-entry fencing and post-entry reconciliation
\* non-vacuous in TLC action coverage.
AcceptNotEnteredProviderEvidence(q, evidence) ==
    /\ EvidenceEntry(evidence) = "NOT_ENTERED"
    /\ AcceptProviderEvidence(q, evidence)

AcceptEnteredProviderEvidence(q, evidence) ==
    /\ EvidenceEntry(evidence) = "ENTERED"
    /\ AcceptProviderEvidence(q, evidence)

AcceptNotEnteredEffectEvidence(q, evidence) ==
    /\ EvidenceEntry(evidence) = "NOT_ENTERED"
    /\ AcceptEffectEvidence(q, evidence)

AcceptEnteredEffectEvidence(q, evidence) ==
    /\ EvidenceEntry(evidence) = "ENTERED"
    /\ AcceptEffectEvidence(q, evidence)

FinalizeResolved(q) ==
    /\ q \in QualificationIds
    /\ status[q] \in {"INVOKING", "INDETERMINATE"}
    /\ providerEvidence[q] # NoEvidence
    /\ effectEvidence[q] # NoEvidence
    /\ providerOutcome[q] # "UNKNOWN"
    /\ effectOutcome[q] # "UNKNOWN"
    /\ ValidProviderEvidence(q, providerEvidence[q])
    /\ ValidEffectEvidence(q, effectEvidence[q])
    /\ status' = [status EXCEPT ![q] = "RESOLVED"]
    /\ qualificationCurrent' =
         [qualificationCurrent EXCEPT ![q] = FALSE]
    /\ UNCHANGED <<
         qualificationAccepted, tenantOf, operationOf, caidOf,
         actionOf, requestOf, authorizationOf, admissionOf,
         authorityState, entryState, invocationCount,
         providerEvidence, effectEvidence, providerOutcome, effectOutcome,
         supersededBy, remedyOf
       >>

\* Kept as a separate top-level action so TLC coverage proves this cross-axis
\* outcome is reachable in the exhaustive bounded graph.
FinalizeCommittedDiverged(q) ==
    /\ providerOutcome[q] = "COMMITTED"
    /\ effectOutcome[q] = "DIVERGED"
    /\ FinalizeResolved(q)

FinalizeOtherResolved(q) ==
    /\ ~(providerOutcome[q] = "COMMITTED"
         /\ effectOutcome[q] = "DIVERGED")
    /\ FinalizeResolved(q)

\* -----------------------------------------------------------------------
\* Reachable refusal/no-op actions
\* -----------------------------------------------------------------------

RejectInvalidAdmission(q, admission) ==
    /\ q \in QualificationIds
    /\ admission \in Admissions
    /\ status[q] = "EMPTY"
    /\ ~ValidAdmission(q, admission)
    /\ UNCHANGED vars

RejectSupersessionIdentityConflict(old, replacement, admission) ==
    /\ old \in QualificationIds
    /\ replacement \in QualificationIds
    /\ old # replacement
    /\ status[old] = "RESERVED"
    /\ status[replacement] = "EMPTY"
    /\ ValidAdmission(replacement, admission)
    /\ AdmissionKind(admission) = "SUPERSESSION"
    /\ ~SameCanonicalOperationAdmission(old, admission)
    /\ UNCHANGED vars

RejectLateSupersession(old, replacement, admission) ==
    /\ old \in QualificationIds
    /\ replacement \in QualificationIds
    /\ admission \in Admissions
    /\ old # replacement
    /\ status[old] # "RESERVED"
    /\ status[replacement] = "EMPTY"
    /\ AdmissionKind(admission) = "SUPERSESSION"
    /\ UNCHANGED vars

RejectInvalidEvidence(q, evidence) ==
    /\ q \in QualificationIds
    /\ evidence \in Evidence
    /\ status[q] \in {"INVOKING", "INDETERMINATE"}
    /\ ~(ValidProviderEvidence(q, evidence)
         \/ ValidEffectEvidence(q, evidence))
    /\ UNCHANGED vars

RejectBlindRetry(q) ==
    /\ q \in QualificationIds
    /\ invocationCount[q] = 1
    /\ UNCHANGED vars

Next ==
    \/ \E q \in QualificationIds, admission \in Admissions :
         AdmitAndReserve(q, admission)
    \/ \E old \in QualificationIds,
          replacement \in QualificationIds,
          admission \in Admissions :
         SupersedeReserved(old, replacement, admission)
    \/ \E remedy \in QualificationIds,
          original \in QualificationIds,
          admission \in Admissions :
         AdmitRemedy(remedy, original, admission)
    \/ \E q \in QualificationIds : BeginInvocation(q)
    \/ \E q \in QualificationIds : EnterProvider(q)
    \/ \E q \in QualificationIds, evidence \in Evidence :
         AcceptNotEnteredProviderEvidence(q, evidence)
    \/ \E q \in QualificationIds, evidence \in Evidence :
         AcceptEnteredProviderEvidence(q, evidence)
    \/ \E q \in QualificationIds, evidence \in Evidence :
         AcceptNotEnteredEffectEvidence(q, evidence)
    \/ \E q \in QualificationIds, evidence \in Evidence :
         AcceptEnteredEffectEvidence(q, evidence)
    \/ \E q \in QualificationIds : FinalizeCommittedDiverged(q)
    \/ \E q \in QualificationIds : FinalizeOtherResolved(q)
    \/ \E q \in QualificationIds, admission \in Admissions :
         RejectInvalidAdmission(q, admission)
    \/ \E old \in QualificationIds,
          replacement \in QualificationIds,
          admission \in Admissions :
         RejectSupersessionIdentityConflict(old, replacement, admission)
    \/ \E old \in QualificationIds,
          replacement \in QualificationIds,
          admission \in Admissions :
         RejectLateSupersession(old, replacement, admission)
    \/ \E q \in QualificationIds, evidence \in Evidence :
         RejectInvalidEvidence(q, evidence)
    \/ \E q \in QualificationIds : RejectBlindRetry(q)

Spec == Init /\ [][Next]_vars

\* -----------------------------------------------------------------------
\* Transition properties
\* -----------------------------------------------------------------------

AdmissionAndReserveAreAtomic ==
    [][\A q \in QualificationIds :
         status[q] = "EMPTY" /\ status'[q] = "RESERVED" =>
             /\ qualificationAccepted'[q]
             /\ qualificationCurrent'[q]
             /\ authorityState'[q] = "RESERVED"
             /\ entryState'[q] = "NOT_ENTERED"
             /\ invocationCount'[q] = 0]_vars

BeginInvocationConsumesAuthority ==
    [][\A q \in QualificationIds :
         status[q] = "RESERVED" /\ status'[q] = "INVOKING" =>
             /\ authorityState[q] = "RESERVED"
             /\ authorityState'[q] = "CONSUMED"
             /\ entryState'[q] = "NOT_ENTERED"
             /\ invocationCount'[q] = 1]_vars

ProviderEntryCreatesIndeterminate ==
    [][\A q \in QualificationIds :
         entryState[q] = "NOT_ENTERED" /\ entryState'[q] = "ENTERED" =>
             /\ status[q] = "INVOKING"
             /\ status'[q] = "INDETERMINATE"
             /\ authorityState'[q] = "CONSUMED"
             /\ invocationCount'[q] = 1]_vars

NotEnteredEvidencePrecludesProviderEntry ==
    [][\A q \in QualificationIds :
         AcceptedNotEnteredEvidence(q) =>
             entryState'[q] = "NOT_ENTERED"]_vars

NoBlindRetryAfterInvocation ==
    [][\A q \in QualificationIds :
         invocationCount[q] = 1 => invocationCount'[q] = 1]_vars

SupersessionTransitionStartsReserved ==
    [][\A q \in QualificationIds :
         status[q] # "SUPERSEDED" /\ status'[q] = "SUPERSEDED" =>
             status[q] = "RESERVED"]_vars

SupersessionRotatesOnlyAdmission ==
    [][\A old \in QualificationIds :
         status[old] # "SUPERSEDED" /\ status'[old] = "SUPERSEDED" =>
             LET replacement == supersededBy'[old]
             IN /\ replacement \in QualificationIds
                /\ tenantOf'[replacement] = tenantOf[old]
                /\ operationOf'[replacement] = operationOf[old]
                /\ caidOf'[replacement] = caidOf[old]
                /\ actionOf'[replacement] = actionOf[old]
                /\ requestOf'[replacement] = requestOf[old]
                /\ authorizationOf'[replacement] = authorizationOf[old]
                /\ admissionOf'[replacement] # admissionOf[old]]_vars

BindingsFrozenAfterAdmission ==
    [][\A q \in QualificationIds :
         status[q] # "EMPTY" =>
             /\ tenantOf'[q] = tenantOf[q]
             /\ operationOf'[q] = operationOf[q]
             /\ caidOf'[q] = caidOf[q]
             /\ actionOf'[q] = actionOf[q]
             /\ requestOf'[q] = requestOf[q]
             /\ authorizationOf'[q] = authorizationOf[q]
             /\ admissionOf'[q] = admissionOf[q]
             /\ remedyOf'[q] = remedyOf[q]]_vars

EvidenceAndOutcomesImmutable ==
    [][\A q \in QualificationIds :
         /\ (providerEvidence[q] # NoEvidence =>
               /\ providerEvidence'[q] = providerEvidence[q]
               /\ providerOutcome'[q] = providerOutcome[q])
         /\ (effectEvidence[q] # NoEvidence =>
               /\ effectEvidence'[q] = effectEvidence[q]
               /\ effectOutcome'[q] = effectOutcome[q])]_vars

TerminalStateIrreversible ==
    [][\A q \in QualificationIds :
         status[q] \in TerminalStatuses => status'[q] = status[q]]_vars

\* -----------------------------------------------------------------------
\* Documentation theorems; TLC checks the configured finite model.
\* -----------------------------------------------------------------------

THEOREM Spec => []TypeInvariant
THEOREM Spec => []DistinctFrozenDomains
THEOREM Spec => []EmptySlotsClean
THEOREM Spec => []QualificationAcceptedAndCurrent
THEOREM Spec => []LifecycleConsistency
THEOREM Spec => []AtomicReservation
THEOREM Spec => []OneLiveTenantOperation
THEOREM Spec => []SameOperationRequiresCanonicalIdentity
THEOREM Spec => []AuthorityConsumedBeforeInvoking
THEOREM Spec => []PostEntryIsIndeterminateOrResolved
THEOREM Spec => []InvokeAtMostOnce
THEOREM Spec => []AuthenticatedExactEvidence
THEOREM Spec => []OutcomeAxesMatchEvidence
THEOREM Spec => []ResolvedRequiresAuthenticatedEvidence
THEOREM Spec => []CommittedDivergedIsValidResolution
THEOREM Spec => []AcceptedNotEnteredEvidenceNeverEntered
THEOREM Spec => []SupersessionOnlyWhileReserved
THEOREM Spec => []SupersessionBindingExact
THEOREM Spec => []RemedyRequiresFreshIdentityAndAuthorization
THEOREM Spec => AdmissionAndReserveAreAtomic
THEOREM Spec => BeginInvocationConsumesAuthority
THEOREM Spec => ProviderEntryCreatesIndeterminate
THEOREM Spec => NotEnteredEvidencePrecludesProviderEntry
THEOREM Spec => NoBlindRetryAfterInvocation
THEOREM Spec => SupersessionTransitionStartsReserved
THEOREM Spec => SupersessionRotatesOnlyAdmission
THEOREM Spec => BindingsFrozenAfterAdmission
THEOREM Spec => EvidenceAndOutcomesImmutable
THEOREM Spec => TerminalStateIrreversible

=============================================================================
