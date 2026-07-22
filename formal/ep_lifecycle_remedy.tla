--------------------- MODULE ep_lifecycle_remedy ---------------------
\* EMILIA Protocol - bounded lifecycle and remedy safety model.
\*
\* Scope:
\*   - one already-claimed, already-executed original effect;
\*   - two bounded remedy slots competing for one tenant budget;
\*   - a second tenant that may trigger or attempt access but cannot acquire or
\*     mutate authority for the original tenant;
\*   - authenticated remedy decisions, fresh identity triples, exact owner and
\*     claim bindings, partial accounting, the indeterminate fence, and
\*     authenticated reconciliation.
\*
\* The original effect and every remedy are separate records.  Revocation and
\* appeal are modeled as later facts; neither rewrites effect truth.  External
\* signature/credential verification is abstracted at the transition boundary:
\* only AuthorizeRemedy and ReconcileRemedy represent authenticated inputs.

EXTENDS Naturals, FiniteSets

CONSTANTS
    Tenants, OriginalTenant, Remedies,
    CAIDs, ActionIDs, OperationIDs,
    EffectDigests, OwnerModes, OwnerDigests, ClaimTokens, DecisionDigests,
    OriginalCAID, OriginalActionID, OriginalOperationID,
    OriginalEffectDigest, OriginalOwnerMode, OriginalOwnerDigest,
    OriginalClaimToken, MaxBudget, MaxSteps

NoTenant == "none_tenant"
NoId == "none_id"

RemedyStates ==
    {"empty", "authorized", "claimed", "indeterminate",
     "succeeded", "proved_no_effect"}

ClaimedStates ==
    {"claimed", "indeterminate", "succeeded", "proved_no_effect"}

TerminalRemedyStates == {"succeeded", "proved_no_effect"}
TerminalSources == {"none", "direct", "authenticated_reconciliation"}

VARIABLES
    \* Immutable original-effect record; revocation is deliberately separate.
    originalClaimed, originalExecuted, originalTenant,
    originalCAID, originalActionID, originalOperationID,
    originalEffectDigest, originalOwnerModes, originalOwnerDigests,
    originalClaimTokens, originalRevoked,

    \* Per-remedy identity and authenticated authority.
    remedyStatus, remedyTenant, remedyCAID, remedyActionID, remedyOperationID,
    decisionAuthenticated, decisionDigests, ownerModes, ownerDigests,
    claimTokens, claimCount,

    \* Non-authoritative observations.
    triggered, triggerTenant, appealed,

    \* Per-remedy and per-tenant accounting/outcome state.
    remedyAmount, remedyReserved, remedyConsumed, remedyReleased,
    terminalSource, reconciliationAuthenticated,
    tenantAvailable, tenantReserved, tenantConsumed,

    \* Explicit finite exploration bound.
    step

effectRecordVars ==
    <<originalClaimed, originalExecuted, originalTenant,
      originalCAID, originalActionID, originalOperationID,
      originalEffectDigest, originalOwnerModes, originalOwnerDigests,
      originalClaimTokens>>

remedyBindingVars ==
    <<remedyTenant, remedyCAID, remedyActionID, remedyOperationID, remedyAmount>>

remedyDecisionVars == <<decisionAuthenticated, decisionDigests>>
remedyOwnerVars == <<ownerModes, ownerDigests>>
remedyClaimVars == <<claimTokens, claimCount>>
remedyObservationVars == <<triggered, triggerTenant, appealed>>
remedyAccountingVars ==
    <<remedyReserved, remedyConsumed, remedyReleased>>
remedyOutcomeVars == <<terminalSource, reconciliationAuthenticated>>
tenantAccountingVars == <<tenantAvailable, tenantReserved, tenantConsumed>>

vars ==
    <<effectRecordVars, originalRevoked, remedyStatus, remedyBindingVars,
      remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
      remedyObservationVars, remedyAccountingVars, remedyOutcomeVars,
      tenantAccountingVars, step>>

OccupiedRemedies == {r \in Remedies : remedyStatus[r] # "empty"}
ClaimedRemedies == {r \in Remedies : claimCount[r] = 1}

UsedCAIDs == {remedyCAID[r] : r \in OccupiedRemedies}
UsedActionIDs == {remedyActionID[r] : r \in OccupiedRemedies}
UsedOperationIDs == {remedyOperationID[r] : r \in OccupiedRemedies}
UsedClaimTokens == UNION {claimTokens[r] : r \in Remedies}

RemediesOf(t) ==
    {r \in Remedies : remedyStatus[r] # "empty" /\ remedyTenant[r] = t}

RECURSIVE SumReserved(_)
SumReserved(S) ==
    IF S = {} THEN 0
    ELSE LET r == CHOOSE x \in S : TRUE
         IN remedyReserved[r] + SumReserved(S \ {r})

RECURSIVE SumConsumed(_)
SumConsumed(S) ==
    IF S = {} THEN 0
    ELSE LET r == CHOOSE x \in S : TRUE
         IN remedyConsumed[r] + SumConsumed(S \ {r})

FreshIdentity(caid, actionId, operationId) ==
    /\ caid \in CAIDs \ {OriginalCAID}
    /\ actionId \in ActionIDs \ {OriginalActionID}
    /\ operationId \in OperationIDs \ {OriginalOperationID}
    /\ caid \notin UsedCAIDs
    /\ actionId \notin UsedActionIDs
    /\ operationId \notin UsedOperationIDs

\* ---------------------------------------------------------------------
\* Static bounded-instance shape and state invariants.
\* ---------------------------------------------------------------------
ModelShape ==
    /\ OriginalTenant \in Tenants
    /\ Cardinality(Tenants) >= 2
    /\ Cardinality(Remedies) >= 2
    /\ OriginalCAID \in CAIDs
    /\ OriginalActionID \in ActionIDs
    /\ OriginalOperationID \in OperationIDs
    /\ OriginalEffectDigest \in EffectDigests
    /\ OriginalOwnerMode \in OwnerModes
    /\ OriginalOwnerDigest \in OwnerDigests
    /\ OriginalClaimToken \in ClaimTokens
    /\ Cardinality(CAIDs \ {OriginalCAID}) >= Cardinality(Remedies)
    /\ Cardinality(ActionIDs \ {OriginalActionID}) >= Cardinality(Remedies)
    /\ Cardinality(OperationIDs \ {OriginalOperationID}) >= Cardinality(Remedies)
    /\ Cardinality(ClaimTokens \ {OriginalClaimToken}) >= Cardinality(Remedies)
    /\ DecisionDigests # {}
    /\ OwnerModes # {}
    /\ OwnerDigests # {}
    /\ NoTenant \notin Tenants
    /\ NoId \notin CAIDs \union ActionIDs \union OperationIDs
    /\ NoId \notin ClaimTokens \union DecisionDigests
    /\ NoId \notin OwnerModes \union OwnerDigests \union EffectDigests
    /\ MaxBudget >= 2
    /\ MaxSteps >= 7

TypeInvariant ==
    /\ originalClaimed \in BOOLEAN
    /\ originalExecuted \in BOOLEAN
    /\ originalTenant \in Tenants
    /\ originalCAID \in CAIDs
    /\ originalActionID \in ActionIDs
    /\ originalOperationID \in OperationIDs
    /\ originalEffectDigest \in EffectDigests
    /\ originalOwnerModes \subseteq OwnerModes
    /\ originalOwnerDigests \subseteq OwnerDigests
    /\ originalClaimTokens \subseteq ClaimTokens
    /\ originalRevoked \in BOOLEAN
    /\ remedyStatus \in [Remedies -> RemedyStates]
    /\ remedyTenant \in [Remedies -> Tenants \union {NoTenant}]
    /\ remedyCAID \in [Remedies -> CAIDs \union {NoId}]
    /\ remedyActionID \in [Remedies -> ActionIDs \union {NoId}]
    /\ remedyOperationID \in [Remedies -> OperationIDs \union {NoId}]
    /\ decisionAuthenticated \in [Remedies -> BOOLEAN]
    /\ decisionDigests \in [Remedies -> SUBSET DecisionDigests]
    /\ ownerModes \in [Remedies -> SUBSET OwnerModes]
    /\ ownerDigests \in [Remedies -> SUBSET OwnerDigests]
    /\ claimTokens \in [Remedies -> SUBSET ClaimTokens]
    /\ claimCount \in [Remedies -> 0..1]
    /\ triggered \in [Remedies -> BOOLEAN]
    /\ triggerTenant \in [Remedies -> Tenants \union {NoTenant}]
    /\ appealed \in [Remedies -> BOOLEAN]
    /\ remedyAmount \in [Remedies -> 0..MaxBudget]
    /\ remedyReserved \in [Remedies -> 0..MaxBudget]
    /\ remedyConsumed \in [Remedies -> 0..MaxBudget]
    /\ remedyReleased \in [Remedies -> 0..MaxBudget]
    /\ terminalSource \in [Remedies -> TerminalSources]
    /\ reconciliationAuthenticated \in [Remedies -> BOOLEAN]
    /\ tenantAvailable \in [Tenants -> 0..MaxBudget]
    /\ tenantReserved \in [Tenants -> 0..MaxBudget]
    /\ tenantConsumed \in [Tenants -> 0..MaxBudget]
    /\ step \in 0..MaxSteps

OriginalEffectRecord ==
    /\ originalClaimed
    /\ originalExecuted
    /\ originalTenant = OriginalTenant
    /\ originalCAID = OriginalCAID
    /\ originalActionID = OriginalActionID
    /\ originalOperationID = OriginalOperationID
    /\ originalEffectDigest = OriginalEffectDigest
    /\ originalOwnerModes = {OriginalOwnerMode}
    /\ originalOwnerDigests = {OriginalOwnerDigest}
    /\ originalClaimTokens = {OriginalClaimToken}

AuthenticatedDecisionRequired ==
    \A r \in OccupiedRemedies :
        /\ decisionAuthenticated[r]
        /\ Cardinality(decisionDigests[r]) = 1

FreshRemedyIdentifiers ==
    /\ \A r \in OccupiedRemedies :
          /\ remedyCAID[r] \in CAIDs \ {OriginalCAID}
          /\ remedyActionID[r] \in ActionIDs \ {OriginalActionID}
          /\ remedyOperationID[r] \in OperationIDs \ {OriginalOperationID}
    /\ \A r1, r2 \in OccupiedRemedies :
          r1 # r2 =>
              /\ remedyCAID[r1] # remedyCAID[r2]
              /\ remedyActionID[r1] # remedyActionID[r2]
              /\ remedyOperationID[r1] # remedyOperationID[r2]

ExactlyOneOwnerModeDigest ==
    \A r \in Remedies :
        IF remedyStatus[r] = "empty"
        THEN /\ ownerModes[r] = {}
             /\ ownerDigests[r] = {}
        ELSE /\ Cardinality(ownerModes[r]) = 1
             /\ Cardinality(ownerDigests[r]) = 1

ExactlyOneClaimToken ==
    /\ \A r \in Remedies :
          /\ (claimCount[r] = 0 <=> claimTokens[r] = {})
          /\ (claimCount[r] = 1 =>
                /\ Cardinality(claimTokens[r]) = 1
                /\ OriginalClaimToken \notin claimTokens[r])
    /\ \A r1, r2 \in ClaimedRemedies :
          r1 # r2 => claimTokens[r1] \intersect claimTokens[r2] = {}

ObservationShape ==
    \A r \in Remedies :
        /\ (triggered[r]
              => triggerTenant[r] \in Tenants)
        /\ (~triggered[r]
              => triggerTenant[r] = NoTenant)
        /\ (appealed[r]
              => /\ triggered[r]
                  /\ triggerTenant[r] = OriginalTenant)
        /\ (remedyStatus[r] # "empty" /\ triggered[r]
              => triggerTenant[r] = remedyTenant[r])

RemedyLifecycleConsistent ==
    \A r \in Remedies :
        CASE remedyStatus[r] = "empty" ->
                 /\ remedyTenant[r] = NoTenant
                 /\ remedyCAID[r] = NoId
                 /\ remedyActionID[r] = NoId
                 /\ remedyOperationID[r] = NoId
                 /\ ~decisionAuthenticated[r]
                 /\ decisionDigests[r] = {}
                 /\ ownerModes[r] = {}
                 /\ ownerDigests[r] = {}
                 /\ claimTokens[r] = {}
                 /\ claimCount[r] = 0
                 /\ remedyAmount[r] = 0
                 /\ remedyReserved[r] = 0
                 /\ remedyConsumed[r] = 0
                 /\ remedyReleased[r] = 0
                 /\ terminalSource[r] = "none"
                 /\ ~reconciliationAuthenticated[r]
          [] remedyStatus[r] = "authorized" ->
                 /\ remedyTenant[r] = OriginalTenant
                 /\ claimCount[r] = 0
                 /\ claimTokens[r] = {}
                 /\ remedyAmount[r] \in 1..MaxBudget
                 /\ remedyReserved[r] = 0
                 /\ remedyConsumed[r] = 0
                 /\ remedyReleased[r] = 0
                 /\ terminalSource[r] = "none"
                 /\ ~reconciliationAuthenticated[r]
          [] remedyStatus[r] = "claimed" ->
                 /\ claimCount[r] = 1
                 /\ remedyReserved[r] > 0
                 /\ remedyReleased[r] = 0
                 /\ remedyReserved[r] + remedyConsumed[r] = remedyAmount[r]
                 /\ terminalSource[r] = "none"
                 /\ ~reconciliationAuthenticated[r]
          [] remedyStatus[r] = "indeterminate" ->
                 /\ claimCount[r] = 1
                 /\ remedyReserved[r] > 0
                 /\ remedyReleased[r] = 0
                 /\ remedyReserved[r] + remedyConsumed[r] = remedyAmount[r]
                 /\ terminalSource[r] = "none"
                 /\ ~reconciliationAuthenticated[r]
          [] remedyStatus[r] = "succeeded" ->
                 /\ claimCount[r] = 1
                 /\ remedyReserved[r] = 0
                 /\ remedyConsumed[r] > 0
                 /\ remedyConsumed[r] + remedyReleased[r] = remedyAmount[r]
                 /\ terminalSource[r] \in
                       {"direct", "authenticated_reconciliation"}
                 /\ (terminalSource[r] = "direct" =>
                       /\ remedyReleased[r] = 0
                       /\ ~reconciliationAuthenticated[r])
                 /\ (terminalSource[r] = "authenticated_reconciliation" =>
                       reconciliationAuthenticated[r])
          [] remedyStatus[r] = "proved_no_effect" ->
                 /\ claimCount[r] = 1
                 /\ remedyReserved[r] = 0
                 /\ remedyConsumed[r] = 0
                 /\ remedyReleased[r] = remedyAmount[r]
                 /\ terminalSource[r] = "authenticated_reconciliation"
                 /\ reconciliationAuthenticated[r]

PartialBudgetConservation ==
    /\ \A t \in Tenants :
          /\ tenantReserved[t] = SumReserved(RemediesOf(t))
          /\ tenantConsumed[t] = SumConsumed(RemediesOf(t))
          /\ tenantAvailable[t] + tenantReserved[t] + tenantConsumed[t]
                = MaxBudget
    /\ \A r \in ClaimedRemedies :
          remedyReserved[r] + remedyConsumed[r] + remedyReleased[r]
              = remedyAmount[r]

IndeterminateStateFence ==
    \A r \in Remedies :
        remedyStatus[r] = "indeterminate" =>
            /\ claimCount[r] = 1
            /\ Cardinality(claimTokens[r]) = 1
            /\ remedyReserved[r] > 0
            /\ terminalSource[r] = "none"
            /\ ~reconciliationAuthenticated[r]

AuthenticatedReconciliation ==
    \A r \in Remedies :
        /\ (remedyStatus[r] = "proved_no_effect" =>
              /\ reconciliationAuthenticated[r]
              /\ terminalSource[r] = "authenticated_reconciliation")
        /\ (remedyStatus[r] = "succeeded" /\ remedyReleased[r] > 0 =>
              /\ reconciliationAuthenticated[r]
              /\ terminalSource[r] = "authenticated_reconciliation")

TriggerAuthorityBoundary ==
    \A r \in Remedies :
        remedyStatus[r] = "empty" =>
            /\ ~decisionAuthenticated[r]
            /\ ownerModes[r] = {}
            /\ ownerDigests[r] = {}
            /\ claimCount[r] = 0
            /\ claimTokens[r] = {}
            /\ remedyReserved[r] = 0
            /\ remedyConsumed[r] = 0

TenantIsolation ==
    /\ \A r \in OccupiedRemedies : remedyTenant[r] = OriginalTenant
    /\ \A t \in Tenants \ {OriginalTenant} :
          /\ tenantAvailable[t] = MaxBudget
          /\ tenantReserved[t] = 0
          /\ tenantConsumed[t] = 0

\* ---------------------------------------------------------------------
\* Initial state.  The original effect is historical truth at model entry.
\* ---------------------------------------------------------------------
Init ==
    /\ originalClaimed = TRUE
    /\ originalExecuted = TRUE
    /\ originalTenant = OriginalTenant
    /\ originalCAID = OriginalCAID
    /\ originalActionID = OriginalActionID
    /\ originalOperationID = OriginalOperationID
    /\ originalEffectDigest = OriginalEffectDigest
    /\ originalOwnerModes = {OriginalOwnerMode}
    /\ originalOwnerDigests = {OriginalOwnerDigest}
    /\ originalClaimTokens = {OriginalClaimToken}
    /\ originalRevoked = FALSE
    /\ remedyStatus = [r \in Remedies |-> "empty"]
    /\ remedyTenant = [r \in Remedies |-> NoTenant]
    /\ remedyCAID = [r \in Remedies |-> NoId]
    /\ remedyActionID = [r \in Remedies |-> NoId]
    /\ remedyOperationID = [r \in Remedies |-> NoId]
    /\ decisionAuthenticated = [r \in Remedies |-> FALSE]
    /\ decisionDigests = [r \in Remedies |-> {}]
    /\ ownerModes = [r \in Remedies |-> {}]
    /\ ownerDigests = [r \in Remedies |-> {}]
    /\ claimTokens = [r \in Remedies |-> {}]
    /\ claimCount = [r \in Remedies |-> 0]
    /\ triggered = [r \in Remedies |-> FALSE]
    /\ triggerTenant = [r \in Remedies |-> NoTenant]
    /\ appealed = [r \in Remedies |-> FALSE]
    /\ remedyAmount = [r \in Remedies |-> 0]
    /\ remedyReserved = [r \in Remedies |-> 0]
    /\ remedyConsumed = [r \in Remedies |-> 0]
    /\ remedyReleased = [r \in Remedies |-> 0]
    /\ terminalSource = [r \in Remedies |-> "none"]
    /\ reconciliationAuthenticated = [r \in Remedies |-> FALSE]
    /\ tenantAvailable = [t \in Tenants |-> MaxBudget]
    /\ tenantReserved = [t \in Tenants |-> 0]
    /\ tenantConsumed = [t \in Tenants |-> 0]
    /\ step = 0

\* ---------------------------------------------------------------------
\* Successful transitions.
\* ---------------------------------------------------------------------
RecordTrigger(r, t) ==
    /\ step < MaxSteps
    /\ ~triggered[r]
    /\ (remedyStatus[r] = "empty" \/ t = remedyTenant[r])
    /\ triggered' = [triggered EXCEPT ![r] = TRUE]
    /\ triggerTenant' = [triggerTenant EXCEPT ![r] = t]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyStatus, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
                   appealed, remedyAccountingVars, remedyOutcomeVars,
                   tenantAccountingVars>>

FileAppeal(r, t) ==
    /\ step < MaxSteps
    /\ t = OriginalTenant
    /\ ~appealed[r]
    /\ (~triggered[r] \/ triggerTenant[r] = t)
    /\ (remedyStatus[r] = "empty" \/ remedyTenant[r] = t)
    /\ appealed' = [appealed EXCEPT ![r] = TRUE]
    /\ triggered' = [triggered EXCEPT ![r] = TRUE]
    /\ triggerTenant' = [triggerTenant EXCEPT ![r] = t]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyStatus, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
                   remedyAccountingVars, remedyOutcomeVars,
                   tenantAccountingVars>>

AuthorizeRemedy(r, t, caid, actionId, operationId,
                decisionDigest, mode, ownerDigest, amount) ==
    /\ step < MaxSteps
    /\ remedyStatus[r] = "empty"
    /\ t = OriginalTenant
    /\ (~triggered[r] \/ triggerTenant[r] = t)
    /\ FreshIdentity(caid, actionId, operationId)
    /\ decisionDigest \in DecisionDigests
    /\ mode \in OwnerModes
    /\ ownerDigest \in OwnerDigests
    /\ amount \in 1..MaxBudget
    /\ remedyStatus' = [remedyStatus EXCEPT ![r] = "authorized"]
    /\ remedyTenant' = [remedyTenant EXCEPT ![r] = t]
    /\ remedyCAID' = [remedyCAID EXCEPT ![r] = caid]
    /\ remedyActionID' = [remedyActionID EXCEPT ![r] = actionId]
    /\ remedyOperationID' =
          [remedyOperationID EXCEPT ![r] = operationId]
    /\ remedyAmount' = [remedyAmount EXCEPT ![r] = amount]
    /\ decisionAuthenticated' =
          [decisionAuthenticated EXCEPT ![r] = TRUE]
    /\ decisionDigests' = [decisionDigests EXCEPT ![r] = {decisionDigest}]
    /\ ownerModes' = [ownerModes EXCEPT ![r] = {mode}]
    /\ ownerDigests' = [ownerDigests EXCEPT ![r] = {ownerDigest}]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyClaimVars,
                   remedyObservationVars, remedyAccountingVars,
                   remedyOutcomeVars, tenantAccountingVars>>

ClaimRemedy(r, t, mode, ownerDigest, token) ==
    /\ step < MaxSteps
    /\ remedyStatus[r] = "authorized"
    /\ t = remedyTenant[r]
    /\ ownerModes[r] = {mode}
    /\ ownerDigests[r] = {ownerDigest}
    /\ token \in ClaimTokens \ {OriginalClaimToken}
    /\ token \notin UsedClaimTokens
    /\ tenantAvailable[t] >= remedyAmount[r]
    /\ remedyStatus' = [remedyStatus EXCEPT ![r] = "claimed"]
    /\ claimTokens' = [claimTokens EXCEPT ![r] = {token}]
    /\ claimCount' = [claimCount EXCEPT ![r] = 1]
    /\ remedyReserved' =
          [remedyReserved EXCEPT ![r] = remedyAmount[r]]
    /\ tenantAvailable' =
          [tenantAvailable EXCEPT ![t] = @ - remedyAmount[r]]
    /\ tenantReserved' =
          [tenantReserved EXCEPT ![t] = @ + remedyAmount[r]]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars,
                   remedyObservationVars, remedyConsumed, remedyReleased,
                   remedyOutcomeVars, tenantConsumed>>

CommitRemedyEffect(r, delta) ==
    /\ step < MaxSteps
    /\ remedyStatus[r] = "claimed"
    /\ delta \in 1..remedyReserved[r]
    /\ LET t == remedyTenant[r]
           completes == delta = remedyReserved[r]
       IN /\ remedyStatus' =
                 [remedyStatus EXCEPT ![r] =
                     IF completes THEN "succeeded" ELSE "claimed"]
          /\ remedyReserved' =
                 [remedyReserved EXCEPT ![r] = @ - delta]
          /\ remedyConsumed' =
                 [remedyConsumed EXCEPT ![r] = @ + delta]
          /\ terminalSource' =
                 [terminalSource EXCEPT ![r] =
                     IF completes THEN "direct" ELSE @]
          /\ tenantReserved' =
                 [tenantReserved EXCEPT ![t] = @ - delta]
          /\ tenantConsumed' =
                 [tenantConsumed EXCEPT ![t] = @ + delta]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
                   remedyObservationVars, remedyReleased,
                   reconciliationAuthenticated, tenantAvailable>>

ReportIndeterminate(r) ==
    /\ step < MaxSteps
    /\ remedyStatus[r] = "claimed"
    /\ remedyReserved[r] > 0
    /\ remedyStatus' = [remedyStatus EXCEPT ![r] = "indeterminate"]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
                   remedyObservationVars, remedyAccountingVars,
                   remedyOutcomeVars, tenantAccountingVars>>

\* Authenticated reconciliation closes the entire remaining reservation.  A
\* delta may confirm all, some, or none of the remaining effect; the rest is
\* explicitly released, preserving the budget identity.
ReconcileRemedy(r, delta) ==
    /\ step < MaxSteps
    /\ remedyStatus[r] = "indeterminate"
    /\ delta \in 0..remedyReserved[r]
    /\ LET t == remedyTenant[r]
           held == remedyReserved[r]
           released == held - delta
           totalEffect == remedyConsumed[r] + delta
       IN /\ remedyStatus' =
                 [remedyStatus EXCEPT ![r] =
                     IF totalEffect > 0 THEN "succeeded"
                     ELSE "proved_no_effect"]
          /\ remedyReserved' = [remedyReserved EXCEPT ![r] = 0]
          /\ remedyConsumed' =
                 [remedyConsumed EXCEPT ![r] = totalEffect]
          /\ remedyReleased' =
                 [remedyReleased EXCEPT ![r] = @ + released]
          /\ terminalSource' =
                 [terminalSource EXCEPT
                    ![r] = "authenticated_reconciliation"]
          /\ reconciliationAuthenticated' =
                 [reconciliationAuthenticated EXCEPT ![r] = TRUE]
          /\ tenantAvailable' =
                 [tenantAvailable EXCEPT ![t] = @ + released]
          /\ tenantReserved' =
                 [tenantReserved EXCEPT ![t] = @ - held]
          /\ tenantConsumed' =
                 [tenantConsumed EXCEPT ![t] = @ + delta]
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<originalRevoked, remedyBindingVars,
                   remedyDecisionVars, remedyOwnerVars, remedyClaimVars,
                   remedyObservationVars>>

\* Revocation is a late fact about the historical authorization.  It cannot
\* erase the claimed/executed original effect or any remedy accounting.
LateRevokeOriginal ==
    /\ step < MaxSteps
    /\ ~originalRevoked
    /\ originalRevoked' = TRUE
    /\ step' = step + 1
    /\ UNCHANGED effectRecordVars
    /\ UNCHANGED <<remedyStatus, remedyBindingVars, remedyDecisionVars,
                   remedyOwnerVars, remedyClaimVars, remedyObservationVars,
                   remedyAccountingVars, remedyOutcomeVars,
                   tenantAccountingVars>>

\* ---------------------------------------------------------------------
\* Refusal paths.  Each hostile or insufficient input is explicitly inert.
\* ---------------------------------------------------------------------
TriggerAsAuthorityAttempt(r) ==
    /\ triggered[r]
    /\ remedyStatus[r] = "empty"
    /\ UNCHANGED vars

UnauthenticatedDecisionAttempt(r) ==
    /\ remedyStatus[r] = "empty"
    /\ UNCHANGED vars

ReusedIdentityAttempt(r) ==
    /\ remedyStatus[r] = "empty"
    /\ OccupiedRemedies # {}
    /\ UNCHANGED vars

DuplicateClaimAttempt(r) ==
    /\ claimCount[r] = 1
    /\ UNCHANGED vars

CrossTenantAuthorizationAttempt(r, t) ==
    /\ remedyStatus[r] = "empty"
    /\ t \in Tenants \ {OriginalTenant}
    /\ UNCHANGED vars

CrossTenantClaimAttempt(r, t) ==
    /\ remedyStatus[r] = "authorized"
    /\ t # remedyTenant[r]
    /\ UNCHANGED vars

RetryWhileIndeterminateAttempt(r) ==
    /\ remedyStatus[r] = "indeterminate"
    /\ UNCHANGED vars

UnauthenticatedReconcileAttempt(r) ==
    /\ remedyStatus[r] = "indeterminate"
    /\ UNCHANGED vars

AppealRewriteAttempt(r) ==
    /\ appealed[r]
    /\ originalClaimed
    /\ UNCHANGED vars

Next ==
    \/ \E r \in Remedies, t \in Tenants : RecordTrigger(r, t)
    \/ \E r \in Remedies, t \in Tenants : FileAppeal(r, t)
    \/ \E r \in Remedies, t \in Tenants,
          caid \in CAIDs, actionId \in ActionIDs,
          operationId \in OperationIDs, decisionDigest \in DecisionDigests,
          mode \in OwnerModes, ownerDigest \in OwnerDigests,
          amount \in 1..MaxBudget :
          AuthorizeRemedy(r, t, caid, actionId, operationId,
                          decisionDigest, mode, ownerDigest, amount)
    \/ \E r \in Remedies, t \in Tenants, mode \in OwnerModes,
          ownerDigest \in OwnerDigests, token \in ClaimTokens :
          ClaimRemedy(r, t, mode, ownerDigest, token)
    \/ \E r \in Remedies, delta \in 1..MaxBudget :
          CommitRemedyEffect(r, delta)
    \/ \E r \in Remedies : ReportIndeterminate(r)
    \/ \E r \in Remedies, delta \in 0..MaxBudget :
          ReconcileRemedy(r, delta)
    \/ LateRevokeOriginal
    \/ \E r \in Remedies : TriggerAsAuthorityAttempt(r)
    \/ \E r \in Remedies : UnauthenticatedDecisionAttempt(r)
    \/ \E r \in Remedies : ReusedIdentityAttempt(r)
    \/ \E r \in Remedies : DuplicateClaimAttempt(r)
    \/ \E r \in Remedies, t \in Tenants :
          CrossTenantAuthorizationAttempt(r, t)
    \/ \E r \in Remedies, t \in Tenants : CrossTenantClaimAttempt(r, t)
    \/ \E r \in Remedies : RetryWhileIndeterminateAttempt(r)
    \/ \E r \in Remedies : UnauthenticatedReconcileAttempt(r)
    \/ \E r \in Remedies : AppealRewriteAttempt(r)

Spec == Init /\ [][Next]_vars

BoundedExploration == step <= MaxSteps

\* ---------------------------------------------------------------------
\* Transition properties.
\* ---------------------------------------------------------------------
OriginalEffectImmutable ==
    [][effectRecordVars' = effectRecordVars]_vars

RemedyIdentityImmutable ==
    [][\A r \in Remedies :
          remedyStatus[r] # "empty" =>
              /\ remedyTenant'[r] = remedyTenant[r]
              /\ remedyCAID'[r] = remedyCAID[r]
              /\ remedyActionID'[r] = remedyActionID[r]
              /\ remedyOperationID'[r] = remedyOperationID[r]
              /\ remedyAmount'[r] = remedyAmount[r]]_vars

OwnerBindingImmutable ==
    [][\A r \in Remedies :
          remedyStatus[r] # "empty" =>
              /\ ownerModes'[r] = ownerModes[r]
              /\ ownerDigests'[r] = ownerDigests[r]]_vars

ClaimTokenImmutable ==
    [][\A r \in Remedies :
          claimCount[r] = 1 =>
              /\ claimCount'[r] = 1
              /\ claimTokens'[r] = claimTokens[r]]_vars

AuthorizationTransitionAuthenticated ==
    [][\A r \in Remedies :
          remedyStatus[r] = "empty" /\ remedyStatus'[r] = "authorized" =>
              /\ decisionAuthenticated'[r]
              /\ Cardinality(decisionDigests'[r]) = 1]_vars

IndeterminateOnlyReconciles ==
    [][\A r \in Remedies :
          remedyStatus[r] = "indeterminate" =>
              \/ /\ remedyStatus'[r] = "indeterminate"
                 /\ remedyReserved'[r] = remedyReserved[r]
                 /\ remedyConsumed'[r] = remedyConsumed[r]
                 /\ remedyReleased'[r] = remedyReleased[r]
                 /\ terminalSource'[r] = terminalSource[r]
                 /\ reconciliationAuthenticated'[r]
                       = reconciliationAuthenticated[r]
              \/ /\ remedyStatus'[r] \in TerminalRemedyStates
                 /\ reconciliationAuthenticated'[r]
                 /\ terminalSource'[r]
                       = "authenticated_reconciliation"]_vars

ReconciliationTransitionAuthenticated ==
    [][\A r \in Remedies :
          remedyStatus[r] = "indeterminate"
          /\ remedyStatus'[r] # "indeterminate" =>
              /\ reconciliationAuthenticated'[r]
              /\ terminalSource'[r]
                    = "authenticated_reconciliation"]_vars

LateRevocationDoesNotUndo ==
    [][(~originalRevoked /\ originalRevoked') =>
          /\ effectRecordVars' = effectRecordVars
          /\ originalClaimed'
          /\ originalExecuted']_vars

TriggerDoesNotGrantAuthority ==
    [][\A r \in Remedies :
          ~triggered[r] /\ triggered'[r] =>
              /\ remedyStatus'[r] = remedyStatus[r]
              /\ remedyTenant'[r] = remedyTenant[r]
              /\ remedyCAID'[r] = remedyCAID[r]
              /\ remedyActionID'[r] = remedyActionID[r]
              /\ remedyOperationID'[r] = remedyOperationID[r]
              /\ decisionAuthenticated'[r] = decisionAuthenticated[r]
              /\ decisionDigests'[r] = decisionDigests[r]
              /\ ownerModes'[r] = ownerModes[r]
              /\ ownerDigests'[r] = ownerDigests[r]
              /\ claimTokens'[r] = claimTokens[r]
              /\ claimCount'[r] = claimCount[r]
              /\ remedyAmount'[r] = remedyAmount[r]
              /\ remedyReserved'[r] = remedyReserved[r]
              /\ remedyConsumed'[r] = remedyConsumed[r]
              /\ tenantAccountingVars' = tenantAccountingVars]_vars

AppealCannotRewriteClaimedEffect ==
    [][(\E r \in Remedies : ~appealed[r] /\ appealed'[r]) =>
          /\ originalClaimed'
          /\ effectRecordVars' = effectRecordVars]_vars

CrossTenantAccountingIsolation ==
    [][\A r \in Remedies :
          <<remedyReserved'[r], remedyConsumed'[r], remedyReleased'[r]>>
            # <<remedyReserved[r], remedyConsumed[r], remedyReleased[r]>> =>
              \A t \in Tenants \ {remedyTenant[r]} :
                  /\ tenantAvailable'[t] = tenantAvailable[t]
                  /\ tenantReserved'[t] = tenantReserved[t]
                  /\ tenantConsumed'[t] = tenantConsumed[t]]_vars

TerminalRemedyIrreversible ==
    [][\A r \in Remedies :
          remedyStatus[r] \in TerminalRemedyStates =>
              remedyStatus'[r] = remedyStatus[r]]_vars

THEOREM Spec => []ModelShape
THEOREM Spec => []TypeInvariant
THEOREM Spec => []OriginalEffectRecord
THEOREM Spec => []AuthenticatedDecisionRequired
THEOREM Spec => []FreshRemedyIdentifiers
THEOREM Spec => []ExactlyOneOwnerModeDigest
THEOREM Spec => []ExactlyOneClaimToken
THEOREM Spec => []ObservationShape
THEOREM Spec => []RemedyLifecycleConsistent
THEOREM Spec => []PartialBudgetConservation
THEOREM Spec => []IndeterminateStateFence
THEOREM Spec => []AuthenticatedReconciliation
THEOREM Spec => []TriggerAuthorityBoundary
THEOREM Spec => []TenantIsolation
THEOREM Spec => OriginalEffectImmutable
THEOREM Spec => RemedyIdentityImmutable
THEOREM Spec => OwnerBindingImmutable
THEOREM Spec => ClaimTokenImmutable
THEOREM Spec => AuthorizationTransitionAuthenticated
THEOREM Spec => IndeterminateOnlyReconciles
THEOREM Spec => ReconciliationTransitionAuthenticated
THEOREM Spec => LateRevocationDoesNotUndo
THEOREM Spec => TriggerDoesNotGrantAuthority
THEOREM Spec => AppealCannotRewriteClaimedEffect
THEOREM Spec => CrossTenantAccountingIsolation
THEOREM Spec => TerminalRemedyIrreversible

=============================================================================
