---------------- MODULE ep_lifecycle_remedy_witness ----------------
\* Reachability/non-vacuity witnesses for ep_lifecycle_remedy.
\*
\* Every operator negates an interesting reachable state.  Checking one as an
\* INVARIANT must fail; its TLC counterexample is the reachability witness.

EXTENDS ep_lifecycle_remedy, FiniteSets

\* Must fail: a trigger can be recorded while authority remains completely
\* absent, including for a foreign tenant.
W_NoForeignTriggerWithoutAuthority ==
    ~(\E r \in Remedies :
        /\ triggered[r]
        /\ triggerTenant[r] \in Tenants \ {OriginalTenant}
        /\ remedyStatus[r] = "empty"
        /\ claimCount[r] = 0)

\* Must fail: an appeal is represented as a non-authoritative trigger while
\* the claimed/executed original effect retains its exact digest and token.
W_NoAppealPreservingOriginal ==
    ~(\E r \in Remedies :
        /\ appealed[r]
        /\ remedyStatus[r] = "empty"
        /\ originalClaimed
        /\ originalExecuted
        /\ originalEffectDigest = OriginalEffectDigest
        /\ originalClaimTokens = {OriginalClaimToken})

\* Must fail: an authenticated decision can create a distinct authorized
\* remedy with exactly one owner mode and digest but no claim yet.
W_NoAuthorizedRemedy ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "authorized"
        /\ decisionAuthenticated[r]
        /\ Cardinality(decisionDigests[r]) = 1
        /\ Cardinality(ownerModes[r]) = 1
        /\ Cardinality(ownerDigests[r]) = 1
        /\ claimTokens[r] = {})

\* Must fail: both remedy slots can be authorized simultaneously with pairwise
\* fresh CAID/action/operation identities, separate from the original effect.
W_NoTwoFreshRemedies ==
    ~(\E r1, r2 \in OccupiedRemedies :
        /\ r1 # r2
        /\ remedyCAID[r1] # remedyCAID[r2]
        /\ remedyActionID[r1] # remedyActionID[r2]
        /\ remedyOperationID[r1] # remedyOperationID[r2])

\* Must fail: one remedy can own exactly one claim token and reserve budget.
W_NoClaimedRemedy ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "claimed"
        /\ claimCount[r] = 1
        /\ Cardinality(claimTokens[r]) = 1
        /\ remedyReserved[r] > 0)

\* Must fail: partial effect accounting is real, with one unit consumed and
\* another still reserved under the same remedy and conserved tenant budget.
W_NoPartialBudgetState ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "claimed"
        /\ remedyConsumed[r] > 0
        /\ remedyReserved[r] > 0
        /\ remedyConsumed[r] + remedyReserved[r] = remedyAmount[r])

\* Must fail: an uncertain effect enters the no-retry indeterminate fence.
W_NoIndeterminateFence ==
    ~(\E r \in Remedies : remedyStatus[r] = "indeterminate")

\* Must fail: authenticated reconciliation can confirm a partial or complete
\* remedy effect and release any unconfirmed remainder.
W_NoReconciledEffect ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "succeeded"
        /\ terminalSource[r] = "authenticated_reconciliation"
        /\ reconciliationAuthenticated[r])

\* Must fail: authenticated reconciliation can prove no remedy effect and
\* return the entire reservation to the tenant budget.
W_NoReconciledNoEffect ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "proved_no_effect"
        /\ remedyReleased[r] = remedyAmount[r]
        /\ reconciliationAuthenticated[r])

\* Must fail: a remedy can succeed as a separate action while the original
\* effect remains claimed, executed, and unchanged.
W_NoSeparateSuccessfulRemedy ==
    ~(\E r \in Remedies :
        /\ remedyStatus[r] = "succeeded"
        /\ originalClaimed
        /\ originalExecuted
        /\ remedyCAID[r] # originalCAID
        /\ remedyActionID[r] # originalActionID
        /\ remedyOperationID[r] # originalOperationID)

\* Must fail: late revocation is reachable after a separate remedy succeeds;
\* neither the original effect nor consumed remedy accounting is erased.
W_NoLateRevocationAfterEffect ==
    ~(originalRevoked
      /\ originalClaimed
      /\ originalExecuted
      /\ (\E r \in Remedies :
            remedyStatus[r] = "succeeded" /\ remedyConsumed[r] > 0))

=============================================================================
