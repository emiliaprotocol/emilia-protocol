-------------------- MODULE ep_trust_program_witness --------------------
\* Reachability/non-vacuity witnesses for ep_trust_program.
\*
\* Each operator is the negation of an interesting reachable-state claim.
\* Checking one as an INVARIANT must fail.  The counterexample trace proves the
\* corresponding behavior is represented by the bounded model.

EXTENDS ep_trust_program, FiniteSets

\* Must fail: satisfying identity unlocks both parallel branches together.
W_NoParallelBranches ==
    ~(stageStatus[ScreeningStage] = "collecting"
      /\ stageStatus[LegalStage] = "collecting")

\* Must fail: the 2-of-3 stage can hold exactly one accepted approval while
\* execution remains locked and unowned.
W_NoPartialThreshold ==
    ~(programStatus = "active"
      /\ ApprovalCountIn(seatEvidence, ApprovalStage) = 1
      /\ stageStatus[ApprovalStage] = "collecting"
      /\ executionStatus = "locked"
      /\ claimCount = 0)

\* Must fail: globally consumed evidence is represented by a real assignment.
W_NoEvidenceAccepted ==
    usedEvidence = {}

\* Must fail: all exact execution dependencies can satisfy and make execution
\* authority ready without yet assigning it to an owner.
W_NoExecutionReady ==
    executionStatus # "ready"

\* Must fail: exactly one owner can acquire the execution claim.
W_NoExecutionClaim ==
    ~(executionStatus = "claimed"
      /\ claimCount = 1
      /\ claimOwner \in Owners)

\* Must fail: the effect result can become indeterminate and fenced.
W_NoIndeterminateFence ==
    executionStatus # "indeterminate"

\* Must fail: authenticated reconciliation can conclude that execution
\* occurred after an indeterminate owner finalization.
W_NoReconciledExecution ==
    ~(executionStatus = "executed"
      /\ terminalSource = "authenticated_reconciliation"
      /\ reconciliationAuthenticated)

\* Must fail: authenticated reconciliation can instead prove no effect.
W_NoProvedNoEffect ==
    executionStatus # "proved_no_effect"

\* Must fail: invalidation can close an in-flight program.
W_NoInvalidation ==
    programStatus # "invalidated"

\* Must fail: invalidation preserves an already owned claim so effect accounting
\* may finish, while all program stages remain permanently invalidated.
W_NoInvalidatedClaim ==
    ~(programStatus = "invalidated"
      /\ executionStatus = "claimed"
      /\ claimCount = 1
      /\ \A s \in Stages : stageStatus[s] = "invalidated")

\* Must fail: conclusive effect truth survives program invalidation (whether it
\* was established immediately before or through the preserved in-flight path).
W_NoTerminalThenInvalidated ==
    ~(programStatus = "invalidated"
      /\ executionStatus \in ReconciledTerminalStates)

=============================================================================
