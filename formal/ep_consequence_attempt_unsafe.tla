------------------ MODULE ep_consequence_attempt_unsafe -------------------
\* Deliberately weakened load-bearing check.
\*
\* UnsafeSpec adds one forbidden transition: it blindly invokes an attempt
\* again while INDETERMINATE. TLC MUST falsify InvokeAtMostOnce. This is not an
\* alternate protocol design; it is the single negative model demonstrating
\* that the no-replay guard is load-bearing.

EXTENDS ep_consequence_attempt

BlindReplayWhileIndeterminate(a) ==
    /\ a \in allocated
    /\ attemptState[a] = "INDETERMINATE"
    /\ invokeCount' = [invokeCount EXCEPT ![a] = @ + 1]
    /\ UNCHANGED <<
         allocated, attemptState, requestOf, aebState, ownerOf,
         ownerGeneration, staleOwners, leaseStale, providerEntered,
         effectMayHaveHappened, pendingCommitEvidence,
         reconciliationEvidence
       >>

UnsafeNext ==
    \/ Next
    \/ \E a \in AttemptIds : BlindReplayWhileIndeterminate(a)

UnsafeSpec == Init /\ [][UnsafeNext]_vars

=============================================================================
