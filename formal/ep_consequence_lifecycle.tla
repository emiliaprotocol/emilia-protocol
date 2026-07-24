-------------------- MODULE ep_consequence_lifecycle --------------------
\* EMILIA Protocol - bounded composed consequence lifecycle.
\*
\* This model joins the safety boundaries that are otherwise easy to verify
\* only in isolation:
\*
\*   exact evidence admission -> approval -> escrow reservation
\*       -> provider invocation -> INDETERMINATE
\*       -> authenticated exact reconciliation -> terminal effect
\*       -> separately authorized remedy
\*
\* A second operation follows approval and reservation but is revoked before
\* provider start.  Refusal transitions record coverage without changing
\* business state.  This makes wrong-CAID admission, unauthenticated admission,
\* revoked invocation, blind replay, inexact reconciliation, terminal rewrite,
\* and effect-approval substitution as remedy authority mutation-resistant and
\* visible to TLC.
\*
\* Cryptographic verification is abstracted into fixed evidence attributes.
\* The model is finite, contains no wall clock or availability claim, and is
\* not an implementation refinement proof.

EXTENDS Naturals, FiniteSets

CONSTANTS
    ExecuteOp, RevokeOp,
    CaidExecute, CaidRevoke, CaidRemedy, CaidWrong,
    AdmissionExecute, AdmissionRevoke,
    AdmissionWrongCAID, AdmissionUnauthenticated,
    ApprovalExecute, ApprovalRevoke,
    ReconcileExecute, ReconcileWrongCAID,
    ReconcileWrongOperation, ReconcileWrongEffectDigest,
    ReconcileUnauthenticated,
    RemedyDecisionExecute, RemedyDecisionUnauthenticated,
    EffectDigestCorrect, EffectDigestWrong

Operations == {ExecuteOp, RevokeOp}
CAIDs == {CaidExecute, CaidRevoke, CaidRemedy, CaidWrong}

AdmissionEvidence == {
    AdmissionExecute,
    AdmissionRevoke,
    AdmissionWrongCAID,
    AdmissionUnauthenticated
}

ApprovalEvidence == {ApprovalExecute, ApprovalRevoke}

ReconciliationEvidence == {
    ReconcileExecute,
    ReconcileWrongCAID,
    ReconcileWrongOperation,
    ReconcileWrongEffectDigest,
    ReconcileUnauthenticated
}

RemedyDecisions == {
    RemedyDecisionExecute,
    RemedyDecisionUnauthenticated
}

AllEvidence ==
    AdmissionEvidence \union ApprovalEvidence
        \union ReconciliationEvidence \union RemedyDecisions

Stages == {
    "PROPOSED",
    "ADMITTED",
    "APPROVED",
    "RESERVED",
    "INVOKING",
    "INDETERMINATE",
    "EFFECT",
    "REVOKED"
}

EscrowStates == {"OPEN", "RESERVED", "CONSUMED", "RELEASED"}
RemedyStates == {"NONE", "AUTHORIZED", "APPLIED"}

NoEvidence == "NO_EVIDENCE"
NoDigest == "NO_DIGEST"
NoOperation == "NO_OPERATION"
NoCAID == "NO_CAID"

\* These events are both coverage witnesses and mutation-test observations.
RequiredCoverage == {
    "wrong_caid_admission_refused",
    "unauthenticated_admission_refused",
    "execute_admitted",
    "revoke_admitted",
    "execute_approved",
    "revoke_approved",
    "execute_escrow_reserved",
    "revoke_escrow_reserved",
    "revoked_before_start",
    "revoked_invocation_refused",
    "provider_invoked_once",
    "indeterminate_fenced",
    "blind_replay_refused",
    "wrong_caid_reconciliation_refused",
    "wrong_operation_reconciliation_refused",
    "wrong_effect_digest_reconciliation_refused",
    "unauthenticated_reconciliation_refused",
    "exact_reconciliation_accepted",
    "terminal_rewrite_refused",
    "effect_approval_as_remedy_refused",
    "unauthenticated_remedy_authority_refused",
    "separate_remedy_authorized",
    "remedy_applied"
}

MutationRefusalEvents == {
    "wrong_caid_admission_refused",
    "unauthenticated_admission_refused",
    "revoked_invocation_refused",
    "blind_replay_refused",
    "wrong_caid_reconciliation_refused",
    "wrong_operation_reconciliation_refused",
    "wrong_effect_digest_reconciliation_refused",
    "unauthenticated_reconciliation_refused",
    "terminal_rewrite_refused",
    "effect_approval_as_remedy_refused",
    "unauthenticated_remedy_authority_refused"
}

VARIABLES
    stage,
    caidOf,
    admittedBy,
    approvedBy,
    revoked,
    escrowState,
    invokeCount,
    reconciledBy,
    effectDigest,
    remedyState,
    remedyFor,
    remedyCAID,
    remedyDecision,
    coverage

AdmissionCAID(e) ==
    CASE e \in {AdmissionExecute, AdmissionUnauthenticated} -> CaidExecute
      [] e = AdmissionRevoke -> CaidRevoke
      [] e = AdmissionWrongCAID -> CaidWrong

AdmissionAuthenticated(e) == e # AdmissionUnauthenticated

ApprovalCAID(e) ==
    CASE e = ApprovalExecute -> CaidExecute
      [] e = ApprovalRevoke -> CaidRevoke

ReconciliationOperation(e) ==
    CASE e = ReconcileWrongOperation -> RevokeOp
      [] OTHER -> ExecuteOp

ReconciliationCAID(e) ==
    CASE e = ReconcileWrongCAID -> CaidWrong
      [] OTHER -> CaidExecute

ReconciliationAuthenticated(e) == e # ReconcileUnauthenticated
ReconciliationDigest(e) ==
    IF e = ReconcileWrongEffectDigest
    THEN EffectDigestWrong
    ELSE EffectDigestCorrect

RemedyDecisionOperation(d) == ExecuteOp
RemedyDecisionCAID(d) == CaidRemedy
RemedyDecisionAuthenticated(d) == d # RemedyDecisionUnauthenticated

ValidAdmission(o, e) ==
    /\ e \in AdmissionEvidence
    /\ AdmissionAuthenticated(e)
    /\ AdmissionCAID(e) = caidOf[o]

ValidApproval(o, e) ==
    /\ e \in ApprovalEvidence
    /\ ApprovalCAID(e) = caidOf[o]

ValidReconciliation(o, e) ==
    /\ e \in ReconciliationEvidence
    /\ ReconciliationAuthenticated(e)
    /\ ReconciliationOperation(e) = o
    /\ ReconciliationCAID(e) = caidOf[o]
    /\ ReconciliationDigest(e) = EffectDigestCorrect

ValidRemedyDecision(d) ==
    /\ d \in RemedyDecisions
    /\ RemedyDecisionAuthenticated(d)
    /\ RemedyDecisionOperation(d) = ExecuteOp
    /\ RemedyDecisionCAID(d) = CaidRemedy

AdmissionRefusalEvent(e) ==
    CASE e = AdmissionWrongCAID -> "wrong_caid_admission_refused"
      [] e = AdmissionUnauthenticated
           -> "unauthenticated_admission_refused"

ReconciliationRefusalEvent(e) ==
    CASE e = ReconcileWrongCAID
           -> "wrong_caid_reconciliation_refused"
      [] e = ReconcileWrongOperation
           -> "wrong_operation_reconciliation_refused"
      [] e = ReconcileWrongEffectDigest
           -> "wrong_effect_digest_reconciliation_refused"
      [] e = ReconcileUnauthenticated
           -> "unauthenticated_reconciliation_refused"

AdmissionCoverage(o) ==
    IF o = ExecuteOp THEN "execute_admitted" ELSE "revoke_admitted"

ApprovalCoverage(o) ==
    IF o = ExecuteOp THEN "execute_approved" ELSE "revoke_approved"

ReservationCoverage(o) ==
    IF o = ExecuteOp
    THEN "execute_escrow_reserved"
    ELSE "revoke_escrow_reserved"

workflowVars == <<
    stage,
    caidOf,
    admittedBy,
    approvedBy,
    revoked,
    escrowState,
    invokeCount,
    reconciledBy,
    effectDigest
>>

remedyVars == <<
    remedyState,
    remedyFor,
    remedyCAID,
    remedyDecision
>>

businessVars == <<workflowVars, remedyVars>>
vars == <<businessVars, coverage>>

\* ---------------------------------------------------------------------
\* State invariants.
\* ---------------------------------------------------------------------

ModelShape ==
    /\ Cardinality(Operations) = 2
    /\ Cardinality(CAIDs) = 4
    /\ Cardinality(AdmissionEvidence) = 4
    /\ Cardinality(ApprovalEvidence) = 2
    /\ Cardinality(ReconciliationEvidence) = 5
    /\ Cardinality(RemedyDecisions) = 2
    /\ NoEvidence \notin AllEvidence
    /\ NoDigest # EffectDigestCorrect
    /\ NoDigest # EffectDigestWrong
    /\ EffectDigestCorrect # EffectDigestWrong
    /\ NoOperation \notin Operations
    /\ NoCAID \notin CAIDs

TypeInvariant ==
    /\ stage \in [Operations -> Stages]
    /\ caidOf \in [Operations -> CAIDs]
    /\ admittedBy \in
         [Operations -> AdmissionEvidence \union {NoEvidence}]
    /\ approvedBy \in
         [Operations -> ApprovalEvidence \union {NoEvidence}]
    /\ revoked \in [Operations -> BOOLEAN]
    /\ escrowState \in [Operations -> EscrowStates]
    /\ invokeCount \in [Operations -> 0..2]
    /\ reconciledBy \in
         [Operations -> ReconciliationEvidence \union {NoEvidence}]
    /\ effectDigest \in
         [Operations -> {EffectDigestCorrect, EffectDigestWrong, NoDigest}]
    /\ remedyState \in RemedyStates
    /\ remedyFor \in Operations \union {NoOperation}
    /\ remedyCAID \in CAIDs \union {NoCAID}
    /\ remedyDecision \in RemedyDecisions \union {NoEvidence}
    /\ coverage \subseteq RequiredCoverage

ExactCAIDBindings ==
    /\ caidOf[ExecuteOp] = CaidExecute
    /\ caidOf[RevokeOp] = CaidRevoke
    /\ CaidRemedy # caidOf[ExecuteOp]
    /\ CaidRemedy # caidOf[RevokeOp]

AuthenticatedExactAdmission ==
    \A o \in Operations :
        admittedBy[o] # NoEvidence =>
            ValidAdmission(o, admittedBy[o])

ExactApproval ==
    \A o \in Operations :
        approvedBy[o] # NoEvidence =>
            /\ admittedBy[o] # NoEvidence
            /\ ValidApproval(o, approvedBy[o])

LifecycleConsistency ==
    \A o \in Operations :
        CASE stage[o] = "PROPOSED" ->
                 /\ admittedBy[o] = NoEvidence
                 /\ approvedBy[o] = NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "OPEN"
                 /\ invokeCount[o] = 0
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "ADMITTED" ->
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] = NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "OPEN"
                 /\ invokeCount[o] = 0
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "APPROVED" ->
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "OPEN"
                 /\ invokeCount[o] = 0
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "RESERVED" ->
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "RESERVED"
                 /\ invokeCount[o] = 0
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "INVOKING" ->
                 /\ o = ExecuteOp
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "RESERVED"
                 /\ invokeCount[o] = 1
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "INDETERMINATE" ->
                 /\ o = ExecuteOp
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "RESERVED"
                 /\ invokeCount[o] = 1
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest
          [] stage[o] = "EFFECT" ->
                 /\ o = ExecuteOp
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ ~revoked[o]
                 /\ escrowState[o] = "CONSUMED"
                 /\ invokeCount[o] = 1
                 /\ reconciledBy[o] # NoEvidence
                 /\ effectDigest[o] = EffectDigestCorrect
          [] stage[o] = "REVOKED" ->
                 /\ o = RevokeOp
                 /\ admittedBy[o] # NoEvidence
                 /\ approvedBy[o] # NoEvidence
                 /\ revoked[o]
                 /\ escrowState[o] = "RELEASED"
                 /\ invokeCount[o] = 0
                 /\ reconciledBy[o] = NoEvidence
                 /\ effectDigest[o] = NoDigest

EscrowPrecedesProvider ==
    \A o \in Operations :
        invokeCount[o] > 0 =>
            /\ "execute_escrow_reserved" \in coverage
            /\ escrowState[o] \in {"RESERVED", "CONSUMED"}

InvokeAtMostOnce ==
    \A o \in Operations : invokeCount[o] <= 1

RevocationBeforeStartSafe ==
    /\ stage[RevokeOp] = "REVOKED" =>
          /\ revoked[RevokeOp]
          /\ invokeCount[RevokeOp] = 0
          /\ escrowState[RevokeOp] = "RELEASED"
          /\ effectDigest[RevokeOp] = NoDigest
          /\ reconciledBy[RevokeOp] = NoEvidence

AuthenticatedExactReconciliation ==
    \A o \in Operations :
        reconciledBy[o] # NoEvidence =>
            /\ stage[o] = "EFFECT"
            /\ ValidReconciliation(o, reconciledBy[o])
            /\ ReconciliationDigest(reconciledBy[o]) = effectDigest[o]

TerminalEffectSound ==
    stage[ExecuteOp] = "EFFECT" =>
        /\ reconciledBy[ExecuteOp] = ReconcileExecute
        /\ effectDigest[ExecuteOp] = EffectDigestCorrect
        /\ escrowState[ExecuteOp] = "CONSUMED"
        /\ invokeCount[ExecuteOp] = 1

SeparateRemedyAuthority ==
    CASE remedyState = "NONE" ->
             /\ remedyFor = NoOperation
             /\ remedyCAID = NoCAID
             /\ remedyDecision = NoEvidence
      [] remedyState \in {"AUTHORIZED", "APPLIED"} ->
             /\ stage[ExecuteOp] = "EFFECT"
             /\ remedyFor = ExecuteOp
             /\ remedyCAID = CaidRemedy
             /\ remedyCAID # caidOf[ExecuteOp]
             /\ ValidRemedyDecision(remedyDecision)
             /\ remedyDecision \notin ApprovalEvidence

\* Coverage facts retain enough immutable evidence to make the bounded witness
\* meaningful even after the lifecycle advances beyond the named event.
CoverageSound ==
    /\ ("execute_admitted" \in coverage =>
          admittedBy[ExecuteOp] = AdmissionExecute)
    /\ ("revoke_admitted" \in coverage =>
          admittedBy[RevokeOp] = AdmissionRevoke)
    /\ ("execute_approved" \in coverage =>
          approvedBy[ExecuteOp] = ApprovalExecute)
    /\ ("revoke_approved" \in coverage =>
          approvedBy[RevokeOp] = ApprovalRevoke)
    /\ ("execute_escrow_reserved" \in coverage =>
          escrowState[ExecuteOp] \in {"RESERVED", "CONSUMED"})
    /\ ("revoke_escrow_reserved" \in coverage =>
          escrowState[RevokeOp] \in {"RESERVED", "RELEASED"})
    /\ ("revoked_before_start" \in coverage =>
          stage[RevokeOp] = "REVOKED")
    /\ ("provider_invoked_once" \in coverage =>
          invokeCount[ExecuteOp] = 1)
    /\ ("indeterminate_fenced" \in coverage =>
          invokeCount[ExecuteOp] = 1)
    /\ ("exact_reconciliation_accepted" \in coverage =>
          /\ stage[ExecuteOp] = "EFFECT"
          /\ reconciledBy[ExecuteOp] = ReconcileExecute)
    /\ ("separate_remedy_authorized" \in coverage =>
          remedyState \in {"AUTHORIZED", "APPLIED"})
    /\ ("remedy_applied" \in coverage => remedyState = "APPLIED")

\* ---------------------------------------------------------------------
\* Initial state.
\* ---------------------------------------------------------------------

Init ==
    /\ stage = [o \in Operations |-> "PROPOSED"]
    /\ caidOf =
         [o \in Operations |->
             IF o = ExecuteOp THEN CaidExecute ELSE CaidRevoke]
    /\ admittedBy = [o \in Operations |-> NoEvidence]
    /\ approvedBy = [o \in Operations |-> NoEvidence]
    /\ revoked = [o \in Operations |-> FALSE]
    /\ escrowState = [o \in Operations |-> "OPEN"]
    /\ invokeCount = [o \in Operations |-> 0]
    /\ reconciledBy = [o \in Operations |-> NoEvidence]
    /\ effectDigest = [o \in Operations |-> NoDigest]
    /\ remedyState = "NONE"
    /\ remedyFor = NoOperation
    /\ remedyCAID = NoCAID
    /\ remedyDecision = NoEvidence
    /\ coverage = {}

\* ---------------------------------------------------------------------
\* Accepted lifecycle transitions.
\* ---------------------------------------------------------------------

Admit(o, e) ==
    /\ stage[o] = "PROPOSED"
    /\ ValidAdmission(o, e)
    /\ IF o = ExecuteOp
       THEN {"wrong_caid_admission_refused",
             "unauthenticated_admission_refused"} \subseteq coverage
       ELSE TRUE
    /\ stage' = [stage EXCEPT ![o] = "ADMITTED"]
    /\ admittedBy' = [admittedBy EXCEPT ![o] = e]
    /\ coverage' = coverage \union {AdmissionCoverage(o)}
    /\ UNCHANGED <<
         caidOf, approvedBy, revoked, escrowState, invokeCount,
         reconciledBy, effectDigest, remedyVars
       >>

Approve(o, e) ==
    /\ stage[o] = "ADMITTED"
    /\ ValidApproval(o, e)
    /\ stage' = [stage EXCEPT ![o] = "APPROVED"]
    /\ approvedBy' = [approvedBy EXCEPT ![o] = e]
    /\ coverage' = coverage \union {ApprovalCoverage(o)}
    /\ UNCHANGED <<
         caidOf, admittedBy, revoked, escrowState, invokeCount,
         reconciledBy, effectDigest, remedyVars
       >>

ReserveEscrow(o) ==
    /\ stage[o] = "APPROVED"
    /\ ~revoked[o]
    /\ escrowState[o] = "OPEN"
    /\ stage' = [stage EXCEPT ![o] = "RESERVED"]
    /\ escrowState' = [escrowState EXCEPT ![o] = "RESERVED"]
    /\ coverage' = coverage \union {ReservationCoverage(o)}
    /\ UNCHANGED <<
         caidOf, admittedBy, approvedBy, revoked, invokeCount,
         reconciledBy, effectDigest, remedyVars
       >>

RevokeBeforeStart ==
    /\ stage[RevokeOp] = "RESERVED"
    /\ invokeCount[RevokeOp] = 0
    /\ stage' = [stage EXCEPT ![RevokeOp] = "REVOKED"]
    /\ revoked' = [revoked EXCEPT ![RevokeOp] = TRUE]
    /\ escrowState' =
         [escrowState EXCEPT ![RevokeOp] = "RELEASED"]
    /\ coverage' = coverage \union {"revoked_before_start"}
    /\ UNCHANGED <<
         caidOf, admittedBy, approvedBy, invokeCount,
         reconciledBy, effectDigest, remedyVars
       >>

InvokeProvider ==
    /\ stage[ExecuteOp] = "RESERVED"
    /\ ~revoked[ExecuteOp]
    /\ escrowState[ExecuteOp] = "RESERVED"
    /\ invokeCount[ExecuteOp] = 0
    /\ stage' = [stage EXCEPT ![ExecuteOp] = "INVOKING"]
    /\ invokeCount' = [invokeCount EXCEPT ![ExecuteOp] = 1]
    /\ coverage' = coverage \union {"provider_invoked_once"}
    /\ UNCHANGED <<
         caidOf, admittedBy, approvedBy, revoked, escrowState,
         reconciledBy, effectDigest, remedyVars
       >>

MarkIndeterminate ==
    /\ stage[ExecuteOp] = "INVOKING"
    /\ invokeCount[ExecuteOp] = 1
    /\ stage' = [stage EXCEPT ![ExecuteOp] = "INDETERMINATE"]
    /\ coverage' = coverage \union {"indeterminate_fenced"}
    /\ UNCHANGED <<
         caidOf, admittedBy, approvedBy, revoked, escrowState,
         invokeCount, reconciledBy, effectDigest, remedyVars
       >>

ReconcileExact(e) ==
    /\ stage[ExecuteOp] = "INDETERMINATE"
    /\ ValidReconciliation(ExecuteOp, e)
    /\ {
         "blind_replay_refused",
         "wrong_caid_reconciliation_refused",
         "wrong_operation_reconciliation_refused",
         "wrong_effect_digest_reconciliation_refused",
         "unauthenticated_reconciliation_refused"
       } \subseteq coverage
    /\ stage' = [stage EXCEPT ![ExecuteOp] = "EFFECT"]
    /\ escrowState' =
         [escrowState EXCEPT ![ExecuteOp] = "CONSUMED"]
    /\ reconciledBy' = [reconciledBy EXCEPT ![ExecuteOp] = e]
    /\ effectDigest' =
         [effectDigest EXCEPT
             ![ExecuteOp] = ReconciliationDigest(e)]
    /\ coverage' =
         coverage \union {"exact_reconciliation_accepted"}
    /\ UNCHANGED <<
         caidOf, admittedBy, approvedBy, revoked, invokeCount, remedyVars
       >>

AuthorizeRemedy(d) ==
    /\ stage[ExecuteOp] = "EFFECT"
    /\ remedyState = "NONE"
    /\ ValidRemedyDecision(d)
    /\ {
         "terminal_rewrite_refused",
         "effect_approval_as_remedy_refused",
         "unauthenticated_remedy_authority_refused"
       } \subseteq coverage
    /\ remedyState' = "AUTHORIZED"
    /\ remedyFor' = ExecuteOp
    /\ remedyCAID' = CaidRemedy
    /\ remedyDecision' = d
    /\ coverage' = coverage \union {"separate_remedy_authorized"}
    /\ UNCHANGED workflowVars

ApplyRemedy ==
    /\ remedyState = "AUTHORIZED"
    /\ ValidRemedyDecision(remedyDecision)
    /\ remedyState' = "APPLIED"
    /\ coverage' = coverage \union {"remedy_applied"}
    /\ UNCHANGED <<workflowVars, remedyFor, remedyCAID, remedyDecision>>

\* ---------------------------------------------------------------------
\* Explicit mutation attempts.  Only the coverage witness may change.
\* ---------------------------------------------------------------------

RefuseInvalidAdmission(e) ==
    /\ stage[ExecuteOp] = "PROPOSED"
    /\ e \in {AdmissionWrongCAID, AdmissionUnauthenticated}
    /\ ~ValidAdmission(ExecuteOp, e)
    /\ AdmissionRefusalEvent(e) \notin coverage
    /\ coverage' = coverage \union {AdmissionRefusalEvent(e)}
    /\ UNCHANGED businessVars

RefuseRevokedInvocation ==
    /\ stage[RevokeOp] = "REVOKED"
    /\ "revoked_invocation_refused" \notin coverage
    /\ coverage' = coverage \union {"revoked_invocation_refused"}
    /\ UNCHANGED businessVars

RefuseBlindReplay ==
    /\ stage[ExecuteOp] = "INDETERMINATE"
    /\ invokeCount[ExecuteOp] = 1
    /\ "blind_replay_refused" \notin coverage
    /\ coverage' = coverage \union {"blind_replay_refused"}
    /\ UNCHANGED businessVars

RefuseInvalidReconciliation(e) ==
    /\ stage[ExecuteOp] = "INDETERMINATE"
    /\ e \in {
         ReconcileWrongCAID,
         ReconcileWrongOperation,
         ReconcileWrongEffectDigest,
         ReconcileUnauthenticated
       }
    /\ ~ValidReconciliation(ExecuteOp, e)
    /\ ReconciliationRefusalEvent(e) \notin coverage
    /\ coverage' =
         coverage \union {ReconciliationRefusalEvent(e)}
    /\ UNCHANGED businessVars

RefuseTerminalRewrite ==
    /\ stage[ExecuteOp] = "EFFECT"
    /\ "terminal_rewrite_refused" \notin coverage
    /\ coverage' = coverage \union {"terminal_rewrite_refused"}
    /\ UNCHANGED businessVars

RefuseEffectApprovalAsRemedyAuthority ==
    /\ stage[ExecuteOp] = "EFFECT"
    /\ approvedBy[ExecuteOp] = ApprovalExecute
    /\ remedyState = "NONE"
    /\ "effect_approval_as_remedy_refused" \notin coverage
    /\ coverage' =
         coverage \union {"effect_approval_as_remedy_refused"}
    /\ UNCHANGED businessVars

RefuseUnauthenticatedRemedyAuthority ==
    /\ stage[ExecuteOp] = "EFFECT"
    /\ remedyState = "NONE"
    /\ ~ValidRemedyDecision(RemedyDecisionUnauthenticated)
    /\ "unauthenticated_remedy_authority_refused" \notin coverage
    /\ coverage' =
         coverage \union {"unauthenticated_remedy_authority_refused"}
    /\ UNCHANGED businessVars

\* Deliberately unsafe, excluded from Next. The selected-trace refinement
\* harness requires TLC to falsify InvokeAtMostOnce while the runtime refuses
\* the same replay after an indeterminate provider result.
UnsafeBlindReplay ==
    /\ stage[ExecuteOp] = "INDETERMINATE"
    /\ invokeCount[ExecuteOp] = 1
    /\ invokeCount' = [invokeCount EXCEPT ![ExecuteOp] = 2]
    /\ UNCHANGED <<
         stage,
         caidOf,
         admittedBy,
         approvedBy,
         revoked,
         escrowState,
         reconciledBy,
         effectDigest,
         remedyVars,
         coverage
       >>

Next ==
    \/ \E o \in Operations, e \in AdmissionEvidence : Admit(o, e)
    \/ \E o \in Operations, e \in ApprovalEvidence : Approve(o, e)
    \/ \E o \in Operations : ReserveEscrow(o)
    \/ RevokeBeforeStart
    \/ InvokeProvider
    \/ MarkIndeterminate
    \/ \E e \in ReconciliationEvidence : ReconcileExact(e)
    \/ \E d \in RemedyDecisions : AuthorizeRemedy(d)
    \/ ApplyRemedy
    \/ \E e \in AdmissionEvidence : RefuseInvalidAdmission(e)
    \/ RefuseRevokedInvocation
    \/ RefuseBlindReplay
    \/ \E e \in ReconciliationEvidence :
         RefuseInvalidReconciliation(e)
    \/ RefuseTerminalRewrite
    \/ RefuseEffectApprovalAsRemedyAuthority
    \/ RefuseUnauthenticatedRemedyAuthority

\* Weak fairness excludes infinite stuttering while one of the finite,
\* monotonic lifecycle or refusal-witness transitions remains enabled.
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ---------------------------------------------------------------------
\* Transition and reachability properties.
\* ---------------------------------------------------------------------

CoverageMonotonic ==
    [][coverage \subseteq coverage']_vars

CAIDBindingImmutable ==
    [][caidOf' = caidOf]_vars

EvidenceBindingsImmutable ==
    [][\A o \in Operations :
          /\ (admittedBy[o] # NoEvidence =>
                admittedBy'[o] = admittedBy[o])
          /\ (approvedBy[o] # NoEvidence =>
                approvedBy'[o] = approvedBy[o])
          /\ (reconciledBy[o] # NoEvidence =>
                reconciledBy'[o] = reconciledBy[o])]_vars

\* Every modeled hostile input produces a distinct successor state, but the
\* complete business state must remain byte-for-byte abstractly unchanged.
MutationRefusalsDoNotMutate ==
    [][((coverage' \ coverage) \intersect MutationRefusalEvents # {})
          => businessVars' = businessVars]_vars

InvocationCountMonotonic ==
    [][\A o \in Operations :
          invokeCount'[o] >= invokeCount[o]]_vars

NoBlindReplayWhileIndeterminate ==
    [][stage[ExecuteOp] = "INDETERMINATE" =>
          invokeCount'[ExecuteOp] = invokeCount[ExecuteOp]]_vars

RevokedOperationCannotStart ==
    [][stage[RevokeOp] = "REVOKED" =>
          /\ stage'[RevokeOp] = "REVOKED"
          /\ invokeCount'[RevokeOp] = 0
          /\ effectDigest'[RevokeOp] = NoDigest]_vars

TerminalEffectImmutable ==
    [][stage[ExecuteOp] = "EFFECT" =>
          /\ stage'[ExecuteOp] = "EFFECT"
          /\ escrowState'[ExecuteOp] = escrowState[ExecuteOp]
          /\ invokeCount'[ExecuteOp] = invokeCount[ExecuteOp]
          /\ reconciledBy'[ExecuteOp] = reconciledBy[ExecuteOp]
          /\ effectDigest'[ExecuteOp] = effectDigest[ExecuteOp]]_vars

RemedyAuthorizationTransitionSeparate ==
    [][remedyState = "NONE" /\ remedyState' = "AUTHORIZED" =>
          /\ remedyFor' = ExecuteOp
          /\ remedyCAID' = CaidRemedy
          /\ remedyCAID' # caidOf[ExecuteOp]
          /\ ValidRemedyDecision(remedyDecision')
          /\ remedyDecision' \notin ApprovalEvidence]_vars

RemedyCannotRewriteTerminalEffect ==
    [][remedyState' # remedyState =>
          /\ stage'[ExecuteOp] = stage[ExecuteOp]
          /\ escrowState'[ExecuteOp] = escrowState[ExecuteOp]
          /\ invokeCount'[ExecuteOp] = invokeCount[ExecuteOp]
          /\ reconciledBy'[ExecuteOp] = reconciledBy[ExecuteOp]
          /\ effectDigest'[ExecuteOp] = effectDigest[ExecuteOp]]_vars

\* This is an explicit bounded reachability obligation, not just an invariant:
\* every fair maximal behavior reaches the complete accepted/refused witness.
FullLifecycleCoverageEventually ==
    <>(coverage = RequiredCoverage)

THEOREM Spec => []ModelShape
THEOREM Spec => []TypeInvariant
THEOREM Spec => []ExactCAIDBindings
THEOREM Spec => []AuthenticatedExactAdmission
THEOREM Spec => []ExactApproval
THEOREM Spec => []LifecycleConsistency
THEOREM Spec => []EscrowPrecedesProvider
THEOREM Spec => []InvokeAtMostOnce
THEOREM Spec => []RevocationBeforeStartSafe
THEOREM Spec => []AuthenticatedExactReconciliation
THEOREM Spec => []TerminalEffectSound
THEOREM Spec => []SeparateRemedyAuthority
THEOREM Spec => []CoverageSound
THEOREM Spec => CoverageMonotonic
THEOREM Spec => CAIDBindingImmutable
THEOREM Spec => EvidenceBindingsImmutable
THEOREM Spec => MutationRefusalsDoNotMutate
THEOREM Spec => InvocationCountMonotonic
THEOREM Spec => NoBlindReplayWhileIndeterminate
THEOREM Spec => RevokedOperationCannotStart
THEOREM Spec => TerminalEffectImmutable
THEOREM Spec => RemedyAuthorizationTransitionSeparate
THEOREM Spec => RemedyCannotRewriteTerminalEffect
THEOREM Spec => FullLifecycleCoverageEventually

=======================================================================
