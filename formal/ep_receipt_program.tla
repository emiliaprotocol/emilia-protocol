---------------------- MODULE ep_receipt_program ----------------------
\* EP Receipt Program — bounded execution-lifecycle model
\*
\* This model is a control-flow abstraction of
\* packages/gate/src/receipt-program.ts createReceiptProgramKernel().run()
\* composed with the capability-backed Gate path in
\* packages/gate/src/capability-receipt.ts executeWithCapability().
\*
\* The modeled happy path is:
\*   RECEIPT -> MATCH -> RESERVE -> EXECUTE -> COMMIT -> CERTIFY
\*
\* The safety-critical alternatives are also modeled:
\*   - invalid or mismatched programs refuse before reservation/effect;
\*   - a second attempt sharing the operation id refuses while the first
\*     reservation is in flight or after it is committed;
\*   - provider failure/timeout/projection failure commits indeterminate when
\*     possible, and otherwise leaves the reservation locked;
\*   - missing execution evidence prevents an executed/indeterminate
\*     certificate rather than manufacturing proof;
\*   - signing/persistence failure preserves the Gate outcome without
\*     reopening authority; and
\*   - terminal attempts and committed operations do not reverse.
\*
\* BOUNDED SCOPE: the CI configuration uses two attempts contending for one
\* stable operation id. TLC exhaustively explores this finite abstraction. It
\* does not prove the TypeScript implementation, database linearizability,
\* cryptographic signatures, canonical JSON, CAID collision resistance,
\* provider truth, wall-clock deadlines, liveness, or arbitrary numbers of
\* attempts/operations. See CONSERVATION_OF_AUTHORITY.md and PROOF_STATUS.md.

EXTENDS FiniteSets, Naturals

CONSTANTS Attempts

NoAttempt == "no_attempt"

AttemptPhases == {
    "receipt",
    "matched",
    "reserved",
    "executing",
    "effect_returned",
    "certifying",
    "terminal"
}

AttemptOutcomes == {"none", "refused", "executed", "indeterminate"}

AttemptReasons == {
    "none",
    "program_invalid",
    "match_failed",
    "gate_refused",
    "operation_in_flight",
    "operation_already_committed",
    "effect_indeterminate",
    "execution_evidence_unavailable",
    "certificate_signing_failed",
    "certificate_persistence_failed"
}

CertificateStates == {"none", "signed", "persisted"}
OperationStates == {"open", "reserved", "committed"}
OperationOutcomes == {"none", "executed", "indeterminate"}

VARIABLES
    phase,                \* [Attempts -> AttemptPhases]
    outcome,              \* [Attempts -> AttemptOutcomes]
    reason,               \* [Attempts -> AttemptReasons]
    matched,              \* program + operation + CAID/digest binding matched
    authorized,           \* Gate allowed the capability-backed action
    reserveWon,           \* this attempt atomically created the operation row
    effectEntered,        \* provider callback was entered
    commitAttempted,      \* terminal capability commit was attempted
    executionEvidence,    \* exact execution evidence was durably available
    certState,            \* none, signed-but-unpersisted, or persisted
    certResultPresent,    \* certificate contains a bounded result projection
    opStatus,             \* one shared stable operation id
    opOutcome,            \* terminal store outcome, if committed
    opOwner               \* attempt holding/owning the operation reservation

vars == <<
    phase,
    outcome,
    reason,
    matched,
    authorized,
    reserveWon,
    effectEntered,
    commitAttempted,
    executionEvidence,
    certState,
    certResultPresent,
    opStatus,
    opOutcome,
    opOwner
>>

BoolMap == [Attempts -> BOOLEAN]

\* ---------------------------------------------------------------------
\* Initial state
\* ---------------------------------------------------------------------

Init ==
    /\ Attempts # {}
    /\ phase = [a \in Attempts |-> "receipt"]
    /\ outcome = [a \in Attempts |-> "none"]
    /\ reason = [a \in Attempts |-> "none"]
    /\ matched = [a \in Attempts |-> FALSE]
    /\ authorized = [a \in Attempts |-> FALSE]
    /\ reserveWon = [a \in Attempts |-> FALSE]
    /\ effectEntered = [a \in Attempts |-> FALSE]
    /\ commitAttempted = [a \in Attempts |-> FALSE]
    /\ executionEvidence = [a \in Attempts |-> FALSE]
    /\ certState = [a \in Attempts |-> "none"]
    /\ certResultPresent = [a \in Attempts |-> FALSE]
    /\ opStatus = "open"
    /\ opOutcome = "none"
    /\ opOwner = NoAttempt

\* ---------------------------------------------------------------------
\* Receipt validation and exact program matching
\* ---------------------------------------------------------------------

Match(a) ==
    /\ phase[a] = "receipt"
    /\ phase' = [phase EXCEPT ![a] = "matched"]
    /\ matched' = [matched EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<
        outcome, reason, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

\* Malformed input, runtime trust injection, operation relabeling, CAID
\* mismatch, or asynchronous CAID resolution: effect is never entered.
RefuseBeforeMatch(a, refusalReason) ==
    /\ phase[a] = "receipt"
    /\ refusalReason \in {"program_invalid", "match_failed"}
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "refused"]
    /\ reason' = [reason EXCEPT ![a] = refusalReason]
    /\ UNCHANGED <<
        matched, authorized, reserveWon, effectEntered, commitAttempted,
        executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

\* Gate/base-receipt/capability checks can refuse after exact program matching
\* but before the atomic operation reservation.
GateRefuse(a) ==
    /\ phase[a] = "matched"
    /\ opStatus = "open"
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "refused"]
    /\ reason' = [reason EXCEPT ![a] = "gate_refused"]
    /\ UNCHANGED <<
        matched, authorized, reserveWon, effectEntered, commitAttempted,
        executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

\* A request using an already-owned operation id fails closed. The owner may
\* be executing, may be locked after an uncertain commit, or may be committed.
ReplayRefuse(a) ==
    /\ phase[a] = "matched"
    /\ opStatus # "open"
    /\ opOwner # a
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "refused"]
    /\ reason' = [reason EXCEPT ![a] =
        IF opStatus = "reserved"
        THEN "operation_in_flight"
        ELSE "operation_already_committed"]
    /\ UNCHANGED <<
        matched, authorized, reserveWon, effectEntered, commitAttempted,
        executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

\* ---------------------------------------------------------------------
\* Atomic reserve, provider entry, and terminal capability commit
\* ---------------------------------------------------------------------

Reserve(a) ==
    /\ phase[a] = "matched"
    /\ opStatus = "open"
    /\ phase' = [phase EXCEPT ![a] = "reserved"]
    /\ authorized' = [authorized EXCEPT ![a] = TRUE]
    /\ reserveWon' = [reserveWon EXCEPT ![a] = TRUE]
    /\ opStatus' = "reserved"
    /\ opOwner' = a
    /\ UNCHANGED <<
        outcome, reason, matched, effectEntered, commitAttempted,
        executionEvidence, certState, certResultPresent, opOutcome
        >>

Execute(a) ==
    /\ phase[a] = "reserved"
    /\ opStatus = "reserved"
    /\ opOwner = a
    /\ phase' = [phase EXCEPT ![a] = "executing"]
    /\ effectEntered' = [effectEntered EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<
        outcome, reason, matched, authorized, reserveWon, commitAttempted,
        executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

ProviderReturns(a) ==
    /\ phase[a] = "executing"
    /\ phase' = [phase EXCEPT ![a] = "effect_returned"]
    /\ UNCHANGED <<
        outcome, reason, matched, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

\* Successful provider return followed by a successful capability commit.
\* ev models whether the subsequent execution-evidence append is available.
CommitExecuted(a, ev) ==
    /\ phase[a] = "effect_returned"
    /\ opStatus = "reserved"
    /\ opOwner = a
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "executed"]
    /\ commitAttempted' = [commitAttempted EXCEPT ![a] = TRUE]
    /\ executionEvidence' = [executionEvidence EXCEPT ![a] = ev]
    /\ certResultPresent' = [certResultPresent EXCEPT ![a] = TRUE]
    /\ opStatus' = "committed"
    /\ opOutcome' = "executed"
    /\ UNCHANGED <<
        reason, matched, authorized, reserveWon, effectEntered,
        certState, opOwner
        >>

\* The provider returned, but the store could not prove the terminal commit.
\* The reservation remains ownership-fenced and replay-blocking. The receipt
\* program reports indeterminate and never certifies the provider result.
CommitExecutedUncertain(a, ev) ==
    /\ phase[a] = "effect_returned"
    /\ opStatus = "reserved"
    /\ opOwner = a
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "indeterminate"]
    /\ reason' = [reason EXCEPT ![a] = "effect_indeterminate"]
    /\ commitAttempted' = [commitAttempted EXCEPT ![a] = TRUE]
    /\ executionEvidence' = [executionEvidence EXCEPT ![a] = ev]
    /\ UNCHANGED <<
        matched, authorized, reserveWon, effectEntered, certState,
        certResultPresent, opStatus, opOutcome, opOwner
        >>

\* Provider exception, timeout, or projection failure. If commitOk is true,
\* the store consumes the reservation with outcome=indeterminate. Otherwise
\* the reservation remains locked. Both states block a blind replay.
CommitIndeterminate(a, commitOk, ev) ==
    /\ phase[a] = "executing"
    /\ opStatus = "reserved"
    /\ opOwner = a
    /\ phase' = [phase EXCEPT ![a] = "certifying"]
    /\ outcome' = [outcome EXCEPT ![a] = "indeterminate"]
    /\ reason' = [reason EXCEPT ![a] = "effect_indeterminate"]
    /\ commitAttempted' = [commitAttempted EXCEPT ![a] = TRUE]
    /\ executionEvidence' = [executionEvidence EXCEPT ![a] = ev]
    /\ opStatus' = IF commitOk THEN "committed" ELSE "reserved"
    /\ opOutcome' = IF commitOk THEN "indeterminate" ELSE "none"
    /\ UNCHANGED <<
        matched, authorized, reserveWon, effectEntered, certState,
        certResultPresent, opOwner
        >>

\* ---------------------------------------------------------------------
\* Certificate signing and durable inclusion
\* ---------------------------------------------------------------------

\* receipt-program.ts refuses to emit executed/indeterminate proof when the
\* corresponding execution record is unavailable.
BlockCertificateWithoutExecutionEvidence(a) ==
    /\ phase[a] = "certifying"
    /\ outcome[a] \in {"executed", "indeterminate"}
    /\ ~executionEvidence[a]
    /\ phase' = [phase EXCEPT ![a] = "terminal"]
    /\ reason' = [reason EXCEPT ![a] = "execution_evidence_unavailable"]
    /\ UNCHANGED <<
        outcome, matched, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

CertificateSigningFails(a) ==
    /\ phase[a] = "certifying"
    /\ (outcome[a] = "refused" \/ executionEvidence[a])
    /\ phase' = [phase EXCEPT ![a] = "terminal"]
    /\ reason' = [reason EXCEPT ![a] = "certificate_signing_failed"]
    /\ UNCHANGED <<
        outcome, matched, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certState, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

CertificatePersistenceFails(a) ==
    /\ phase[a] = "certifying"
    /\ (outcome[a] = "refused" \/ executionEvidence[a])
    /\ phase' = [phase EXCEPT ![a] = "terminal"]
    /\ reason' = [reason EXCEPT ![a] = "certificate_persistence_failed"]
    /\ certState' = [certState EXCEPT ![a] = "signed"]
    /\ UNCHANGED <<
        outcome, matched, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

PersistCertificate(a) ==
    /\ phase[a] = "certifying"
    /\ (outcome[a] = "refused" \/ executionEvidence[a])
    /\ phase' = [phase EXCEPT ![a] = "terminal"]
    /\ certState' = [certState EXCEPT ![a] = "persisted"]
    /\ UNCHANGED <<
        outcome, reason, matched, authorized, reserveWon, effectEntered,
        commitAttempted, executionEvidence, certResultPresent,
        opStatus, opOutcome, opOwner
        >>

Next ==
    \/ \E a \in Attempts : Match(a)
    \/ \E a \in Attempts, refusalReason \in {"program_invalid", "match_failed"} :
        RefuseBeforeMatch(a, refusalReason)
    \/ \E a \in Attempts : GateRefuse(a)
    \/ \E a \in Attempts : ReplayRefuse(a)
    \/ \E a \in Attempts : Reserve(a)
    \/ \E a \in Attempts : Execute(a)
    \/ \E a \in Attempts : ProviderReturns(a)
    \/ \E a \in Attempts, ev \in BOOLEAN : CommitExecuted(a, ev)
    \/ \E a \in Attempts, ev \in BOOLEAN : CommitExecutedUncertain(a, ev)
    \/ \E a \in Attempts, commitOk \in BOOLEAN, ev \in BOOLEAN :
        CommitIndeterminate(a, commitOk, ev)
    \/ \E a \in Attempts : BlockCertificateWithoutExecutionEvidence(a)
    \/ \E a \in Attempts : CertificateSigningFails(a)
    \/ \E a \in Attempts : CertificatePersistenceFails(a)
    \/ \E a \in Attempts : PersistCertificate(a)

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------
\* Single-state safety invariants
\* ---------------------------------------------------------------------

TypeInvariant ==
    /\ phase \in [Attempts -> AttemptPhases]
    /\ outcome \in [Attempts -> AttemptOutcomes]
    /\ reason \in [Attempts -> AttemptReasons]
    /\ matched \in BoolMap
    /\ authorized \in BoolMap
    /\ reserveWon \in BoolMap
    /\ effectEntered \in BoolMap
    /\ commitAttempted \in BoolMap
    /\ executionEvidence \in BoolMap
    /\ certState \in [Attempts -> CertificateStates]
    /\ certResultPresent \in BoolMap
    /\ opStatus \in OperationStates
    /\ opOutcome \in OperationOutcomes
    /\ opOwner \in Attempts \union {NoAttempt}

OperationStateSound ==
    /\ (opStatus = "open" => opOwner = NoAttempt /\ opOutcome = "none")
    /\ (opStatus = "reserved" => opOwner \in Attempts /\ opOutcome = "none")
    /\ (opStatus = "committed" =>
        opOwner \in Attempts /\ opOutcome \in {"executed", "indeterminate"})

PipelineOrderSafety ==
    \A a \in Attempts :
        /\ (matched[a] => phase[a] # "receipt")
        /\ (reserveWon[a] => matched[a] /\ authorized[a])
        /\ (effectEntered[a] => reserveWon[a])
        /\ (commitAttempted[a] => effectEntered[a])

ReservationOwnership ==
    /\ (opOwner # NoAttempt => reserveWon[opOwner])
    /\ \A a \in Attempts : reserveWon[a] => opOwner = a

EffectRequiresReservation ==
    \A a \in Attempts :
        effectEntered[a] => reserveWon[a] /\ authorized[a] /\ opOwner = a

CommitRequiresEffect ==
    opStatus = "committed" =>
        effectEntered[opOwner] /\ commitAttempted[opOwner]

ExecutedImpliesCommitted ==
    \A a \in Attempts :
        outcome[a] = "executed" =>
            /\ opOwner = a
            /\ opStatus = "committed"
            /\ opOutcome = "executed"
            /\ certResultPresent[a]

IndeterminateLocksAuthority ==
    \A a \in Attempts :
        outcome[a] = "indeterminate" =>
            /\ opOwner = a
            /\ opStatus \in {"reserved", "committed"}
            /\ reserveWon[a]
            /\ effectEntered[a]
            /\ commitAttempted[a]
            /\ ~certResultPresent[a]
            /\ (opStatus = "committed" => opOutcome = "indeterminate")

RefusalBeforeEffect ==
    \A a \in Attempts :
        outcome[a] = "refused" => ~reserveWon[a] /\ ~effectEntered[a]

ReplayFailClosed ==
    \A a \in Attempts :
        reason[a] \in {"operation_in_flight", "operation_already_committed"} =>
            outcome[a] = "refused" /\ ~reserveWon[a] /\ ~effectEntered[a]

SingleEffectOwner ==
    Cardinality({a \in Attempts : effectEntered[a]}) <= 1

TerminalOutcomeComplete ==
    \A a \in Attempts : phase[a] = "terminal" => outcome[a] # "none"

CertificateOutcomeSound ==
    \A a \in Attempts : certState[a] # "none" =>
        /\ phase[a] = "terminal"
        /\ outcome[a] # "none"
        /\ (certResultPresent[a] <=> outcome[a] = "executed")

CertificateEvidenceRequired ==
    \A a \in Attempts :
        (certState[a] # "none" /\ outcome[a] \in {"executed", "indeterminate"})
            => executionEvidence[a]

\* ---------------------------------------------------------------------
\* Transition-level terminality properties
\* ---------------------------------------------------------------------

TerminalAttemptStability ==
    [][\A a \in Attempts : phase[a] = "terminal" =>
        /\ phase'[a] = "terminal"
        /\ outcome'[a] = outcome[a]
        /\ reason'[a] = reason[a]
        /\ certState'[a] = certState[a]]_vars

CommittedOperationStability ==
    [][opStatus = "committed" =>
        /\ opStatus' = "committed"
        /\ opOutcome' = opOutcome
        /\ opOwner' = opOwner]_vars

\* There is no automatic release after provider entry. A reservation either
\* remains locked or becomes committed; it never reopens in this kernel.
ReservationNeverReopens ==
    [][opStatus = "reserved" =>
        /\ opStatus' \in {"reserved", "committed"}
        /\ opOwner' = opOwner]_vars

=======================================================================
