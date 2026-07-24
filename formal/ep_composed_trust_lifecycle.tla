-------------------- MODULE ep_composed_trust_lifecycle --------------------
\* EMILIA Protocol - bounded end-to-end trust lifecycle.
\*
\* This model is intentionally one state machine.  It does not verify six
\* profiles in isolation and then infer that their composition is safe.  One
\* exact CAID passes through AEB admission, exact-role AEC satisfaction,
\* human approval, Action Escrow, Model-to-Matter, GRACE, mobile continuity,
\* mobile enrollment, status freshness, witness admission, reservation,
\* provider uncertainty, authenticated reconciliation, late revocation,
\* dispute, and a separately authorized compensating remedy.
\*
\* Unsafe actions are excluded from Next and are used by the governed
\* formal/runtime trace harness as mutation operators.  Cryptographic
\* soundness, provider truth, trusted clocks, complete mediation, and durable
\* database behavior remain explicit assumptions.  TLC explores this finite
\* abstraction; the result is not an unbounded proof or a mechanized program
\* refinement proof.

EXTENDS Naturals

NoCAID == "none"
ActionCAID == "caid:action"
RemedyCAID == "caid:remedy"
WrongCAID == "caid:wrong"

VARIABLES
  phase,
  caid,
  aebState,
  aecState,
  approvalBound,
  actionEscrowClear,
  modelToMatterClear,
  graceClear,
  mobileContinuityClear,
  mobileEnrollmentClear,
  statusState,
  witnessState,
  everWitnessPoisoned,
  revoked,
  escrowState,
  providerCalls,
  replayRefused,
  reconciliationAuthenticated,
  originalEffect,
  disputeOpen,
  remedyCaid,
  remedyAuthorized,
  remedyCalls,
  remedyReplayRefused,
  remedyReconciliationAuthenticated,
  remedyEffect

vars == <<
  phase,
  caid,
  aebState,
  aecState,
  approvalBound,
  actionEscrowClear,
  modelToMatterClear,
  graceClear,
  mobileContinuityClear,
  mobileEnrollmentClear,
  statusState,
  witnessState,
  everWitnessPoisoned,
  revoked,
  escrowState,
  providerCalls,
  replayRefused,
  reconciliationAuthenticated,
  originalEffect,
  disputeOpen,
  remedyCaid,
  remedyAuthorized,
  remedyCalls,
  remedyReplayRefused,
  remedyReconciliationAuthenticated,
  remedyEffect
>>

Init ==
  /\ phase = "START"
  /\ caid = NoCAID
  /\ aebState = "UNVERIFIED"
  /\ aecState = "UNSATISFIED"
  /\ approvalBound = FALSE
  /\ actionEscrowClear = FALSE
  /\ modelToMatterClear = FALSE
  /\ graceClear = FALSE
  /\ mobileContinuityClear = FALSE
  /\ mobileEnrollmentClear = FALSE
  /\ statusState = "UNCHECKED"
  /\ witnessState = "UNCHECKED"
  /\ everWitnessPoisoned = FALSE
  /\ revoked = FALSE
  /\ escrowState = "OPEN"
  /\ providerCalls = 0
  /\ replayRefused = FALSE
  /\ reconciliationAuthenticated = FALSE
  /\ originalEffect = "NONE"
  /\ disputeOpen = FALSE
  /\ remedyCaid = NoCAID
  /\ remedyAuthorized = FALSE
  /\ remedyCalls = 0
  /\ remedyReplayRefused = FALSE
  /\ remedyReconciliationAuthenticated = FALSE
  /\ remedyEffect = "NONE"

BindExactCAID ==
  /\ phase = "START"
  /\ phase' = "CAID_BOUND"
  /\ caid' = ActionCAID
  /\ UNCHANGED <<
       aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

VerifyAEB ==
  /\ phase = "CAID_BOUND"
  /\ caid = ActionCAID
  /\ phase' = "AEB_VERIFIED"
  /\ aebState' = "VERIFIED_ACCEPTED"
  /\ UNCHANGED <<
       caid, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

SatisfyExactAEC ==
  /\ phase = "AEB_VERIFIED"
  /\ aebState = "VERIFIED_ACCEPTED"
  /\ phase' = "AEC_SATISFIED"
  /\ aecState' = "MACHINE_AND_HUMAN"
  /\ UNCHANGED <<
       caid, aebState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

CaptureApproval ==
  /\ phase = "AEC_SATISFIED"
  /\ aecState = "MACHINE_AND_HUMAN"
  /\ phase' = "APPROVED"
  /\ approvalBound' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

ClearActionEscrow ==
  /\ phase = "APPROVED"
  /\ approvalBound
  /\ phase' = "ACTION_ESCROW_CLEAR"
  /\ actionEscrowClear' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, modelToMatterClear,
       graceClear, mobileContinuityClear, mobileEnrollmentClear,
       statusState, witnessState, everWitnessPoisoned, revoked,
       escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ClearModelToMatter ==
  /\ phase = "ACTION_ESCROW_CLEAR"
  /\ actionEscrowClear
  /\ phase' = "MODEL_TO_MATTER_CLEAR"
  /\ modelToMatterClear' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       graceClear, mobileContinuityClear, mobileEnrollmentClear,
       statusState, witnessState, everWitnessPoisoned, revoked,
       escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ClearGRACE ==
  /\ phase = "MODEL_TO_MATTER_CLEAR"
  /\ modelToMatterClear
  /\ phase' = "GRACE_CLEAR"
  /\ graceClear' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, mobileContinuityClear, mobileEnrollmentClear,
       statusState, witnessState, everWitnessPoisoned, revoked,
       escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ClearMobileContinuity ==
  /\ phase = "GRACE_CLEAR"
  /\ graceClear
  /\ phase' = "MOBILE_CONTINUITY_CLEAR"
  /\ mobileContinuityClear' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileEnrollmentClear,
       statusState, witnessState, everWitnessPoisoned, revoked,
       escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ClearMobileEnrollment ==
  /\ phase = "MOBILE_CONTINUITY_CLEAR"
  /\ mobileContinuityClear
  /\ phase' = "MOBILE_ENROLLMENT_CLEAR"
  /\ mobileEnrollmentClear' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       statusState, witnessState, everWitnessPoisoned, revoked,
       escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

AcceptFreshStatus ==
  /\ phase = "MOBILE_ENROLLMENT_CLEAR"
  /\ phase' = "STATUS_FRESH"
  /\ statusState' = "FRESH_NOT_REVOKED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, witnessState, everWitnessPoisoned,
       revoked, escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

AcceptCleanWitness ==
  /\ phase = "STATUS_FRESH"
  /\ statusState = "FRESH_NOT_REVOKED"
  /\ witnessState # "POISONED"
  /\ phase' = "WITNESS_CLEAN"
  /\ witnessState' = "CLEAN"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, everWitnessPoisoned,
       revoked, escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ReserveEscrow ==
  /\ phase = "WITNESS_CLEAN"
  /\ caid = ActionCAID
  /\ aebState = "VERIFIED_ACCEPTED"
  /\ aecState = "MACHINE_AND_HUMAN"
  /\ approvalBound
  /\ actionEscrowClear
  /\ modelToMatterClear
  /\ graceClear
  /\ mobileContinuityClear
  /\ mobileEnrollmentClear
  /\ statusState = "FRESH_NOT_REVOKED"
  /\ witnessState = "CLEAN"
  /\ ~revoked
  /\ phase' = "RESERVED"
  /\ escrowState' = "RESERVED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

InvokeProvider ==
  /\ phase = "RESERVED"
  /\ escrowState = "RESERVED"
  /\ ~revoked
  /\ providerCalls = 0
  /\ phase' = "INVOKING"
  /\ providerCalls' = 1
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

MarkIndeterminate ==
  /\ phase = "INVOKING"
  /\ providerCalls = 1
  /\ phase' = "INDETERMINATE"
  /\ originalEffect' = "INDETERMINATE"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

RefuseBlindReplay ==
  /\ phase = "INDETERMINATE"
  /\ providerCalls = 1
  /\ phase' = "REPLAY_FENCED"
  /\ replayRefused' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ReconcileExecuted ==
  /\ phase = "REPLAY_FENCED"
  /\ replayRefused
  /\ phase' = "EXECUTED"
  /\ reconciliationAuthenticated' = TRUE
  /\ originalEffect' = "EXECUTED"
  /\ escrowState' = "CONSUMED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, providerCalls, replayRefused,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated,
       remedyEffect
     >>

RecordLateRevocation ==
  /\ phase = "EXECUTED"
  /\ originalEffect = "EXECUTED"
  /\ phase' = "LATE_REVOKED"
  /\ revoked' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

OpenDispute ==
  /\ phase = "LATE_REVOKED"
  /\ originalEffect = "EXECUTED"
  /\ phase' = "DISPUTED"
  /\ disputeOpen' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

AuthorizeSeparateRemedy ==
  /\ phase = "DISPUTED"
  /\ disputeOpen
  /\ phase' = "REMEDY_AUTHORIZED"
  /\ remedyCaid' = RemedyCAID
  /\ remedyAuthorized' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

InvokeRemedy ==
  /\ phase = "REMEDY_AUTHORIZED"
  /\ remedyAuthorized
  /\ remedyCaid = RemedyCAID
  /\ remedyCaid # caid
  /\ remedyCalls = 0
  /\ phase' = "REMEDY_INVOKING"
  /\ remedyCalls' = 1
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

MarkRemedyIndeterminate ==
  /\ phase = "REMEDY_INVOKING"
  /\ remedyCalls = 1
  /\ phase' = "REMEDY_INDETERMINATE"
  /\ remedyEffect' = "INDETERMINATE"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated
     >>

RefuseRemedyBlindReplay ==
  /\ phase = "REMEDY_INDETERMINATE"
  /\ remedyCalls = 1
  /\ phase' = "REMEDY_REPLAY_FENCED"
  /\ remedyReplayRefused' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReconciliationAuthenticated, remedyEffect
     >>

ReconcileRemedyExecuted ==
  /\ phase = "REMEDY_REPLAY_FENCED"
  /\ remedyReplayRefused
  /\ phase' = "REMEDIED"
  /\ remedyReconciliationAuthenticated' = TRUE
  /\ remedyEffect' = "EXECUTED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused
     >>

\* Adversarial branches that are valid refusals.

PresentSubstitutedAECRole ==
  /\ phase = "AEB_VERIFIED"
  /\ phase' = "AEC_ROLE_SUBSTITUTION_REFUSED"
  /\ aecState' = "SUBSTITUTED_REFUSED"
  /\ UNCHANGED <<
       caid, aebState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

RejectStaleStatus ==
  /\ phase = "MOBILE_ENROLLMENT_CLEAR"
  /\ phase' = "STALE_STATUS_REFUSED"
  /\ statusState' = "STALE_REFUSED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, witnessState, everWitnessPoisoned,
       revoked, escrowState, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

PoisonWitnessStream ==
  /\ phase = "STATUS_FRESH"
  /\ phase' = "WITNESS_POISONED"
  /\ witnessState' = "POISONED"
  /\ everWitnessPoisoned' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, revoked, escrowState,
       providerCalls, replayRefused, reconciliationAuthenticated,
       originalEffect, disputeOpen, remedyCaid, remedyAuthorized,
       remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

RecordPreExecutionRevocation ==
  /\ phase = "RESERVED"
  /\ phase' = "PRE_EXECUTION_REVOKED"
  /\ revoked' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

RefuseRevokedInvocation ==
  /\ phase = "PRE_EXECUTION_REVOKED"
  /\ revoked
  /\ phase' = "REVOKED_INVOCATION_REFUSED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

\* Unsafe model-defined mutations.  These are never in Next.

UnsafeRoleSubstitution ==
  /\ phase = "AEB_VERIFIED"
  /\ phase' = "AEC_SATISFIED"
  /\ aecState' = "SUBSTITUTED"
  /\ UNCHANGED <<
       caid, aebState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafeStaleStatusReserve ==
  /\ phase = "STALE_STATUS_REFUSED"
  /\ phase' = "RESERVED"
  /\ escrowState' = "RESERVED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafePoisonedWitnessReserve ==
  /\ phase = "WITNESS_POISONED"
  /\ phase' = "RESERVED"
  /\ escrowState' = "RESERVED"
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, providerCalls, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafeRevokedInvocation ==
  /\ phase = "PRE_EXECUTION_REVOKED"
  /\ phase' = "INVOKING"
  /\ providerCalls' = 1
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafeBlindReplay ==
  /\ phase = "INDETERMINATE"
  /\ phase' = "INVOKING"
  /\ providerCalls' = providerCalls + 1
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, replayRefused,
       reconciliationAuthenticated, originalEffect, disputeOpen,
       remedyCaid, remedyAuthorized, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafeUnauthenticatedReconciliation ==
  /\ phase = "REPLAY_FENCED"
  /\ phase' = "EXECUTED"
  /\ originalEffect' = "EXECUTED"
  /\ escrowState' = "CONSUMED"
  /\ reconciliationAuthenticated' = FALSE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, providerCalls, replayRefused,
       disputeOpen, remedyCaid, remedyAuthorized, remedyCalls,
       remedyReplayRefused, remedyReconciliationAuthenticated,
       remedyEffect
     >>

UnsafeOriginalAuthorityAsRemedy ==
  /\ phase = "DISPUTED"
  /\ phase' = "REMEDY_AUTHORIZED"
  /\ remedyCaid' = caid
  /\ remedyAuthorized' = TRUE
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCalls, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

UnsafeRemedyBlindReplay ==
  /\ phase = "REMEDY_INDETERMINATE"
  /\ phase' = "REMEDY_INVOKING"
  /\ remedyCalls' = remedyCalls + 1
  /\ UNCHANGED <<
       caid, aebState, aecState, approvalBound, actionEscrowClear,
       modelToMatterClear, graceClear, mobileContinuityClear,
       mobileEnrollmentClear, statusState, witnessState,
       everWitnessPoisoned, revoked, escrowState, providerCalls,
       replayRefused, reconciliationAuthenticated, originalEffect,
       disputeOpen, remedyCaid, remedyAuthorized, remedyReplayRefused,
       remedyReconciliationAuthenticated, remedyEffect
     >>

Next ==
  \/ BindExactCAID
  \/ VerifyAEB
  \/ SatisfyExactAEC
  \/ CaptureApproval
  \/ ClearActionEscrow
  \/ ClearModelToMatter
  \/ ClearGRACE
  \/ ClearMobileContinuity
  \/ ClearMobileEnrollment
  \/ AcceptFreshStatus
  \/ AcceptCleanWitness
  \/ ReserveEscrow
  \/ InvokeProvider
  \/ MarkIndeterminate
  \/ RefuseBlindReplay
  \/ ReconcileExecuted
  \/ RecordLateRevocation
  \/ OpenDispute
  \/ AuthorizeSeparateRemedy
  \/ InvokeRemedy
  \/ MarkRemedyIndeterminate
  \/ RefuseRemedyBlindReplay
  \/ ReconcileRemedyExecuted
  \/ PresentSubstitutedAECRole
  \/ RejectStaleStatus
  \/ PoisonWitnessStream
  \/ RecordPreExecutionRevocation
  \/ RefuseRevokedInvocation

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ caid \in {NoCAID, ActionCAID}
  /\ aebState \in {"UNVERIFIED", "VERIFIED_ACCEPTED"}
  /\ aecState \in {
       "UNSATISFIED", "MACHINE_AND_HUMAN", "SUBSTITUTED_REFUSED",
       "SUBSTITUTED"
     }
  /\ statusState \in {"UNCHECKED", "FRESH_NOT_REVOKED", "STALE_REFUSED"}
  /\ witnessState \in {"UNCHECKED", "CLEAN", "POISONED"}
  /\ escrowState \in {"OPEN", "RESERVED", "CONSUMED"}
  /\ providerCalls \in 0..2
  /\ remedyCaid \in {NoCAID, ActionCAID, RemedyCAID}
  /\ remedyCalls \in 0..2
  /\ originalEffect \in {"NONE", "INDETERMINATE", "EXECUTED"}
  /\ remedyEffect \in {"NONE", "INDETERMINATE", "EXECUTED"}

ExactActionBinding ==
  phase # "START" => caid = ActionCAID

ExactAECRoles ==
  phase \in {
    "AEC_SATISFIED", "APPROVED", "ACTION_ESCROW_CLEAR",
    "MODEL_TO_MATTER_CLEAR", "GRACE_CLEAR", "MOBILE_CONTINUITY_CLEAR",
    "MOBILE_ENROLLMENT_CLEAR", "STATUS_FRESH", "WITNESS_CLEAN",
    "RESERVED", "INVOKING", "INDETERMINATE", "REPLAY_FENCED",
    "EXECUTED", "LATE_REVOKED", "DISPUTED", "REMEDY_AUTHORIZED",
    "REMEDY_INVOKING", "REMEDY_INDETERMINATE",
    "REMEDY_REPLAY_FENCED", "REMEDIED"
  } => aecState = "MACHINE_AND_HUMAN"

ReservationRequiresTrust ==
  escrowState \in {"RESERVED", "CONSUMED"} =>
    /\ caid = ActionCAID
    /\ aebState = "VERIFIED_ACCEPTED"
    /\ aecState = "MACHINE_AND_HUMAN"
    /\ approvalBound
    /\ actionEscrowClear
    /\ modelToMatterClear
    /\ graceClear
    /\ mobileContinuityClear
    /\ mobileEnrollmentClear
    /\ statusState = "FRESH_NOT_REVOKED"
    /\ witnessState = "CLEAN"
    /\ ~everWitnessPoisoned

ProviderAtMostOnce == providerCalls <= 1

RevokedBeforeExecutionCannotInvoke ==
  revoked /\ originalEffect # "EXECUTED" => providerCalls = 0

AuthenticatedReconciliation ==
  originalEffect = "EXECUTED" => reconciliationAuthenticated

WitnessPoisonPermanent ==
  everWitnessPoisoned => witnessState = "POISONED"

SeparateRemedyAuthority ==
  remedyAuthorized => /\ remedyCaid = RemedyCAID /\ remedyCaid # caid

RemedyRequiresDisputedEffect ==
  remedyAuthorized => /\ disputeOpen /\ originalEffect = "EXECUTED"

RemedyAtMostOnce == remedyCalls <= 1

AuthenticatedRemedyReconciliation ==
  remedyEffect = "EXECUTED" => remedyReconciliationAuthenticated

RemedyDoesNotRewriteOriginal ==
  remedyEffect # "NONE" => originalEffect = "EXECUTED"

=============================================================================
