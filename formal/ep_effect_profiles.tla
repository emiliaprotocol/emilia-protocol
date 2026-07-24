----------------------- MODULE ep_effect_profiles -----------------------
EXTENDS Naturals, FiniteSets

\* Bounded composition model for six implementation-backed effect profiles.
\*
\* Each profile below is an independent state machine.  A composed Next step
\* advances exactly one profile and leaves all other profile variables
\* unchanged.  The finite instance intentionally contains:
\*
\*   - one Action Escrow milestone and release operation,
\*   - one Model-to-Matter action with the six required evidence types,
\*   - one AEC requirement with distinct machine-policy and human roles,
\*   - one GRACE authorization, envelope, dispatch, meter, and settlement,
\*   - one tenant-scoped mobile operation with one frozen executor, and
\*   - one mobile-enrollment challenge.
\*
\* The model abstracts successful native verification to explicit booleans or
\* exact symbolic bindings.  It does not model cryptographic soundness,
\* physical truth, complete mediation, database isolation, provider honesty,
\* key compromise, multiple tenants/actions, liveness, or implementation
\* refinement.  A clean TLC run is bounded same-team safety evidence only.

\* ---------------------------------------------------------------------
\* Finite symbolic domains
\* ---------------------------------------------------------------------

NoBinding == "none"
ExactActionCaid == "caid:exact-action"
OtherActionCaid == "caid:other-action"

ExpectedTenant == "tenant:expected"
OtherTenant == "tenant:other"
ExpectedExecutor == "executor:expected"
OtherExecutor == "executor:other"

ModelToMatterEvidenceLegs == {
  "model_attestation",
  "safety_case_attestation",
  "institutional_authority",
  "biosafety_review",
  "domain_screening",
  "human_authorization"
}

AecRequiredRoles == {"machine_policy", "human_authority"}
EnrollmentRowKinds == {"webauthn", "platform"}

\* ---------------------------------------------------------------------
\* Independent profile variables
\* ---------------------------------------------------------------------

VARIABLES
  aeState,
  aeMilestoneCaid,
  aeReleaseCount,
  aeDuplicateRefused,

  m2mState,
  m2mPresentedCaid,
  m2mLegBindings,
  m2mConsumptionCount,

  aecState,
  aecPresentedRoles,

  graceState,
  graceAuthorizationVerified,
  graceEnvelopeVerified,
  graceDispatchCount,
  graceMeterRecorded,
  graceSettlementCount,
  graceReplayRefused,

  mobileState,
  mobileTenant,
  mobileExecutor,
  mobileProviderCalls,
  mobileFenced,
  mobileOutcomeAuthenticated,
  mobileOutcomeTenant,
  mobileOutcomeExecutor,
  mobileReplayRefused,
  mobileReconciliationRefused,

  enrollmentState,
  enrollmentRows,
  enrollmentActivationCount,
  enrollmentReplayRefused

ActionEscrowVars ==
  <<aeState, aeMilestoneCaid, aeReleaseCount, aeDuplicateRefused>>

ModelToMatterVars ==
  <<m2mState, m2mPresentedCaid, m2mLegBindings,
    m2mConsumptionCount>>

AecVars == <<aecState, aecPresentedRoles>>

GraceVars ==
  <<graceState, graceAuthorizationVerified, graceEnvelopeVerified,
    graceDispatchCount, graceMeterRecorded, graceSettlementCount,
    graceReplayRefused>>

MobileContinuityVars ==
  <<mobileState, mobileTenant, mobileExecutor, mobileProviderCalls,
    mobileFenced, mobileOutcomeAuthenticated, mobileOutcomeTenant,
    mobileOutcomeExecutor, mobileReplayRefused,
    mobileReconciliationRefused>>

MobileEnrollmentVars ==
  <<enrollmentState, enrollmentRows, enrollmentActivationCount,
    enrollmentReplayRefused>>

vars ==
  <<ActionEscrowVars, ModelToMatterVars, AecVars, GraceVars,
    MobileContinuityVars, MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* Initial state
\* ---------------------------------------------------------------------

Init ==
  /\ aeState = "awaiting_milestone"
  /\ aeMilestoneCaid = NoBinding
  /\ aeReleaseCount = 0
  /\ aeDuplicateRefused = FALSE

  /\ m2mState = "collecting"
  /\ m2mPresentedCaid = NoBinding
  /\ m2mLegBindings =
       [leg \in ModelToMatterEvidenceLegs |-> NoBinding]
  /\ m2mConsumptionCount = 0

  /\ aecState = "awaiting_roles"
  /\ aecPresentedRoles = {}

  /\ graceState = "idle"
  /\ graceAuthorizationVerified = FALSE
  /\ graceEnvelopeVerified = FALSE
  /\ graceDispatchCount = 0
  /\ graceMeterRecorded = FALSE
  /\ graceSettlementCount = 0
  /\ graceReplayRefused = FALSE

  /\ mobileState = "idle"
  /\ mobileTenant = NoBinding
  /\ mobileExecutor = NoBinding
  /\ mobileProviderCalls = 0
  /\ mobileFenced = FALSE
  /\ mobileOutcomeAuthenticated = FALSE
  /\ mobileOutcomeTenant = NoBinding
  /\ mobileOutcomeExecutor = NoBinding
  /\ mobileReplayRefused = FALSE
  /\ mobileReconciliationRefused = FALSE

  /\ enrollmentState = "pending"
  /\ enrollmentRows = {}
  /\ enrollmentActivationCount = 0
  /\ enrollmentReplayRefused = FALSE

\* ---------------------------------------------------------------------
\* Action Escrow: exact milestone, durable reserve, one release
\* ---------------------------------------------------------------------

SubmitExactMilestone ==
  /\ aeState = "awaiting_milestone"
  /\ aeState' = "milestone_exact"
  /\ aeMilestoneCaid' = ExactActionCaid
  /\ UNCHANGED <<aeReleaseCount, aeDuplicateRefused>>

SubmitMismatchedMilestone ==
  /\ aeState = "awaiting_milestone"
  /\ aeState' = "milestone_refused"
  /\ aeMilestoneCaid' = OtherActionCaid
  /\ UNCHANGED <<aeReleaseCount, aeDuplicateRefused>>

ReserveEscrowRelease ==
  /\ aeState = "milestone_exact"
  /\ aeMilestoneCaid = ExactActionCaid
  /\ aeState' = "release_reserved"
  /\ UNCHANGED
       <<aeMilestoneCaid, aeReleaseCount, aeDuplicateRefused>>

ReleaseEscrow ==
  /\ aeState = "release_reserved"
  /\ aeMilestoneCaid = ExactActionCaid
  /\ aeReleaseCount = 0
  /\ aeState' = "released"
  /\ aeReleaseCount' = 1
  /\ UNCHANGED <<aeMilestoneCaid, aeDuplicateRefused>>

AttemptDuplicateEscrowRelease ==
  /\ aeState = "released"
  /\ ~aeDuplicateRefused
  /\ aeDuplicateRefused' = TRUE
  /\ UNCHANGED <<aeState, aeMilestoneCaid, aeReleaseCount>>

\* Deliberately unsafe, excluded from Next. Selected-trace mutation testing
\* must show TLC rejects a second release while the runtime refuses replay.
UnsafeDuplicateEscrowRelease ==
  /\ aeState = "released"
  /\ aeReleaseCount = 1
  /\ aeReleaseCount' = 2
  /\ UNCHANGED <<aeState, aeMilestoneCaid, aeDuplicateRefused>>
  /\ UNCHANGED
       <<ModelToMatterVars, AecVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

ActionEscrowLocalStep ==
  \/ SubmitExactMilestone
  \/ SubmitMismatchedMilestone
  \/ ReserveEscrowRelease
  \/ ReleaseEscrow
  \/ AttemptDuplicateEscrowRelease

ActionEscrowStep ==
  /\ ActionEscrowLocalStep
  /\ UNCHANGED
       <<ModelToMatterVars, AecVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* Model-to-Matter: six fixed evidence legs, exact CAID, one consumption
\* ---------------------------------------------------------------------

PresentSixExactLegs ==
  /\ m2mState = "collecting"
  /\ m2mState' = "ready"
  /\ m2mPresentedCaid' = ExactActionCaid
  /\ m2mLegBindings' =
       [leg \in ModelToMatterEvidenceLegs |-> ExactActionCaid]
  /\ UNCHANGED m2mConsumptionCount

PresentMismatchedLeg ==
  /\ m2mState = "collecting"
  /\ \E badLeg \in ModelToMatterEvidenceLegs :
       /\ m2mState' = "mismatch_presented"
       /\ m2mPresentedCaid' = OtherActionCaid
       /\ m2mLegBindings' =
            [leg \in ModelToMatterEvidenceLegs |->
               IF leg = badLeg
               THEN OtherActionCaid
               ELSE ExactActionCaid]
  /\ UNCHANGED m2mConsumptionCount

ConsumeModelToMatterClearance ==
  /\ m2mState = "ready"
  /\ m2mPresentedCaid = ExactActionCaid
  /\ \A leg \in ModelToMatterEvidenceLegs :
       m2mLegBindings[leg] = ExactActionCaid
  /\ m2mConsumptionCount = 0
  /\ m2mState' = "consumed"
  /\ m2mConsumptionCount' = 1
  /\ UNCHANGED <<m2mPresentedCaid, m2mLegBindings>>

RefuseModelToMatterClearance ==
  /\ m2mState = "mismatch_presented"
  /\ m2mState' = "refused"
  /\ UNCHANGED
       <<m2mPresentedCaid, m2mLegBindings, m2mConsumptionCount>>

AttemptModelToMatterReplay ==
  /\ m2mState = "consumed"
  /\ m2mState' = "replay_refused"
  /\ UNCHANGED
       <<m2mPresentedCaid, m2mLegBindings, m2mConsumptionCount>>

\* Deliberately unsafe, excluded from Next.
UnsafeAcceptMismatchedModelToMatter ==
  /\ m2mState = "mismatch_presented"
  /\ m2mState' = "consumed"
  /\ m2mConsumptionCount' = 1
  /\ UNCHANGED <<m2mPresentedCaid, m2mLegBindings>>
  /\ UNCHANGED
       <<ActionEscrowVars, AecVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

ModelToMatterLocalStep ==
  \/ PresentSixExactLegs
  \/ PresentMismatchedLeg
  \/ ConsumeModelToMatterClearance
  \/ RefuseModelToMatterClearance
  \/ AttemptModelToMatterReplay

ModelToMatterStep ==
  /\ ModelToMatterLocalStep
  /\ UNCHANGED
       <<ActionEscrowVars, AecVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* AEC: machine-policy evidence cannot substitute for human authority
\* ---------------------------------------------------------------------

PresentExactAecRoles ==
  /\ aecState = "awaiting_roles"
  /\ aecState' = "exact_roles_presented"
  /\ aecPresentedRoles' = AecRequiredRoles

PresentSubstitutedAecRole ==
  /\ aecState = "awaiting_roles"
  /\ aecState' = "substitution_presented"
  /\ aecPresentedRoles' = {"machine_policy", "operator_substitute"}

AcceptAec ==
  /\ aecState = "exact_roles_presented"
  /\ aecPresentedRoles = AecRequiredRoles
  /\ aecState' = "accepted"
  /\ UNCHANGED aecPresentedRoles

RefuseAec ==
  /\ aecState = "substitution_presented"
  /\ aecState' = "refused"
  /\ UNCHANGED aecPresentedRoles

\* Deliberately unsafe, excluded from Next.
UnsafeAcceptSubstitutedAecRole ==
  /\ aecState = "substitution_presented"
  /\ aecState' = "accepted"
  /\ UNCHANGED aecPresentedRoles
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

AecLocalStep ==
  \/ PresentExactAecRoles
  \/ PresentSubstitutedAecRole
  \/ AcceptAec
  \/ RefuseAec

AecStep ==
  /\ AecLocalStep
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, GraceVars,
         MobileContinuityVars, MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* GRACE: authorization and envelope before dispatch, meter before
\* one settlement.  AuthorizeGrace abstracts the successful verification
\* of both independent prerequisites over the same exact action.
\* ---------------------------------------------------------------------

PresentGraceAuthorizationOnly ==
  /\ graceState = "idle"
  /\ graceState' = "authorization_only"
  /\ graceAuthorizationVerified' = TRUE
  /\ UNCHANGED
       <<graceEnvelopeVerified, graceDispatchCount, graceMeterRecorded,
         graceSettlementCount, graceReplayRefused>>

PresentGraceEnvelopeOnly ==
  /\ graceState = "idle"
  /\ graceState' = "envelope_only"
  /\ graceEnvelopeVerified' = TRUE
  /\ UNCHANGED
       <<graceAuthorizationVerified, graceDispatchCount,
         graceMeterRecorded, graceSettlementCount, graceReplayRefused>>

AuthorizeGrace ==
  /\ graceState = "idle"
  /\ graceState' = "authorized"
  /\ graceAuthorizationVerified' = TRUE
  /\ graceEnvelopeVerified' = TRUE
  /\ UNCHANGED
       <<graceDispatchCount, graceMeterRecorded, graceSettlementCount,
         graceReplayRefused>>

DispatchGrace ==
  /\ graceState = "authorized"
  /\ graceAuthorizationVerified
  /\ graceEnvelopeVerified
  /\ graceDispatchCount = 0
  /\ graceState' = "dispatched"
  /\ graceDispatchCount' = 1
  /\ UNCHANGED
       <<graceAuthorizationVerified, graceEnvelopeVerified,
         graceMeterRecorded, graceSettlementCount, graceReplayRefused>>

GraceTimeout ==
  /\ graceState = "dispatched"
  /\ graceState' = "indeterminate"
  /\ UNCHANGED
       <<graceAuthorizationVerified, graceEnvelopeVerified,
         graceDispatchCount, graceMeterRecorded, graceSettlementCount,
         graceReplayRefused>>

AttemptGraceReplay ==
  /\ graceState = "indeterminate"
  /\ ~graceReplayRefused
  /\ graceReplayRefused' = TRUE
  /\ UNCHANGED
       <<graceState, graceAuthorizationVerified, graceEnvelopeVerified,
         graceDispatchCount, graceMeterRecorded, graceSettlementCount>>

\* Deliberately unsafe, excluded from Next.
UnsafeGraceReplayDispatch ==
  /\ graceState = "indeterminate"
  /\ graceDispatchCount = 1
  /\ graceDispatchCount' = 2
  /\ UNCHANGED
       <<graceState, graceAuthorizationVerified, graceEnvelopeVerified,
         graceMeterRecorded, graceSettlementCount, graceReplayRefused>>
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars,
         MobileContinuityVars, MobileEnrollmentVars>>

RecordGraceMeter ==
  /\ graceState = "dispatched"
  /\ graceState' = "metered"
  /\ graceMeterRecorded' = TRUE
  /\ UNCHANGED
       <<graceAuthorizationVerified, graceEnvelopeVerified,
         graceDispatchCount, graceSettlementCount, graceReplayRefused>>

SettleGrace ==
  /\ graceState = "metered"
  /\ graceMeterRecorded
  /\ graceSettlementCount = 0
  /\ graceState' = "settled"
  /\ graceSettlementCount' = 1
  /\ UNCHANGED
       <<graceAuthorizationVerified, graceEnvelopeVerified,
         graceDispatchCount, graceMeterRecorded, graceReplayRefused>>

AttemptGraceSettlementReplay ==
  /\ graceState = "settled"
  /\ ~graceReplayRefused
  /\ graceReplayRefused' = TRUE
  /\ UNCHANGED
       <<graceState, graceAuthorizationVerified, graceEnvelopeVerified,
         graceDispatchCount, graceMeterRecorded, graceSettlementCount>>

GraceLocalStep ==
  \/ PresentGraceAuthorizationOnly
  \/ PresentGraceEnvelopeOnly
  \/ AuthorizeGrace
  \/ DispatchGrace
  \/ GraceTimeout
  \/ AttemptGraceReplay
  \/ RecordGraceMeter
  \/ SettleGrace
  \/ AttemptGraceSettlementReplay

GraceStep ==
  /\ GraceLocalStep
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars,
         MobileContinuityVars, MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* Mobile action continuity: exact tenant and frozen executor, timeout
\* fence, no provider replay, authenticated exact reconciliation
\* ---------------------------------------------------------------------

ReserveMobileAction ==
  /\ mobileState = "idle"
  /\ mobileState' = "reserved"
  /\ mobileTenant' = ExpectedTenant
  /\ mobileExecutor' = ExpectedExecutor
  /\ UNCHANGED
       <<mobileProviderCalls, mobileFenced, mobileOutcomeAuthenticated,
         mobileOutcomeTenant, mobileOutcomeExecutor, mobileReplayRefused,
         mobileReconciliationRefused>>

AttemptWrongMobileReservation ==
  /\ mobileState = "idle"
  /\ mobileState' = "reservation_refused"
  /\ mobileTenant' \in {ExpectedTenant, OtherTenant}
  /\ mobileExecutor' \in {ExpectedExecutor, OtherExecutor}
  /\ (mobileTenant' = OtherTenant \/ mobileExecutor' = OtherExecutor)
  /\ UNCHANGED
       <<mobileProviderCalls, mobileFenced, mobileOutcomeAuthenticated,
         mobileOutcomeTenant, mobileOutcomeExecutor, mobileReplayRefused,
         mobileReconciliationRefused>>

InvokeMobileProvider ==
  /\ mobileState = "reserved"
  /\ mobileTenant = ExpectedTenant
  /\ mobileExecutor = ExpectedExecutor
  /\ mobileProviderCalls = 0
  /\ mobileState' = "provider_invoked"
  /\ mobileProviderCalls' = 1
  /\ UNCHANGED
       <<mobileTenant, mobileExecutor, mobileFenced,
         mobileOutcomeAuthenticated, mobileOutcomeTenant,
         mobileOutcomeExecutor, mobileReplayRefused,
         mobileReconciliationRefused>>

MobileTimeout ==
  /\ mobileState = "provider_invoked"
  /\ mobileState' = "indeterminate"
  /\ mobileFenced' = TRUE
  /\ UNCHANGED
       <<mobileTenant, mobileExecutor, mobileProviderCalls,
         mobileOutcomeAuthenticated, mobileOutcomeTenant,
         mobileOutcomeExecutor, mobileReplayRefused,
         mobileReconciliationRefused>>

AttemptMobileProviderReplay ==
  /\ mobileState = "indeterminate"
  /\ ~mobileReplayRefused
  /\ mobileReplayRefused' = TRUE
  /\ UNCHANGED
       <<mobileState, mobileTenant, mobileExecutor, mobileProviderCalls,
         mobileFenced, mobileOutcomeAuthenticated, mobileOutcomeTenant,
         mobileOutcomeExecutor, mobileReconciliationRefused>>

\* Deliberately unsafe, excluded from Next.
UnsafeMobileProviderReplay ==
  /\ mobileState = "indeterminate"
  /\ mobileProviderCalls = 1
  /\ mobileProviderCalls' = 2
  /\ UNCHANGED
       <<mobileState, mobileTenant, mobileExecutor, mobileFenced,
         mobileOutcomeAuthenticated, mobileOutcomeTenant,
         mobileOutcomeExecutor, mobileReplayRefused,
         mobileReconciliationRefused>>
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars, GraceVars,
         MobileEnrollmentVars>>

AttemptUnauthenticatedMobileReconciliation ==
  /\ mobileState = "indeterminate"
  /\ ~mobileReconciliationRefused
  /\ mobileReconciliationRefused' = TRUE
  /\ UNCHANGED
       <<mobileState, mobileTenant, mobileExecutor, mobileProviderCalls,
         mobileFenced, mobileOutcomeAuthenticated, mobileOutcomeTenant,
         mobileOutcomeExecutor, mobileReplayRefused>>

ReconcileExactMobileOutcome ==
  /\ mobileState = "indeterminate"
  /\ mobileTenant = ExpectedTenant
  /\ mobileExecutor = ExpectedExecutor
  /\ mobileFenced
  /\ mobileState' = "executed"
  /\ mobileOutcomeAuthenticated' = TRUE
  /\ mobileOutcomeTenant' = ExpectedTenant
  /\ mobileOutcomeExecutor' = ExpectedExecutor
  /\ UNCHANGED
       <<mobileTenant, mobileExecutor, mobileProviderCalls, mobileFenced,
         mobileReplayRefused, mobileReconciliationRefused>>

MobileContinuityLocalStep ==
  \/ ReserveMobileAction
  \/ AttemptWrongMobileReservation
  \/ InvokeMobileProvider
  \/ MobileTimeout
  \/ AttemptMobileProviderReplay
  \/ AttemptUnauthenticatedMobileReconciliation
  \/ ReconcileExactMobileOutcome

MobileContinuityStep ==
  /\ MobileContinuityLocalStep
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars, GraceVars,
         MobileEnrollmentVars>>

\* ---------------------------------------------------------------------
\* Mobile enrollment: both independently verified rows, one activation
\* ---------------------------------------------------------------------

VerifyWebAuthnEnrollment ==
  /\ enrollmentState \in
       {"pending", "platform_only"}
  /\ "webauthn" \notin enrollmentRows
  /\ enrollmentRows' = enrollmentRows \cup {"webauthn"}
  /\ enrollmentState' =
       IF "platform" \in enrollmentRows
       THEN "ready"
       ELSE "webauthn_only"
  /\ UNCHANGED
       <<enrollmentActivationCount, enrollmentReplayRefused>>

VerifyPlatformEnrollment ==
  /\ enrollmentState \in
       {"pending", "webauthn_only"}
  /\ "platform" \notin enrollmentRows
  /\ enrollmentRows' = enrollmentRows \cup {"platform"}
  /\ enrollmentState' =
       IF "webauthn" \in enrollmentRows
       THEN "ready"
       ELSE "platform_only"
  /\ UNCHANGED
       <<enrollmentActivationCount, enrollmentReplayRefused>>

ActivateEnrollment ==
  /\ enrollmentState = "ready"
  /\ enrollmentRows = EnrollmentRowKinds
  /\ enrollmentActivationCount = 0
  /\ enrollmentState' = "active"
  /\ enrollmentActivationCount' = 1
  /\ UNCHANGED <<enrollmentRows, enrollmentReplayRefused>>

AttemptEnrollmentReplay ==
  /\ enrollmentState = "active"
  /\ ~enrollmentReplayRefused
  /\ enrollmentReplayRefused' = TRUE
  /\ UNCHANGED
       <<enrollmentState, enrollmentRows, enrollmentActivationCount>>

\* Deliberately unsafe, excluded from Next.
UnsafeActivateIncompleteEnrollment ==
  /\ enrollmentState = "webauthn_only"
  /\ enrollmentRows = {"webauthn"}
  /\ enrollmentState' = "active"
  /\ enrollmentActivationCount' = 1
  /\ UNCHANGED <<enrollmentRows, enrollmentReplayRefused>>
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars, GraceVars,
         MobileContinuityVars>>

MobileEnrollmentLocalStep ==
  \/ VerifyWebAuthnEnrollment
  \/ VerifyPlatformEnrollment
  \/ ActivateEnrollment
  \/ AttemptEnrollmentReplay

MobileEnrollmentStep ==
  /\ MobileEnrollmentLocalStep
  /\ UNCHANGED
       <<ActionEscrowVars, ModelToMatterVars, AecVars, GraceVars,
         MobileContinuityVars>>

\* ---------------------------------------------------------------------
\* Asynchronous product: one independent profile transition per step
\* ---------------------------------------------------------------------

Next ==
  \/ ActionEscrowStep
  \/ ModelToMatterStep
  \/ AecStep
  \/ GraceStep
  \/ MobileContinuityStep
  \/ MobileEnrollmentStep

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------
\* Type and requested safety obligations
\* ---------------------------------------------------------------------

TypeOK ==
  /\ aeState \in {
       "awaiting_milestone", "milestone_exact", "milestone_refused",
       "release_reserved", "released"
     }
  /\ aeMilestoneCaid \in
       {NoBinding, ExactActionCaid, OtherActionCaid}
  /\ aeReleaseCount \in 0..1
  /\ aeDuplicateRefused \in BOOLEAN

  /\ m2mState \in {
       "collecting", "ready", "mismatch_presented", "consumed",
       "refused", "replay_refused"
     }
  /\ m2mPresentedCaid \in
       {NoBinding, ExactActionCaid, OtherActionCaid}
  /\ m2mLegBindings \in
       [ModelToMatterEvidenceLegs ->
         {NoBinding, ExactActionCaid, OtherActionCaid}]
  /\ m2mConsumptionCount \in 0..1

  /\ aecState \in {
       "awaiting_roles", "exact_roles_presented",
       "substitution_presented", "accepted", "refused"
     }
  /\ aecPresentedRoles \subseteq
       {"machine_policy", "human_authority", "operator_substitute"}

  /\ graceState \in {
       "idle", "authorization_only", "envelope_only", "authorized",
       "dispatched", "metered", "settled", "indeterminate"
     }
  /\ graceAuthorizationVerified \in BOOLEAN
  /\ graceEnvelopeVerified \in BOOLEAN
  /\ graceDispatchCount \in 0..1
  /\ graceMeterRecorded \in BOOLEAN
  /\ graceSettlementCount \in 0..1
  /\ graceReplayRefused \in BOOLEAN

  /\ mobileState \in {
       "idle", "reserved", "reservation_refused", "provider_invoked",
       "indeterminate", "executed"
     }
  /\ mobileTenant \in {NoBinding, ExpectedTenant, OtherTenant}
  /\ mobileExecutor \in
       {NoBinding, ExpectedExecutor, OtherExecutor}
  /\ mobileProviderCalls \in 0..1
  /\ mobileFenced \in BOOLEAN
  /\ mobileOutcomeAuthenticated \in BOOLEAN
  /\ mobileOutcomeTenant \in
       {NoBinding, ExpectedTenant, OtherTenant}
  /\ mobileOutcomeExecutor \in
       {NoBinding, ExpectedExecutor, OtherExecutor}
  /\ mobileReplayRefused \in BOOLEAN
  /\ mobileReconciliationRefused \in BOOLEAN

  /\ enrollmentState \in {
       "pending", "webauthn_only", "platform_only", "ready", "active"
     }
  /\ enrollmentRows \subseteq EnrollmentRowKinds
  /\ enrollmentActivationCount \in 0..1
  /\ enrollmentReplayRefused \in BOOLEAN

ActionEscrowExactMilestoneRelease ==
  aeReleaseCount = 1 =>
    /\ aeState = "released"
    /\ aeMilestoneCaid = ExactActionCaid

ActionEscrowSingleRelease ==
  /\ aeReleaseCount <= 1
  /\ (aeDuplicateRefused => aeReleaseCount = 1)

ModelToMatterSixLegClearance ==
  /\ Cardinality(ModelToMatterEvidenceLegs) = 6
  /\ (m2mConsumptionCount = 1 =>
       {leg \in ModelToMatterEvidenceLegs :
          m2mLegBindings[leg] # NoBinding}
       = ModelToMatterEvidenceLegs)

ModelToMatterExactCaid ==
  m2mConsumptionCount = 1 =>
    /\ m2mPresentedCaid = ExactActionCaid
    /\ \A leg \in ModelToMatterEvidenceLegs :
         m2mLegBindings[leg] = ExactActionCaid

ModelToMatterSingleConsumption ==
  /\ m2mConsumptionCount <= 1
  /\ (m2mState \in {"consumed", "replay_refused"} =>
       m2mConsumptionCount = 1)

AecRoleNonSubstitution ==
  aecState = "accepted" =>
    aecPresentedRoles = AecRequiredRoles

GraceAuthorizedEnvelopeBeforeDispatch ==
  graceDispatchCount = 1 =>
    /\ graceAuthorizationVerified
    /\ graceEnvelopeVerified

GraceMeterBeforeSettlement ==
  graceSettlementCount = 1 =>
    /\ graceDispatchCount = 1
    /\ graceMeterRecorded
    /\ graceState = "settled"

GraceSingleSettlement ==
  /\ graceSettlementCount <= 1
  /\ (graceReplayRefused =>
       graceState \in {"indeterminate", "settled"})

GraceSingleDispatch ==
  graceDispatchCount <= 1

MobileExactTenantExecutor ==
  mobileProviderCalls = 1 =>
    /\ mobileTenant = ExpectedTenant
    /\ mobileExecutor = ExpectedExecutor

MobileTimeoutFence ==
  /\ (mobileState \in {"indeterminate", "executed"} =>
       /\ mobileFenced
       /\ mobileProviderCalls = 1)
  /\ (mobileFenced => mobileProviderCalls = 1)
  /\ (mobileReplayRefused => mobileFenced)

MobileAuthenticatedReconciliation ==
  mobileState = "executed" =>
    /\ mobileOutcomeAuthenticated
    /\ mobileOutcomeTenant = ExpectedTenant
    /\ mobileOutcomeExecutor = ExpectedExecutor
    /\ mobileTenant = mobileOutcomeTenant
    /\ mobileExecutor = mobileOutcomeExecutor

MobileEnrollmentRequiresBothRows ==
  enrollmentActivationCount = 1 =>
    /\ enrollmentState = "active"
    /\ enrollmentRows = EnrollmentRowKinds

MobileEnrollmentActivatesAtMostOnce ==
  /\ enrollmentActivationCount <= 1
  /\ (enrollmentReplayRefused => enrollmentActivationCount = 1)

=============================================================================
