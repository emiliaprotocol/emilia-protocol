----------------------- MODULE ep_complete_mediation -----------------------
\* EMILIA consequence-actuator complete-mediation boundary.
\*
\* The Gate decides whether an exact action is allowed but never holds the
\* provider credential.  A separately deployed actuator is the only principal
\* that can invoke the provider.  The actuator accepts one short-lived signed
\* execution envelope, verifies its exact binding, consumes it atomically, and
\* never reopens it after provider entry.  An uncertain provider result remains
\* fenced until authenticated reconciliation.
\*
\* The AEB one-time reservation for the action instance is modelled explicitly.
\* draft-schrock-action-evidence-boundary-04 s5.11: reconciling an authoritative
\* NOT_COMMITTED result marks the reservation RELEASED_NOT_ENTERED, which is
\* terminal.  It is never handed back, so the same action instance can never be
\* reserved a second time and can never produce a second provider call, however
\* many fresh envelopes the caller mints.
\*
\* This is a finite safety abstraction. Signature soundness, credential-store
\* isolation, trusted time, provider truth, and linearizable durable storage are
\* explicit assumptions rather than claims proved by TLC.

EXTENDS Naturals

CONSTANTS
  AllowDirectProviderCall,
  AllowReleasedReservationReuse

VARIABLES
  decision,
  envelope,
  binding,
  effect,
  providerCalls,
  providerCaller,
  bypassRefused,
  staleRefused,
  replayRefused,
  reconciliationAuthenticated,
  reservation,
  reservationReleased,
  reReserveRefused

vars == <<
  decision,
  envelope,
  binding,
  effect,
  providerCalls,
  providerCaller,
  bypassRefused,
  staleRefused,
  replayRefused,
  reconciliationAuthenticated,
  reservation,
  reservationReleased,
  reReserveRefused
>>

DecisionStates == {"NONE", "ALLOWED"}
EnvelopeStates == {"NONE", "FRESH", "CONSUMED", "EXPIRED", "REVOKED"}
BindingStates == {"NONE", "EXACT", "WRONG"}
EffectStates == {
  "NONE",
  "INVOKING",
  "INDETERMINATE",
  "COMMITTED",
  "NOT_COMMITTED",
  "ESCALATED"
}
Callers == {"NONE", "ACTUATOR", "GATE"}
ReservationStates == {"NONE", "RESERVED", "CONSUMED", "RELEASED_NOT_ENTERED"}
TerminalEffects == {"COMMITTED", "NOT_COMMITTED", "ESCALATED"}

Init ==
  /\ decision = "NONE"
  /\ envelope = "NONE"
  /\ binding = "NONE"
  /\ effect = "NONE"
  /\ providerCalls = 0
  /\ providerCaller = "NONE"
  /\ bypassRefused = FALSE
  /\ staleRefused = FALSE
  /\ replayRefused = FALSE
  /\ reconciliationAuthenticated = FALSE
  /\ reservation = "NONE"
  /\ reservationReleased = FALSE
  /\ reReserveRefused = FALSE

AuthorizeExactAction ==
  /\ decision = "NONE"
  /\ decision' = "ALLOWED"
  /\ UNCHANGED <<
       envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

ReserveOneTimeUnit ==
  /\ decision = "ALLOWED"
  /\ reservation = "NONE"
  /\ reservation' = "RESERVED"
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservationReleased, reReserveRefused
     >>

\* Re-presenting the same action instance after a terminal release derives the
\* byte-identical reservation key, which the store refuses. No envelope, no
\* decision, and above all no provider call follows.
RefuseReReserveAfterRelease ==
  /\ reservation = "RELEASED_NOT_ENTERED"
  /\ ~reReserveRefused
  /\ reReserveRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased
     >>

IssueExactEnvelope ==
  /\ decision = "ALLOWED"
  /\ reservation = "RESERVED"
  /\ envelope = "NONE"
  /\ envelope' = "FRESH"
  /\ binding' = "EXACT"
  /\ UNCHANGED <<
       decision, effect, providerCalls, providerCaller, bypassRefused,
       staleRefused, replayRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

IssueWrongEnvelope ==
  /\ decision = "ALLOWED"
  /\ reservation = "RESERVED"
  /\ envelope = "NONE"
  /\ envelope' = "FRESH"
  /\ binding' = "WRONG"
  /\ UNCHANGED <<
       decision, effect, providerCalls, providerCaller, bypassRefused,
       staleRefused, replayRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

ExpireEnvelope ==
  /\ envelope = "FRESH"
  /\ envelope' = "EXPIRED"
  /\ UNCHANGED <<
       decision, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

RevokeEnvelope ==
  /\ envelope = "FRESH"
  /\ envelope' = "REVOKED"
  /\ UNCHANGED <<
       decision, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

RefuseGateBypass ==
  /\ providerCalls = 0
  /\ ~bypassRefused
  /\ bypassRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       staleRefused, replayRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

RefuseInvalidEnvelope ==
  /\ envelope \in {"FRESH", "EXPIRED", "REVOKED"}
  /\ \/ binding = "WRONG"
     \/ envelope \in {"EXPIRED", "REVOKED"}
  /\ ~staleRefused
  /\ staleRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, replayRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

InvokeThroughActuator ==
  /\ decision = "ALLOWED"
  /\ reservation = "RESERVED"
  /\ envelope = "FRESH"
  /\ binding = "EXACT"
  /\ effect = "NONE"
  /\ providerCalls = 0
  /\ envelope' = "CONSUMED"
  /\ effect' = "INVOKING"
  /\ providerCalls' = 1
  /\ providerCaller' = "ACTUATOR"
  /\ UNCHANGED <<
       decision, binding, bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

\* Deliberate mutation enabled only by the unsafe configuration. It represents
\* a Gate deployment that can reach the provider with a raw credential and
\* therefore bypass the execution-envelope boundary.
UnsafeDirectProviderCall ==
  /\ AllowDirectProviderCall
  /\ effect = "NONE"
  /\ providerCalls = 0
  /\ effect' = "INVOKING"
  /\ providerCalls' = 1
  /\ providerCaller' = "GATE"
  /\ UNCHANGED <<
       decision, envelope, binding, bypassRefused, staleRefused,
       replayRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

\* Deliberate mutation enabled only by the unsafe configuration. It represents
\* the pre-fix reconciliation, which DELETED the reservation on an authoritative
\* NOT_COMMITTED result. The action instance is unchanged, so re-presenting the
\* same evaluation record re-derives the byte-identical key and a fresh envelope
\* drives a second provider call on one human authorization.
UnsafeResurrectReleasedReservation ==
  /\ AllowReleasedReservationReuse
  /\ reservation = "RELEASED_NOT_ENTERED"
  /\ reservation' = "NONE"
  /\ envelope' = "NONE"
  /\ binding' = "NONE"
  /\ effect' = "NONE"
  /\ UNCHANGED <<
       decision, providerCalls, providerCaller, bypassRefused, staleRefused,
       replayRefused, reconciliationAuthenticated, reservationReleased,
       reReserveRefused
     >>

ProviderCommitted ==
  /\ effect = "INVOKING"
  /\ effect' = "COMMITTED"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

ProviderNotCommitted ==
  /\ effect = "INVOKING"
  /\ effect' = "NOT_COMMITTED"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

ProviderTimeout ==
  /\ effect = "INVOKING"
  /\ effect' = "INDETERMINATE"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated, reservation, reservationReleased,
       reReserveRefused
     >>

RefuseBlindReplay ==
  /\ effect = "INDETERMINATE"
  /\ envelope = "CONSUMED"
  /\ providerCalls = 1
  /\ ~replayRefused
  /\ replayRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, reconciliationAuthenticated, reservation,
       reservationReleased, reReserveRefused
     >>

ReconcileCommitted ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "COMMITTED"
  /\ reservation' = "CONSUMED"
  /\ reservationReleased' = reservationReleased
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused, reReserveRefused
     >>

\* s5.11: the authoritative non-entry is TERMINAL. The reservation is marked
\* released-not-entered rather than deleted, so it is never reservable again.
ReconcileNotCommitted ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "NOT_COMMITTED"
  /\ reservation' = "RELEASED_NOT_ENTERED"
  /\ reservationReleased' = TRUE
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused, reReserveRefused
     >>

ReconcileEscalated ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "ESCALATED"
  /\ reservation' = reservation
  /\ reservationReleased' = reservationReleased
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused, reReserveRefused
     >>

Next ==
  \/ AuthorizeExactAction
  \/ ReserveOneTimeUnit
  \/ RefuseReReserveAfterRelease
  \/ IssueExactEnvelope
  \/ IssueWrongEnvelope
  \/ ExpireEnvelope
  \/ RevokeEnvelope
  \/ RefuseGateBypass
  \/ RefuseInvalidEnvelope
  \/ InvokeThroughActuator
  \/ UnsafeDirectProviderCall
  \/ UnsafeResurrectReleasedReservation
  \/ ProviderCommitted
  \/ ProviderNotCommitted
  \/ ProviderTimeout
  \/ RefuseBlindReplay
  \/ ReconcileCommitted
  \/ ReconcileNotCommitted
  \/ ReconcileEscalated

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ decision \in DecisionStates
  /\ envelope \in EnvelopeStates
  /\ binding \in BindingStates
  /\ effect \in EffectStates
  /\ providerCalls \in 0..2
  /\ providerCaller \in Callers
  /\ bypassRefused \in BOOLEAN
  /\ staleRefused \in BOOLEAN
  /\ replayRefused \in BOOLEAN
  /\ reconciliationAuthenticated \in BOOLEAN
  /\ reservation \in ReservationStates
  /\ reservationReleased \in BOOLEAN
  /\ reReserveRefused \in BOOLEAN

ProviderAtMostOnce == providerCalls <= 1

EffectRequiresActuator ==
  providerCalls > 0 => providerCaller = "ACTUATOR"

EffectRequiresConsumedEnvelope ==
  providerCalls > 0 => envelope = "CONSUMED"

EffectRequiresExactDecision ==
  providerCalls > 0 =>
    /\ decision = "ALLOWED"
    /\ binding = "EXACT"

UncertainEffectBlocksReplay ==
  effect = "INDETERMINATE" =>
    /\ envelope = "CONSUMED"
    /\ providerCalls = 1

TerminalReconciliationIsAuthenticated ==
  reconciliationAuthenticated =>
    /\ effect \in TerminalEffects
    /\ providerCalls = 1

NoEnvelopeReopenAfterInvocation ==
  providerCalls > 0 => envelope = "CONSUMED"

\* s5.11. Once an authoritative non-entry has been reconciled, the one-time unit
\* stays released-not-entered forever: never AVAILABLE, never re-reserved, never
\* consumed by a late COMMITTED, and never the source of a second provider call.
ReleasedReservationNeverReReserved ==
  reservationReleased =>
    /\ reservation = "RELEASED_NOT_ENTERED"
    /\ providerCalls <= 1

InvocationRequiresReservedUnit ==
  providerCalls > 0 /\ providerCaller = "ACTUATOR" =>
    reservation \in {"RESERVED", "CONSUMED", "RELEASED_NOT_ENTERED"}

=============================================================================
