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
\* This is a finite safety abstraction. Signature soundness, credential-store
\* isolation, trusted time, provider truth, and linearizable durable storage are
\* explicit assumptions rather than claims proved by TLC.

EXTENDS Naturals

CONSTANT AllowDirectProviderCall

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
  reconciliationAuthenticated

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
  reconciliationAuthenticated
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

AuthorizeExactAction ==
  /\ decision = "NONE"
  /\ decision' = "ALLOWED"
  /\ UNCHANGED <<
       envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

IssueExactEnvelope ==
  /\ decision = "ALLOWED"
  /\ envelope = "NONE"
  /\ envelope' = "FRESH"
  /\ binding' = "EXACT"
  /\ UNCHANGED <<
       decision, effect, providerCalls, providerCaller, bypassRefused,
       staleRefused, replayRefused, reconciliationAuthenticated
     >>

IssueWrongEnvelope ==
  /\ decision = "ALLOWED"
  /\ envelope = "NONE"
  /\ envelope' = "FRESH"
  /\ binding' = "WRONG"
  /\ UNCHANGED <<
       decision, effect, providerCalls, providerCaller, bypassRefused,
       staleRefused, replayRefused, reconciliationAuthenticated
     >>

ExpireEnvelope ==
  /\ envelope = "FRESH"
  /\ envelope' = "EXPIRED"
  /\ UNCHANGED <<
       decision, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

RevokeEnvelope ==
  /\ envelope = "FRESH"
  /\ envelope' = "REVOKED"
  /\ UNCHANGED <<
       decision, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

RefuseGateBypass ==
  /\ providerCalls = 0
  /\ ~bypassRefused
  /\ bypassRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       staleRefused, replayRefused, reconciliationAuthenticated
     >>

RefuseInvalidEnvelope ==
  /\ envelope \in {"FRESH", "EXPIRED", "REVOKED"}
  /\ \/ binding = "WRONG"
     \/ envelope \in {"EXPIRED", "REVOKED"}
  /\ ~staleRefused
  /\ staleRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, replayRefused, reconciliationAuthenticated
     >>

InvokeThroughActuator ==
  /\ decision = "ALLOWED"
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
       reconciliationAuthenticated
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
       replayRefused, reconciliationAuthenticated
     >>

ProviderCommitted ==
  /\ effect = "INVOKING"
  /\ effect' = "COMMITTED"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

ProviderNotCommitted ==
  /\ effect = "INVOKING"
  /\ effect' = "NOT_COMMITTED"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

ProviderTimeout ==
  /\ effect = "INVOKING"
  /\ effect' = "INDETERMINATE"
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused,
       reconciliationAuthenticated
     >>

RefuseBlindReplay ==
  /\ effect = "INDETERMINATE"
  /\ envelope = "CONSUMED"
  /\ providerCalls = 1
  /\ ~replayRefused
  /\ replayRefused' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, effect, providerCalls, providerCaller,
       bypassRefused, staleRefused, reconciliationAuthenticated
     >>

ReconcileCommitted ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "COMMITTED"
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused
     >>

ReconcileNotCommitted ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "NOT_COMMITTED"
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused
     >>

ReconcileEscalated ==
  /\ effect = "INDETERMINATE"
  /\ effect' = "ESCALATED"
  /\ reconciliationAuthenticated' = TRUE
  /\ UNCHANGED <<
       decision, envelope, binding, providerCalls, providerCaller,
       bypassRefused, staleRefused, replayRefused
     >>

Next ==
  \/ AuthorizeExactAction
  \/ IssueExactEnvelope
  \/ IssueWrongEnvelope
  \/ ExpireEnvelope
  \/ RevokeEnvelope
  \/ RefuseGateBypass
  \/ RefuseInvalidEnvelope
  \/ InvokeThroughActuator
  \/ UnsafeDirectProviderCall
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

=============================================================================
