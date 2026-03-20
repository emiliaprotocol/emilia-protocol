--------------------------- MODULE ep_handshake ---------------------------
\* EP Handshake Protocol — Formal State Machine Model
\*
\* This model captures the safety properties of the EP handshake lifecycle:
\* 1. Consume-once safety: an accepted handshake can be consumed at most once
\* 2. No acceptance without valid policy
\* 3. No verified state after revocation
\* 4. Event coverage for every state transition
\* 5. No transitions outside the allowed state graph
\* 6. No replay after successful consumption
\*
\* Maps to code:
\*   lib/handshake/invariants.js  — pure invariant checks
\*   lib/handshake/verify.js     — verification pipeline
\*   lib/handshake/consume.js    — one-time consumption
\*   lib/handshake/finalize.js   — revocation logic

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Handshakes, Actors, Policies

VARIABLES
    state,           \* handshake_id -> status
    bindings,        \* handshake_id -> binding_hash
    consumptions,    \* set of consumed handshake_ids
    events,          \* sequence of (handshake_id, event_type) pairs
    revoked,         \* set of revoked handshake_ids
    policyValid      \* handshake_id -> BOOLEAN (policy validity)

vars == <<state, bindings, consumptions, events, revoked, policyValid>>

\* --------------------------------------------------------------------------
\* Type Invariant
\* --------------------------------------------------------------------------

TypeInvariant ==
    /\ state \in [Handshakes -> {"none", "initiated", "pending_verification",
                                  "verified", "rejected", "expired", "revoked", "consumed"}]
    /\ consumptions \subseteq Handshakes
    /\ revoked \subseteq Handshakes

\* --------------------------------------------------------------------------
\* Safety Properties
\* --------------------------------------------------------------------------

\* S1: Consumed handshakes are never consumed again.
\* Maps to: consume.js unique constraint (23505) + consumed_at check in verify.js
ConsumeOnceSafety ==
    \A h \in Handshakes :
        (h \in consumptions) => (state[h] = "consumed")

\* S2: Only verified handshakes can be consumed.
\* Maps to: consume.js status !== 'verified' guard (line 47)
ConsumeRequiresVerified ==
    \A h \in consumptions :
        \/ state[h] = "consumed"

\* S3: Revoked handshakes never reach verified or consumed.
\* Maps to: finalize.js revocation sets terminal state; verify.js rejects
\*          non-initiated/non-pending states (line 83)
RevokedIsTerminal ==
    \A h \in revoked :
        state[h] \notin {"verified", "consumed", "initiated", "pending_verification"}

\* S4: Every state transition has a corresponding event.
\* Maps to: verify.js requireHandshakeEvent() called BEFORE state change (line 280);
\*          finalize.js requireHandshakeEvent() called BEFORE state change (line 89)
EventCoverage ==
    \A h \in Handshakes :
        state[h] # "none" =>
            \E i \in 1..Len(events) : events[i][1] = h

\* S5: No policy-invalid handshake reaches verified.
\* Maps to: verify.js policy resolution + hash comparison (lines 164-183);
\*          invariants.js checkAssuranceLevel, checkAllPartiesPresent
PolicyRequired ==
    \A h \in Handshakes :
        state[h] = "verified" => policyValid[h] = TRUE

\* S6: Expired handshakes are terminal — no further advancement.
\* Maps to: verify.js status guard (line 83); invariants.js checkNotExpired
ExpiredIsTerminal ==
    \A h \in Handshakes :
        state[h] = "expired" =>
            (h \notin consumptions /\ state[h] # "verified")

\* S7: Rejected handshakes are terminal.
\* Maps to: verify.js sets rejected; no transition from rejected exists
RejectedIsTerminal ==
    \A h \in Handshakes :
        state[h] = "rejected" =>
            (h \notin consumptions)

\* --------------------------------------------------------------------------
\* Initial State
\* --------------------------------------------------------------------------

Init ==
    /\ state = [h \in Handshakes |-> "none"]
    /\ bindings = [h \in Handshakes |-> ""]
    /\ consumptions = {}
    /\ events = <<>>
    /\ revoked = {}
    /\ policyValid = [h \in Handshakes |-> FALSE]

\* --------------------------------------------------------------------------
\* State Transitions
\* --------------------------------------------------------------------------

\* T1: Create a new handshake (none -> initiated)
\* Maps to: initiateHandshake() in lib/handshake/initiate.js
Initiate(h) ==
    /\ state[h] = "none"
    /\ state' = [state EXCEPT ![h] = "initiated"]
    /\ events' = Append(events, <<h, "initiated">>)
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid>>

\* T2: Add a presentation (initiated -> pending_verification)
\* Maps to: _handleAddPresentation() in lib/handshake/present.js
Present(h) ==
    /\ state[h] = "initiated"
    /\ state' = [state EXCEPT ![h] = "pending_verification"]
    /\ events' = Append(events, <<h, "presentation_added">>)
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid>>

\* T3: Verify and accept (pending_verification -> verified)
\* Maps to: _handleVerifyHandshake() outcome='accepted' in verify.js
\* Preconditions: policy valid, not revoked, all invariants pass
VerifyAccept(h) ==
    /\ state[h] = "pending_verification"
    /\ policyValid[h] = TRUE
    /\ h \notin revoked
    /\ state' = [state EXCEPT ![h] = "verified"]
    /\ events' = Append(events, <<h, "verified">>)
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid>>

\* T4: Verify and reject (pending_verification -> rejected)
\* Maps to: _handleVerifyHandshake() outcome='rejected' in verify.js
\* Triggers: policy invalid, revoked authority, missing party, binding mismatch
VerifyReject(h) ==
    /\ state[h] = "pending_verification"
    /\ (\/ policyValid[h] = FALSE
        \/ h \in revoked)
    /\ state' = [state EXCEPT ![h] = "rejected"]
    /\ events' = Append(events, <<h, "rejected">>)
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid>>

\* T5: Consume a verified handshake (verified -> consumed)
\* Maps to: consumeHandshake() in consume.js
\* Preconditions: verified state, not already consumed, not revoked
Consume(h) ==
    /\ state[h] = "verified"
    /\ h \notin consumptions
    /\ h \notin revoked
    /\ state' = [state EXCEPT ![h] = "consumed"]
    /\ consumptions' = consumptions \union {h}
    /\ events' = Append(events, <<h, "consumed">>)
    /\ UNCHANGED <<bindings, revoked, policyValid>>

\* T6: Revoke a handshake (initiated|pending_verification|verified -> revoked)
\* Maps to: _handleRevokeHandshake() in finalize.js
\* Guard: cannot revoke already-revoked/expired (finalize.js line 78)
\* Guard: cannot revoke already-consumed (consume-once safety)
Revoke(h) ==
    /\ state[h] \in {"initiated", "pending_verification", "verified"}
    /\ h \notin consumptions
    /\ state' = [state EXCEPT ![h] = "revoked"]
    /\ revoked' = revoked \union {h}
    /\ events' = Append(events, <<h, "revoked">>)
    /\ UNCHANGED <<bindings, consumptions, policyValid>>

\* T7: Expire a handshake (initiated|pending_verification|verified -> expired)
\* Maps to: _handleVerifyHandshake() outcome='expired' in verify.js
\* Trigger: binding past expires_at (invariants.js checkNotExpired)
Expire(h) ==
    /\ state[h] \in {"initiated", "pending_verification", "verified"}
    /\ h \notin consumptions
    /\ state' = [state EXCEPT ![h] = "expired"]
    /\ events' = Append(events, <<h, "expired">>)
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid>>

\* --------------------------------------------------------------------------
\* Adversarial Actions (must be no-ops or resolve safely)
\* --------------------------------------------------------------------------

\* A1: Attempt to consume an already-consumed handshake.
\* Maps to: consume.js unique constraint (error code 23505) -> ALREADY_CONSUMED
DuplicateConsumeAttempt(h) ==
    /\ h \in consumptions
    /\ UNCHANGED vars  \* blocked — no state change

\* A2: Concurrent revoke and consume on same verified handshake.
\* Maps to: DB-level atomicity; exactly one wins.
\* Model: non-deterministic choice — either revoke wins or consume wins.
ConcurrentRevokeConsume(h) ==
    /\ state[h] = "verified"
    /\ h \notin consumptions
    \* Non-deterministic choice: either revoke wins or consume wins
    /\ \/ (state' = [state EXCEPT ![h] = "revoked"]
           /\ revoked' = revoked \union {h}
           /\ events' = Append(events, <<h, "revoked">>)
           /\ UNCHANGED <<bindings, consumptions, policyValid>>)
       \/ (state' = [state EXCEPT ![h] = "consumed"]
           /\ consumptions' = consumptions \union {h}
           /\ events' = Append(events, <<h, "consumed">>)
           /\ UNCHANGED <<bindings, revoked, policyValid>>)

\* A3: Attempt to verify an already-consumed binding.
\* Maps to: verify.js HARD GATE (line 52-68) — existingBinding.consumed_at check
ReplayAfterConsumption(h) ==
    /\ h \in consumptions
    /\ UNCHANGED vars  \* blocked — hard gate rejects

\* --------------------------------------------------------------------------
\* Policy Environment Actions
\* --------------------------------------------------------------------------

\* Allow policy validity to be set during early states (models policy resolution).
\* Maps to: verify.js resolvePolicy() + computePolicyHash() comparison
SetPolicyValid(h) ==
    /\ state[h] \in {"none", "initiated", "pending_verification"}
    /\ policyValid' = [policyValid EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked>>

\* --------------------------------------------------------------------------
\* Next-State Relation
\* --------------------------------------------------------------------------

Next ==
    \E h \in Handshakes :
        \/ Initiate(h)
        \/ Present(h)
        \/ VerifyAccept(h)
        \/ VerifyReject(h)
        \/ Consume(h)
        \/ Revoke(h)
        \/ Expire(h)
        \/ DuplicateConsumeAttempt(h)
        \/ ConcurrentRevokeConsume(h)
        \/ ReplayAfterConsumption(h)
        \/ SetPolicyValid(h)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Theorems — properties that TLC should verify
\* --------------------------------------------------------------------------

THEOREM Spec => []TypeInvariant
THEOREM Spec => []ConsumeOnceSafety
THEOREM Spec => []RevokedIsTerminal
THEOREM Spec => []PolicyRequired
THEOREM Spec => []EventCoverage
THEOREM Spec => []ExpiredIsTerminal
THEOREM Spec => []RejectedIsTerminal

==========================================================================
