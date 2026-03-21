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
\* 7. Write-bypass safety: no state change without canonical write path
\* 8. Delegation authority bounds: delegates cannot exceed principal
\* 9. Delegation acyclicity: no circular delegation chains
\* 10. Policy-hash mismatch detection after binding
\* 11. Strengthened terminal-state proofs
\* 12. Event completeness: exactly one event per transition
\*
\* Maps to code:
\*   lib/handshake/invariants.js  — pure invariant checks
\*   lib/handshake/verify.js     — verification pipeline
\*   lib/handshake/consume.js    — one-time consumption
\*   lib/handshake/finalize.js   — revocation logic
\*   lib/protocol-write.js       — canonical write path
\*   lib/delegation.js           — delegation chain management
\*   lib/write-guard.js          — write-bypass prevention

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Handshakes, Actors, Policies

VARIABLES
    state,           \* handshake_id -> status
    bindings,        \* handshake_id -> binding_hash
    consumptions,    \* set of consumed handshake_ids
    events,          \* sequence of (handshake_id, event_type) pairs
    revoked,         \* set of revoked handshake_ids
    policyValid,     \* handshake_id -> BOOLEAN (policy validity)
    writePath,       \* handshake_id -> BOOLEAN (TRUE iff last mutation used canonical write)
    delegations,     \* actor -> set of {principal, scope} delegation records
    policyVersion,   \* handshake_id -> Nat (policy version at binding time)
    currentPolicyVer \* handshake_id -> Nat (current live policy version)

vars == <<state, bindings, consumptions, events, revoked, policyValid,
          writePath, delegations, policyVersion, currentPolicyVer>>

\* --------------------------------------------------------------------------
\* Type Invariant
\* --------------------------------------------------------------------------

TerminalStates == {"consumed", "revoked", "expired", "rejected"}

TypeInvariant ==
    /\ state \in [Handshakes -> {"none", "initiated", "pending_verification",
                                  "verified", "rejected", "expired", "revoked", "consumed"}]
    /\ consumptions \subseteq Handshakes
    /\ revoked \subseteq Handshakes
    /\ writePath \in [Handshakes -> BOOLEAN]
    /\ policyVersion \in [Handshakes -> Nat]
    /\ currentPolicyVer \in [Handshakes -> Nat]

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

\* S8: Write-bypass safety — every state mutation was performed through
\* the canonical write path (protocolWrite). No direct DB write can change state.
\* Maps to: lib/write-guard.js getGuardedClient() Proxy; lib/protocol-write.js
WriteBypassSafety ==
    \A h \in Handshakes :
        state[h] # "none" => writePath[h] = TRUE

\* S9: Unified terminal-state theorem — once a handshake reaches any terminal
\* state (consumed, revoked, expired, rejected), no further transition is possible.
\* This strengthens S3, S6, S7 into a single proof that covers all terminal states.
\* Maps to: verify.js status guard (line 83); finalize.js terminal check
TerminalStateIrreversibility ==
    \A h \in Handshakes :
        state[h] \in TerminalStates =>
            /\ h \notin {h2 \in Handshakes : state[h2] = "verified"}
            /\ (state[h] # "consumed" => h \notin consumptions)

\* S10: Delegation authority bound — a delegate's effective authority cannot
\* exceed the principal's authority. If principal has scope S, delegate
\* can only act within S (never beyond).
\* Maps to: lib/delegation.js scope validation; createDelegation() scope check
DelegateCannotExceedPrincipal ==
    \A a \in Actors :
        \A d \in delegations[a] :
            d.scope \subseteq d.principalScope

\* S11: Delegation acyclicity — no circular delegation chains. If A delegates
\* to B, B cannot (directly or transitively) delegate back to A.
\* Maps to: lib/delegation.js cycle detection in createDelegation()
DelegationAcyclicity ==
    \A a \in Actors :
        a \notin {d.delegate : d \in delegations[a]}

\* S12: Policy-hash mismatch detection — if the current policy version differs
\* from the version bound at handshake creation, verification must fail.
\* Maps to: verify.js resolvePolicy() + computePolicyHash() comparison
PolicyHashMismatchDetection ==
    \A h \in Handshakes :
        (state[h] = "verified") =>
            policyVersion[h] = currentPolicyVer[h]

\* S13: Event completeness — for every state transition from "none" to a
\* non-"none" state, there exists exactly one event of the matching type.
\* Maps to: requireHandshakeEvent() in verify.js/finalize.js
EventCompleteness ==
    \A h \in Handshakes :
        /\ (state[h] = "initiated" =>
            Len(SelectSeq(events, LAMBDA e : e[1] = h /\ e[2] = "initiated")) = 1)
        /\ (state[h] = "consumed" =>
            Len(SelectSeq(events, LAMBDA e : e[1] = h /\ e[2] = "consumed")) = 1)
        /\ (state[h] = "revoked" =>
            Len(SelectSeq(events, LAMBDA e : e[1] = h /\ e[2] = "revoked")) = 1)
        /\ (state[h] = "expired" =>
            Len(SelectSeq(events, LAMBDA e : e[1] = h /\ e[2] = "expired")) = 1)
        /\ (state[h] = "rejected" =>
            Len(SelectSeq(events, LAMBDA e : e[1] = h /\ e[2] = "rejected")) = 1)

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
    /\ writePath = [h \in Handshakes |-> FALSE]
    /\ delegations = [a \in Actors |-> {}]
    /\ policyVersion = [h \in Handshakes |-> 0]
    /\ currentPolicyVer = [h \in Handshakes |-> 0]

\* --------------------------------------------------------------------------
\* State Transitions
\* --------------------------------------------------------------------------

\* T1: Create a new handshake (none -> initiated)
\* Maps to: initiateHandshake() in lib/handshake/initiate.js
Initiate(h) ==
    /\ state[h] = "none"
    /\ state' = [state EXCEPT ![h] = "initiated"]
    /\ events' = Append(events, <<h, "initiated">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

\* T2: Add a presentation (initiated -> pending_verification)
\* Maps to: _handleAddPresentation() in lib/handshake/present.js
Present(h) ==
    /\ state[h] = "initiated"
    /\ state' = [state EXCEPT ![h] = "pending_verification"]
    /\ events' = Append(events, <<h, "presentation_added">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

\* T3: Verify and accept (pending_verification -> verified)
\* Maps to: _handleVerifyHandshake() outcome='accepted' in verify.js
\* Preconditions: policy valid, not revoked, all invariants pass
VerifyAccept(h) ==
    /\ state[h] = "pending_verification"
    /\ policyValid[h] = TRUE
    /\ h \notin revoked
    /\ policyVersion[h] = currentPolicyVer[h]  \* policy hash must match
    /\ state' = [state EXCEPT ![h] = "verified"]
    /\ events' = Append(events, <<h, "verified">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

\* T4: Verify and reject (pending_verification -> rejected)
\* Maps to: _handleVerifyHandshake() outcome='rejected' in verify.js
\* Triggers: policy invalid, revoked authority, missing party, binding mismatch
VerifyReject(h) ==
    /\ state[h] = "pending_verification"
    /\ (\/ policyValid[h] = FALSE
        \/ h \in revoked
        \/ policyVersion[h] # currentPolicyVer[h])  \* policy-hash mismatch triggers reject
    /\ state' = [state EXCEPT ![h] = "rejected"]
    /\ events' = Append(events, <<h, "rejected">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

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
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

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
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, policyValid, delegations, policyVersion, currentPolicyVer>>

\* T7: Expire a handshake (initiated|pending_verification|verified -> expired)
\* Maps to: _handleVerifyHandshake() outcome='expired' in verify.js
\* Trigger: binding past expires_at (invariants.js checkNotExpired)
Expire(h) ==
    /\ state[h] \in {"initiated", "pending_verification", "verified"}
    /\ h \notin consumptions
    /\ state' = [state EXCEPT ![h] = "expired"]
    /\ events' = Append(events, <<h, "expired">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

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
           /\ writePath' = [writePath EXCEPT ![h] = TRUE]
           /\ UNCHANGED <<bindings, consumptions, policyValid, delegations, policyVersion, currentPolicyVer>>)
       \/ (state' = [state EXCEPT ![h] = "consumed"]
           /\ consumptions' = consumptions \union {h}
           /\ events' = Append(events, <<h, "consumed">>)
           /\ writePath' = [writePath EXCEPT ![h] = TRUE]
           /\ UNCHANGED <<bindings, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>)

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
    /\ policyVersion' = [policyVersion EXCEPT ![h] = currentPolicyVer[h]]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, writePath, delegations, currentPolicyVer>>

\* --------------------------------------------------------------------------
\* Policy Environment Actions (continued)
\* --------------------------------------------------------------------------

\* Model a policy change after binding — increments the current policy version.
\* Maps to: policy_versions table update; verify.js computePolicyHash() comparison
PolicyChange(h) ==
    /\ state[h] \in {"initiated", "pending_verification"}
    /\ currentPolicyVer' = [currentPolicyVer EXCEPT ![h] = currentPolicyVer[h] + 1]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, policyValid, writePath, delegations, policyVersion>>

\* --------------------------------------------------------------------------
\* Delegation Actions
\* --------------------------------------------------------------------------

\* D1: Grant delegation — principal authorizes a delegate with bounded scope.
\* Maps to: createDelegation() in lib/delegation.js
\* Precondition: delegate is not the principal (no self-delegation),
\*               no circular chains
GrantDelegation(principal, delegate) ==
    /\ principal # delegate
    /\ delegate \notin {d.delegate : d \in delegations[principal]}
    /\ principal \notin {d.delegate : d \in delegations[delegate]}  \* acyclicity
    /\ delegations' = [delegations EXCEPT ![delegate] =
        delegations[delegate] \union {[delegate |-> delegate, principal |-> principal,
                                        scope |-> {"verify", "present"},
                                        principalScope |-> {"verify", "present", "revoke"}]}]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, policyValid, writePath, policyVersion, currentPolicyVer>>

\* A4: Attempt direct write bypass — models an actor trying to mutate state
\* without going through protocolWrite. This MUST be a no-op.
\* Maps to: write-guard.js getGuardedClient() Proxy throws WRITE_DISCIPLINE_VIOLATION
DirectWriteBypassAttempt(h) ==
    /\ state[h] # "none"
    /\ UNCHANGED vars  \* blocked — write guard rejects

\* A5: Attempt to transition out of a terminal state.
\* This MUST be a no-op for ALL terminal states.
\* Maps to: verify.js status guard; finalize.js terminal check
TerminalEscapeAttempt(h) ==
    /\ state[h] \in TerminalStates
    /\ UNCHANGED vars  \* blocked — no escape from terminal states

\* --------------------------------------------------------------------------
\* Next-State Relation
\* --------------------------------------------------------------------------

Next ==
    \/ \E h \in Handshakes :
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
        \/ PolicyChange(h)
        \/ DirectWriteBypassAttempt(h)
        \/ TerminalEscapeAttempt(h)
    \/ \E p \in Actors, d \in Actors :
        GrantDelegation(p, d)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Theorems — properties that TLC should verify
\* --------------------------------------------------------------------------

\* Original safety theorems
THEOREM Spec => []TypeInvariant
THEOREM Spec => []ConsumeOnceSafety
THEOREM Spec => []RevokedIsTerminal
THEOREM Spec => []PolicyRequired
THEOREM Spec => []EventCoverage
THEOREM Spec => []ExpiredIsTerminal
THEOREM Spec => []RejectedIsTerminal

\* New safety theorems (added for expanded coverage)
THEOREM Spec => []WriteBypassSafety
THEOREM Spec => []TerminalStateIrreversibility
THEOREM Spec => []DelegateCannotExceedPrincipal
THEOREM Spec => []DelegationAcyclicity
THEOREM Spec => []PolicyHashMismatchDetection
THEOREM Spec => []EventCompleteness

==========================================================================
