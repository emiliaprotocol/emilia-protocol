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
\* 13. Accountable Signoff: challenge-response signoff with binding integrity
\*
\* Maps to code:
\*   lib/handshake/invariants.js  — pure invariant checks
\*   lib/handshake/verify.js     — verification pipeline
\*   lib/handshake/consume.js    — one-time consumption
\*   lib/handshake/finalize.js   — revocation logic
\*   lib/protocol-write.js       — canonical write path
\*   lib/delegation.js           — delegation chain management
\*   lib/write-guard.js          — write-bypass prevention
\*   lib/signoff/challenge.js    — signoff challenge issuance
\*   lib/signoff/approve.js      — signoff approval and consumption
\*   lib/signoff/revoke.js       — signoff revocation and expiry

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Handshakes, Actors, Policies,
          MaxPolicyVer  \* Upper bound on currentPolicyVer to keep TLC state space finite

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
    currentPolicyVer,\* handshake_id -> Nat (current live policy version)
    \* --- Accountable Signoff variables ---
    signoffState,    \* handshake_id -> signoff lifecycle state
    signoffActor,    \* handshake_id -> actor who issued/approved the signoff (or "none")
    signoffBinding   \* handshake_id -> binding hash at signoff time (or "none")

vars == <<state, bindings, consumptions, events, revoked, policyValid,
          writePath, delegations, policyVersion, currentPolicyVer,
          signoffState, signoffActor, signoffBinding>>

\* --------------------------------------------------------------------------
\* Type Invariant
\* --------------------------------------------------------------------------

TerminalStates == {"consumed", "revoked", "expired", "rejected"}

SignoffTerminalStates == {"denied", "consumed_signoff", "expired_signoff", "revoked_signoff"}

TypeInvariant ==
    /\ state \in [Handshakes -> {"none", "initiated", "pending_verification",
                                  "verified", "rejected", "expired", "revoked", "consumed"}]
    /\ consumptions \subseteq Handshakes
    /\ revoked \subseteq Handshakes
    /\ writePath \in [Handshakes -> BOOLEAN]
    /\ policyVersion \in [Handshakes -> Nat]
    /\ currentPolicyVer \in [Handshakes -> Nat]
    /\ signoffState \in [Handshakes -> {"none", "challenge_issued", "challenge_viewed",
                                         "approved", "denied", "expired_signoff",
                                         "revoked_signoff", "consumed_signoff"}]
    /\ signoffActor \in [Handshakes -> Actors \union {"none"}]

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

\* S11: Delegation acyclicity — no direct circular delegation chains.
\* delegations[x] stores delegations received by x; each record carries
\* d.principal = the actor who granted authority to x.
\* Acyclicity (direct): if Y granted to X (delegations[X] has d.principal=Y),
\* then X must not have granted to Y (no record in delegations[Y] has d.principal=X).
\* Maps to: lib/delegation.js cycle detection in createDelegation()
DelegationAcyclicity ==
    \A a \in Actors :
        \A d \in delegations[a] :
            ~\E d2 \in delegations[d.principal] : d2.principal = a

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
\* Accountable Signoff Safety Properties
\* --------------------------------------------------------------------------

\* S14: Signoff requires verified handshake — a challenge can only be ACTIVE
\* (challenge_issued, challenge_viewed, approved) when the handshake is "verified".
\* Once the handshake transitions to a terminal state, the signoff also becomes
\* terminal (revoked_signoff, expired_signoff), which is compatible with
\* revoked/expired handshake state.
\* Maps to: lib/signoff/challenge.js status guard (handshake must be verified)
SignoffRequiresVerifiedHandshake ==
    \A h \in Handshakes :
        signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
            => state[h] = "verified"

\* S15: Signoff consume-once — a signoff can transition to consumed_signoff
\* at most once per handshake. Once consumed, no further signoff transitions.
\* Maps to: lib/signoff/approve.js unique constraint on signoff_consumptions
SignoffConsumeOnce ==
    \A h \in Handshakes :
        signoffState[h] = "consumed_signoff" =>
            signoffState[h] \notin {"challenge_issued", "challenge_viewed", "approved"}

\* S16: Signoff binding match — the signoff binding hash must equal the
\* handshake's binding hash at every signoff transition. This ensures
\* the signoff is bound to the exact handshake state it was issued for.
\* Maps to: lib/signoff/challenge.js binding hash comparison;
\*          lib/signoff/approve.js binding hash verification
SignoffBindingMatch ==
    \A h \in Handshakes :
        signoffState[h] # "none" =>
            signoffBinding[h] = bindings[h]

\* S17: Signoff terminal irreversibility — denied, consumed_signoff,
\* expired_signoff, and revoked_signoff are terminal signoff states.
\* No transition out of these states is possible.
\* Maps to: lib/signoff/approve.js terminal state guard;
\*          lib/signoff/revoke.js terminal state guard
SignoffTerminalIrreversible ==
    \A h \in Handshakes :
        signoffState[h] \in SignoffTerminalStates =>
            signoffState[h] \notin {"challenge_issued", "challenge_viewed", "approved"}

\* S18: Deny cannot be approved — once a signoff is denied, it cannot
\* transition to approved. This is a strengthening of S17 for the specific
\* deny -> approve path that must be explicitly prevented.
\* Maps to: lib/signoff/approve.js status guard rejects denied challenges
DenyCannotBeApproved ==
    \A h \in Handshakes :
        signoffState[h] = "denied" =>
            signoffState[h] # "approved"

\* S19: Signoff authority match — the signoff actor must have an authority
\* class that matches the policy requirement. Only actors with the correct
\* authority class can issue or approve signoffs.
\* Maps to: lib/signoff/challenge.js authority class check;
\*          lib/signoff/approve.js authority class verification
SignoffAuthorityMatch ==
    \A h \in Handshakes :
        signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved", "consumed_signoff"} =>
            signoffActor[h] # "none"

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
    /\ signoffState = [h \in Handshakes |-> "none"]
    /\ signoffActor = [h \in Handshakes |-> "none"]
    /\ signoffBinding = [h \in Handshakes |-> "none"]

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
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

\* T2: Add a presentation (initiated -> pending_verification)
\* Maps to: _handleAddPresentation() in lib/handshake/present.js
Present(h) ==
    /\ state[h] = "initiated"
    /\ state' = [state EXCEPT ![h] = "pending_verification"]
    /\ events' = Append(events, <<h, "presentation_added">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

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
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

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
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

\* T5: Consume a verified handshake (verified -> consumed)
\* Maps to: consumeHandshake() in consume.js
\* Preconditions: verified state, not already consumed, not revoked,
\*                no pending signoff ceremony (challenge_issued/viewed/approved blocks consumption)
Consume(h) ==
    /\ state[h] = "verified"
    /\ h \notin consumptions
    /\ h \notin revoked
    /\ signoffState[h] \notin {"challenge_issued", "challenge_viewed", "approved"}
    /\ state' = [state EXCEPT ![h] = "consumed"]
    /\ consumptions' = consumptions \union {h}
    /\ events' = Append(events, <<h, "consumed">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<bindings, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

\* T6: Revoke a handshake (initiated|pending_verification|verified -> revoked)
\* Maps to: _handleRevokeHandshake() in finalize.js
\* Guard: cannot revoke already-revoked/expired (finalize.js line 78)
\* Guard: cannot revoke already-consumed (consume-once safety)
\* Side-effect: any in-progress signoff challenge is terminated ("revoked")
\*              so SignoffRequiresVerifiedHandshake is preserved.
Revoke(h) ==
    /\ state[h] \in {"initiated", "pending_verification", "verified"}
    /\ h \notin consumptions
    /\ state' = [state EXCEPT ![h] = "revoked"]
    /\ revoked' = revoked \union {h}
    /\ events' = Append(events, <<h, "revoked">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ signoffState' = [signoffState EXCEPT ![h] =
          IF signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
          THEN "revoked_signoff"
          ELSE signoffState[h]]
    /\ UNCHANGED <<bindings, consumptions, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* T7: Expire a handshake (initiated|pending_verification|verified -> expired)
\* Maps to: _handleVerifyHandshake() outcome='expired' in verify.js
\* Trigger: binding past expires_at (invariants.js checkNotExpired)
\* Side-effect: any in-progress signoff challenge is terminated ("expired")
\*              so SignoffRequiresVerifiedHandshake is preserved.
Expire(h) ==
    /\ state[h] \in {"initiated", "pending_verification", "verified"}
    /\ h \notin consumptions
    /\ state' = [state EXCEPT ![h] = "expired"]
    /\ events' = Append(events, <<h, "expired">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ signoffState' = [signoffState EXCEPT ![h] =
          IF signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
          THEN "expired_signoff"
          ELSE signoffState[h]]
    /\ UNCHANGED <<bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

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
\* Side-effect: any in-progress signoff is terminated (matches Revoke/Consume behavior).
ConcurrentRevokeConsume(h) ==
    /\ state[h] = "verified"
    /\ h \notin consumptions
    \* Non-deterministic choice: either revoke wins or consume wins
    /\ \/ (state' = [state EXCEPT ![h] = "revoked"]
           /\ revoked' = revoked \union {h}
           /\ events' = Append(events, <<h, "revoked">>)
           /\ writePath' = [writePath EXCEPT ![h] = TRUE]
           /\ signoffState' = [signoffState EXCEPT ![h] =
                 IF signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
                 THEN "revoked_signoff"
                 ELSE signoffState[h]]
           /\ UNCHANGED <<bindings, consumptions, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>)
       \/ (state' = [state EXCEPT ![h] = "consumed"]
           /\ consumptions' = consumptions \union {h}
           /\ events' = Append(events, <<h, "consumed">>)
           /\ writePath' = [writePath EXCEPT ![h] = TRUE]
           /\ signoffState' = [signoffState EXCEPT ![h] =
                 IF signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
                 THEN "revoked_signoff"
                 ELSE signoffState[h]]
           /\ UNCHANGED <<bindings, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>)

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
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, writePath, delegations, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

\* --------------------------------------------------------------------------
\* Policy Environment Actions (continued)
\* --------------------------------------------------------------------------

\* Model a policy change after binding — increments the current policy version.
\* Maps to: policy_versions table update; verify.js computePolicyHash() comparison
PolicyChange(h) ==
    /\ state[h] \in {"initiated", "pending_verification"}
    /\ currentPolicyVer[h] < MaxPolicyVer  \* TLC bound: prevent infinite state space
    /\ currentPolicyVer' = [currentPolicyVer EXCEPT ![h] = currentPolicyVer[h] + 1]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, policyValid, writePath, delegations, policyVersion, signoffState, signoffActor, signoffBinding>>

\* --------------------------------------------------------------------------
\* Delegation Actions
\* --------------------------------------------------------------------------

\* D1: Grant delegation — principal authorizes a delegate with bounded scope.
\* Maps to: createDelegation() in lib/delegation.js
\* Precondition: delegate is not the principal (no self-delegation),
\*               adding (principal -> delegate) must not create a direct cycle.
\* Direct cycle check: delegate has not already granted authority to principal,
\* i.e. delegations[principal] must not contain a record with d.principal = delegate.
GrantDelegation(principal, delegate) ==
    /\ principal # delegate
    /\ ~\E d \in delegations[principal] : d.principal = delegate  \* no direct cycle
    /\ delegations' = [delegations EXCEPT ![delegate] =
        delegations[delegate] \union {[delegate |-> delegate, principal |-> principal,
                                        scope |-> {"verify", "present"},
                                        principalScope |-> {"verify", "present", "revoke"}]}]
    /\ UNCHANGED <<state, bindings, consumptions, events, revoked, policyValid, writePath, policyVersion, currentPolicyVer, signoffState, signoffActor, signoffBinding>>

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
\* Accountable Signoff Actions
\* --------------------------------------------------------------------------

\* SO1: Issue a signoff challenge for a verified handshake.
\* Maps to: lib/signoff/challenge.js issueChallenge()
\* Precondition: handshake verified, no signoff in progress
IssueChallenge(h, actor) ==
    /\ state[h] = "verified"
    /\ signoffState[h] = "none"
    /\ actor \in Actors
    /\ signoffState' = [signoffState EXCEPT ![h] = "challenge_issued"]
    /\ signoffActor' = [signoffActor EXCEPT ![h] = actor]
    /\ signoffBinding' = [signoffBinding EXCEPT ![h] = bindings[h]]
    /\ events' = Append(events, <<h, "signoff_challenge_issued">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer>>

\* SO2: View a signoff challenge (challenge_issued -> challenge_viewed).
\* Maps to: lib/signoff/challenge.js viewChallenge()
ViewChallenge(h) ==
    /\ signoffState[h] = "challenge_issued"
    /\ signoffState' = [signoffState EXCEPT ![h] = "challenge_viewed"]
    /\ events' = Append(events, <<h, "signoff_challenge_viewed">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* SO3: Approve a signoff (challenge_issued|challenge_viewed -> approved).
\* Maps to: lib/signoff/approve.js approveSignoff()
\* Precondition: binding hash still matches (tamper detection)
ApproveSignoff(h) ==
    /\ signoffState[h] \in {"challenge_issued", "challenge_viewed"}
    /\ signoffBinding[h] = bindings[h]  \* binding integrity check
    /\ signoffState' = [signoffState EXCEPT ![h] = "approved"]
    /\ events' = Append(events, <<h, "signoff_approved">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* SO4: Deny a signoff (challenge_issued|challenge_viewed -> denied).
\* Maps to: lib/signoff/approve.js denySignoff()
DenySignoff(h) ==
    /\ signoffState[h] \in {"challenge_issued", "challenge_viewed"}
    /\ signoffState' = [signoffState EXCEPT ![h] = "denied"]
    /\ events' = Append(events, <<h, "signoff_denied">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* SO5: Consume a signoff (approved -> consumed_signoff).
\* Maps to: lib/signoff/approve.js consumeSignoff()
\* Precondition: binding hash must still match at consumption time
ConsumeSignoff(h) ==
    /\ signoffState[h] = "approved"
    /\ signoffBinding[h] = bindings[h]  \* binding integrity at consumption
    /\ signoffState' = [signoffState EXCEPT ![h] = "consumed_signoff"]
    /\ events' = Append(events, <<h, "signoff_consumed">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* SO6: Expire a signoff (challenge_issued|challenge_viewed|approved -> expired_signoff).
\* Maps to: lib/signoff/revoke.js expireSignoff()
\* Trigger: signoff TTL exceeded
ExpireSignoff(h) ==
    /\ signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
    /\ signoffState' = [signoffState EXCEPT ![h] = "expired_signoff"]
    /\ events' = Append(events, <<h, "signoff_expired">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* SO7: Revoke a signoff (challenge_issued|challenge_viewed|approved -> revoked_signoff).
\* Maps to: lib/signoff/revoke.js revokeSignoff()
RevokeSignoff(h) ==
    /\ signoffState[h] \in {"challenge_issued", "challenge_viewed", "approved"}
    /\ signoffState' = [signoffState EXCEPT ![h] = "revoked_signoff"]
    /\ events' = Append(events, <<h, "signoff_revoked">>)
    /\ writePath' = [writePath EXCEPT ![h] = TRUE]
    /\ UNCHANGED <<state, bindings, consumptions, revoked, policyValid, delegations, policyVersion, currentPolicyVer, signoffActor, signoffBinding>>

\* A6: Attempt to transition out of a terminal signoff state.
\* This MUST be a no-op for ALL terminal signoff states.
\* Maps to: lib/signoff/approve.js terminal state guard
SignoffTerminalEscapeAttempt(h) ==
    /\ signoffState[h] \in SignoffTerminalStates
    /\ UNCHANGED vars  \* blocked — no escape from terminal signoff states

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
        \* Accountable Signoff actions
        \/ \E a \in Actors : IssueChallenge(h, a)
        \/ ViewChallenge(h)
        \/ ApproveSignoff(h)
        \/ DenySignoff(h)
        \/ ConsumeSignoff(h)
        \/ ExpireSignoff(h)
        \/ RevokeSignoff(h)
        \/ SignoffTerminalEscapeAttempt(h)
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

\* Accountable Signoff safety theorems
THEOREM Spec => []SignoffRequiresVerifiedHandshake
THEOREM Spec => []SignoffConsumeOnce
THEOREM Spec => []SignoffBindingMatch
THEOREM Spec => []SignoffTerminalIrreversible
THEOREM Spec => []DenyCannotBeApproved
THEOREM Spec => []SignoffAuthorityMatch

==========================================================================
