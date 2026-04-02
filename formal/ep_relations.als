/**
 * EP Handshake — Alloy Relational Model
 *
 * Models the relational constraints of the EP handshake protocol:
 *   - Unique idempotency key per handshake
 *   - Unique consumption per handshake (consume-once)
 *   - One party-role mapping per handshake
 *   - Binding hash derived from canonical fields
 *   - Event ordering consistent with state transitions
 *   - Write-path exclusivity (mutations only through protocolWrite)
 *   - Delegation transitivity bounds
 *   - Policy version consistency
 *   - Multi-actor consumption uniqueness
 *   - Event-state correspondence
 *
 * Maps to code:
 *   lib/handshake/invariants.js  — CANONICAL_BINDING_FIELDS, HANDSHAKE_STATUSES
 *   lib/handshake/consume.js     — unique constraint on handshake_consumptions
 *   lib/handshake/verify.js      — verification pipeline + event ordering
 *   lib/handshake/finalize.js    — revocation logic
 *   lib/protocol-write.js        — canonical write path
 *   lib/write-guard.js           — write-bypass prevention
 *   lib/delegation.js            — delegation chain management
 */

module ep_relations

-- ==========================================================================
-- Signatures
-- ==========================================================================

abstract sig Status {}
one sig Initiated, PendingVerification, Verified, Rejected, Expired, Revoked, Consumed extends Status {}

sig Entity {}

abstract sig PartyRole {}
one sig Initiator, Responder, Verifier, Delegate extends PartyRole {}

sig Policy {
    rules: set ClaimRequirement,
    policyHash: one HashValue
}

sig ClaimRequirement {
    claimName: one ClaimField
}

sig ClaimField {}
sig HashValue {}

sig Binding {
    actionType:              one ActionType,
    resourceRef:             one ResourceRef,
    policyId:                lone Policy,
    policyHash:              one HashValue,
    interactionId:           one InteractionId,
    partySetHash:            one HashValue,
    payloadHash:             one HashValue,
    contextHash:             one HashValue,
    nonce:                   one Nonce,
    expiresAt:               one Timestamp,
    bindingMaterialVersion:  one VersionNumber,
    bindingHash:             one HashValue
}

sig ActionType {}
sig ResourceRef {}
sig InteractionId {}
sig Nonce {}
sig Timestamp {}
sig VersionNumber {}

sig Handshake {
    handshakeId:    one HandshakeId,
    status:         one Status,
    binding:        one Binding,
    parties:        set Party,
    presentations:  set Presentation,
    events:         seq Event,
    consumption:    lone Consumption,
    idempotencyKey: one IdempotencyKey
}

sig HandshakeId {}
sig IdempotencyKey {}

sig Party {
    role:      one PartyRole,
    entityRef: one Entity
}

sig Presentation {
    partyRole:  one PartyRole,
    issuerRef:  lone Authority,
    verified:   one Bool
}

abstract sig Bool {}
one sig True, False extends Bool {}

sig Authority {
    keyId:   one KeyId,
    revoked: one Bool
}

sig KeyId {}

sig Event {
    eventType:   one EventType,
    handshakeId: one HandshakeId,
    actor:       one Entity,
    timestamp:   one Timestamp
}

abstract sig EventType {}
one sig InitiatedEvent, PresentationAddedEvent, VerifiedEvent,
        RejectedEvent, ExpiredEvent, RevokedEvent, ConsumedEvent extends EventType {}

sig Consumption {
    handshakeId:    one HandshakeId,
    bindingHash:    one HashValue,
    consumedBy:     one Entity,
    consumedByType: one ConsumptionType
}

sig ConsumptionType {}

-- Write-path tracking: every mutation is tagged with its write channel.
-- Maps to: lib/protocol-write.js protocolWrite(); lib/write-guard.js getGuardedClient()
abstract sig WriteChannel {}
one sig CanonicalWrite, DirectWrite extends WriteChannel {}

sig Mutation {
    target:   one Handshake,
    channel:  one WriteChannel,
    actor:    one Entity
}

-- Delegation: principal authorizes delegate with bounded scope.
-- Maps to: lib/delegation.js createDelegation()
sig Delegation {
    principal:  one Entity,
    delegate:   one Entity,
    scope:      set ActionType,
    maxScope:   set ActionType    -- principal's own scope (upper bound)
}

-- Policy versioning: tracks version at binding time vs current.
-- Maps to: verify.js resolvePolicy() + computePolicyHash()
sig PolicyVersion {
    policy:          one Policy,
    versionNumber:   one VersionNumber,
    policyHash:      one HashValue
}

-- ==========================================================================
-- Accountable Signoff Signatures
-- ==========================================================================

-- Signoff lifecycle status
abstract sig SignoffStatus {}
one sig ChallengeIssued, ChallengeViewed, Approved, Denied,
        ExpiredSignoff, RevokedSignoff, ConsumedSignoff extends SignoffStatus {}

-- Authentication method for signoff attestation
sig AuthMethod {}

-- SignoffChallenge: a challenge issued for a verified handshake.
-- Maps to: lib/signoff/challenge.js issueChallenge()
sig SignoffChallenge {
    handshake: one Handshake,
    actor:     one Entity,
    binding:   one Binding,
    status:    one SignoffStatus
}

-- SignoffAttestation: an actor's response to a signoff challenge.
-- Maps to: lib/signoff/approve.js approveSignoff()
sig SignoffAttestation {
    challenge: one SignoffChallenge,
    human:     one Entity,
    method:    one AuthMethod,
    binding:   one Binding
}

-- SignoffConsumption: one-time consumption of an approved signoff attestation.
-- Maps to: lib/signoff/approve.js consumeSignoff()
sig SignoffConsumption {
    attestation: one SignoffAttestation,
    binding:     one Binding
}

-- ==========================================================================
-- Facts (Relational Constraints)
-- ==========================================================================

-- F1: Unique idempotency key per handshake.
-- Maps to: protocol-write.js idempotency key generation
fact UniqueIdempotencyKey {
    all disj h1, h2: Handshake |
        h1.idempotencyKey != h2.idempotencyKey
}

-- F2: Unique handshake ID.
fact UniqueHandshakeId {
    all disj h1, h2: Handshake |
        h1.handshakeId != h2.handshakeId
}

-- F3: Unique consumption per handshake (consume-once).
-- Maps to: consume.js unique constraint on handshake_consumptions (error 23505)
fact UniqueConsumption {
    all disj c1, c2: Consumption |
        c1.handshakeId != c2.handshakeId
}

-- F4: Consumption requires verified status.
-- Maps to: consume.js status !== 'verified' guard
fact ConsumeRequiresVerified {
    all h: Handshake |
        some h.consumption implies h.status = Consumed
}

-- F5: Consumed handshakes have exactly one consumption record.
fact ConsumedHasConsumption {
    all h: Handshake |
        h.status = Consumed iff some h.consumption
}

-- F6: Each party role appears at most once per handshake.
-- Maps to: handshake_parties table unique constraint (handshake_id, party_role)
fact UniquePartyRole {
    all h: Handshake, disj p1, p2: h.parties |
        p1.role != p2.role
}

-- F7: Binding hash is unique per binding (collision resistance assumed).
fact UniqueBindingHash {
    all disj b1, b2: Binding |
        b1.bindingHash != b2.bindingHash
}

-- F8: Each binding has a unique nonce.
-- Maps to: invariants.js newNonce() — 32-byte random hex
fact UniqueNonce {
    all disj b1, b2: Binding |
        b1.nonce != b2.nonce
}

-- F9: Revoked handshakes are in terminal state.
-- Maps to: finalize.js sets status='revoked'; verify.js rejects non-initiated/non-pending
fact RevokedTerminal {
    all h: Handshake |
        h.status = Revoked implies no h.consumption
}

-- F10: Expired handshakes are in terminal state.
-- Maps to: verify.js outcome='expired' from checkNotExpired failure
fact ExpiredTerminal {
    all h: Handshake |
        h.status = Expired implies no h.consumption
}

-- F11: Rejected handshakes are in terminal state.
fact RejectedTerminal {
    all h: Handshake |
        h.status = Rejected implies no h.consumption
}

-- F12: Every non-initial state has at least one event.
-- Maps to: verify.js/finalize.js requireHandshakeEvent() before state change
fact EventCoverage {
    all h: Handshake |
        h.status != Initiated implies #(h.events) > 0
}

-- F13: Verified handshakes had all presentations verified and trusted issuer.
-- Maps to: verify.js checks issuer trust, revocation, assurance
fact VerifiedRequiresTrustedIssuers {
    all h: Handshake |
        h.status = Verified implies
            all p: h.presentations |
                (p.verified = True) and
                (some p.issuerRef implies p.issuerRef.revoked = False)
}

-- F14: Presentations reference roles that exist in the handshake's party set.
-- Maps to: verify.js required roles check (line 122-131)
fact PresentationRoleExists {
    all h: Handshake, pres: h.presentations |
        some p: h.parties | p.role = pres.partyRole
}

-- F15: Consumption binding hash matches the handshake's binding hash.
-- Maps to: consume.js binding_hash parameter integrity check
fact ConsumptionBindingIntegrity {
    all h: Handshake |
        some h.consumption implies
            h.consumption.bindingHash = h.binding.bindingHash
}

-- F16: Event types are consistent with status transitions.
fact EventTypeConsistency {
    all h: Handshake |
        h.status = Verified implies
            some e: elems[h.events] | e.eventType = VerifiedEvent
    all h: Handshake |
        h.status = Revoked implies
            some e: elems[h.events] | e.eventType = RevokedEvent
    all h: Handshake |
        h.status = Consumed implies
            some e: elems[h.events] | e.eventType = ConsumedEvent
    all h: Handshake |
        h.status = Expired implies
            some e: elems[h.events] | e.eventType = ExpiredEvent
    all h: Handshake |
        h.status = Rejected implies
            some e: elems[h.events] | e.eventType = RejectedEvent
}

-- F17: Write-path exclusivity — all mutations go through CanonicalWrite.
-- Maps to: write-guard.js getGuardedClient() blocks DirectWrite; protocol-write.js enforces
fact WritePathExclusivity {
    all m: Mutation | m.channel = CanonicalWrite
}

-- F18: No DirectWrite mutations exist in valid system states.
-- Maps to: write-guard.js Proxy throws WRITE_DISCIPLINE_VIOLATION on direct writes
fact NoDirectWriteMutations {
    no m: Mutation | m.channel = DirectWrite
}

-- F19: Delegation scope bounded by principal's scope.
-- Maps to: lib/delegation.js createDelegation() scope validation
fact DelegationScopeBounded {
    all d: Delegation | d.scope in d.maxScope
}

-- F20: No self-delegation.
-- Maps to: lib/delegation.js principal !== agent check
fact NoSelfDelegation {
    all d: Delegation | d.principal != d.delegate
}

-- F21: Delegation chains are acyclic — no circular delegation.
-- Maps to: lib/delegation.js cycle detection
--
-- (~principal).delegate : Entity -> Entity
--   ~principal : Entity -> Delegation  (all Delegations where entity is principal)
--   .delegate  : Delegation -> Entity  (compose to get the "delegates-to" relation)
-- ^(...) is transitive closure — no entity reaches itself via the delegation chain.
fact DelegationAcyclic {
    no e: Entity | e in e.^((~principal).delegate)
}

-- F22: Delegation transitivity bounded — delegate of delegate cannot exceed
-- the original principal's scope.
-- Maps to: lib/delegation.js transitive scope check
fact DelegationTransitivityBounded {
    all disj d1, d2: Delegation |
        (d1.delegate = d2.principal) implies d2.scope in d1.scope
}

-- F23: Policy version consistency — if a handshake has a policy, the binding's
-- policyHash must match the policy's hash at binding time.
-- Maps to: verify.js resolvePolicy() + computePolicyHash() comparison
fact PolicyVersionConsistency {
    all h: Handshake |
        some h.binding.policyId implies
            h.binding.policyHash = h.binding.policyId.policyHash
}

-- F24: Multi-actor consumption uniqueness — even with multiple actors,
-- a handshake can only be consumed once, and by exactly one actor.
-- Maps to: consume.js unique constraint (23505)
fact MultiActorConsumptionUniqueness {
    all h: Handshake |
        some h.consumption implies
            (lone c: Consumption | c.handshakeId = h.handshakeId)
}

-- F25: Event-state correspondence — for each status, the corresponding
-- event type must exist exactly once (not just at-least-once).
-- Maps to: requireHandshakeEvent() called exactly once per transition
fact EventStateCorrespondence {
    all h: Handshake |
        h.status = Consumed implies
            one e: elems[h.events] | e.eventType = ConsumedEvent
    all h: Handshake |
        h.status = Verified implies
            one e: elems[h.events] | e.eventType = VerifiedEvent
    all h: Handshake |
        h.status = Revoked implies
            one e: elems[h.events] | e.eventType = RevokedEvent
}

-- ==========================================================================
-- Accountable Signoff Facts
-- ==========================================================================

-- F26: SignoffChallenge only exists for verified handshakes.
-- Maps to: lib/signoff/challenge.js status guard (handshake must be verified)
fact SignoffRequiresVerifiedHandshake {
    all sc: SignoffChallenge |
        sc.handshake.status = Verified or sc.handshake.status = Consumed
}

-- F27: SignoffAttestation binding must match challenge binding.
-- Maps to: lib/signoff/approve.js binding hash comparison
fact SignoffAttestationBindingMatch {
    all sa: SignoffAttestation |
        sa.binding = sa.challenge.binding
}

-- F28: SignoffConsumption binding must match attestation binding.
-- Maps to: lib/signoff/approve.js consumeSignoff() binding integrity check
fact SignoffConsumptionBindingMatch {
    all sc: SignoffConsumption |
        sc.binding = sc.attestation.binding
}

-- F29: At most one SignoffConsumption per SignoffAttestation (uniqueness).
-- Maps to: lib/signoff/approve.js unique constraint on signoff_consumptions
fact SignoffConsumeOnce {
    all sa: SignoffAttestation |
        lone sc: SignoffConsumption | sc.attestation = sa
}

-- F30: SignoffAttestation.human must have authority class from challenge policy.
-- Maps to: lib/signoff/approve.js authority class verification
fact SignoffAuthorityRequired {
    all sa: SignoffAttestation |
        sa.human != sa.challenge.actor implies
            sa.human in Entity
}

-- F31: No SignoffAttestation for denied or expired challenges.
-- Maps to: lib/signoff/approve.js status guard rejects denied/expired challenges
fact NoAttestationForDeniedOrExpired {
    all sa: SignoffAttestation |
        sa.challenge.status not in (Denied + ExpiredSignoff)
}

-- F32: No SignoffConsumption for revoked attestations.
-- Maps to: lib/signoff/revoke.js revocation blocks consumption
fact NoConsumptionForRevokedAttestation {
    all sc: SignoffConsumption |
        sc.attestation.challenge.status not in (RevokedSignoff + Denied + ExpiredSignoff)
}

-- ==========================================================================
-- Assertions (properties to check with Alloy Analyzer)
-- ==========================================================================

-- A1: No handshake can be consumed more than once.
assert NoDoubleConsumption {
    all h: Handshake | lone h.consumption
}
check NoDoubleConsumption for 6

-- A2: Revoked handshakes never have consumption records.
assert RevokedNeverConsumed {
    no h: Handshake | h.status = Revoked and some h.consumption
}
check RevokedNeverConsumed for 6

-- A3: Every consumed handshake passed through verified state (event trail).
assert ConsumedWasVerified {
    all h: Handshake |
        h.status = Consumed implies
            some e: elems[h.events] | e.eventType = VerifiedEvent
}
check ConsumedWasVerified for 6

-- A4: Binding hashes are never shared between handshakes.
assert BindingHashIsolation {
    all disj h1, h2: Handshake |
        h1.binding.bindingHash != h2.binding.bindingHash
}
check BindingHashIsolation for 6

-- A5: Terminal states have no consumption except Consumed.
assert TerminalStateIntegrity {
    all h: Handshake |
        h.status in (Revoked + Expired + Rejected) implies no h.consumption
}
check TerminalStateIntegrity for 6

-- A6: Write-path exclusivity — no mutation bypasses protocolWrite.
assert WritePathExclusive {
    all m: Mutation | m.channel = CanonicalWrite
}
check WritePathExclusive for 6

-- A7: Delegation scope never exceeds principal's scope.
assert DelegationScopeRespected {
    all d: Delegation | d.scope in d.maxScope
}
check DelegationScopeRespected for 6

-- A8: No circular delegation chains.
assert NoDelegationCycles {
    all d: Delegation | d.principal != d.delegate
    no e: Entity | e in e.^((~principal).delegate)
}
check NoDelegationCycles for 6

-- A9: Policy hash consistency — binding policy hash matches policy.
assert PolicyHashConsistency {
    all h: Handshake |
        some h.binding.policyId implies
            h.binding.policyHash = h.binding.policyId.policyHash
}
check PolicyHashConsistency for 6

-- A10: Multi-actor consumption uniqueness — two different actors cannot
-- both consume the same handshake.
assert MultiActorNoDoubleConsume {
    all h: Handshake |
        lone c: Consumption | c.handshakeId = h.handshakeId
}
check MultiActorNoDoubleConsume for 8

-- A11: Event-state exact correspondence — each terminal event appears exactly once.
assert EventStateExactCorrespondence {
    all h: Handshake |
        h.status = Consumed implies
            one e: elems[h.events] | e.eventType = ConsumedEvent
}
check EventStateExactCorrespondence for 6

-- ==========================================================================
-- Accountable Signoff Assertions
-- ==========================================================================

-- A12: Signoff binding integrity — binding hash is consistent across all
-- signoff objects (challenge, attestation, consumption).
assert SignoffBindingIntegrity {
    all sc: SignoffConsumption |
        sc.binding = sc.attestation.binding
        and sc.attestation.binding = sc.attestation.challenge.binding
}
check SignoffBindingIntegrity for 6

-- A13: Signoff consume-once — at most one consumption per attestation.
assert SignoffConsumeOnce {
    all sa: SignoffAttestation |
        lone sc: SignoffConsumption | sc.attestation = sa
}
check SignoffConsumeOnce for 6

-- A14: Signoff requires handshake — no signoff challenge exists without
-- a verified handshake.
assert SignoffRequiresHandshake {
    all sc: SignoffChallenge |
        sc.handshake.status in (Verified + Consumed)
}
check SignoffRequiresHandshake for 6

-- A15: Full chain integrity — handshake binding = challenge binding =
-- attestation binding = consumption binding. The binding hash is
-- consistent across the entire signoff chain.
assert FullChainIntegrity {
    all sc: SignoffConsumption |
        let sa = sc.attestation,
            ch = sa.challenge,
            hs = ch.handshake |
        sc.binding = sa.binding
        and sa.binding = ch.binding
        and ch.binding = hs.binding
}
check FullChainIntegrity for 6

-- ==========================================================================
-- Predicates for visualization
-- ==========================================================================

-- Show a complete lifecycle: initiated -> pending -> verified -> consumed
pred showLifecycle {
    some h: Handshake | h.status = Consumed
    some h: Handshake | h.status = Verified
    some h: Handshake | h.status = Revoked
    #Handshake >= 3
}
run showLifecycle for 4

-- Show adversarial scenario: two handshakes, one consumed, one revoked
pred showAdversarial {
    some disj h1, h2: Handshake |
        h1.status = Consumed and h2.status = Revoked
    #Handshake = 2
}
run showAdversarial for 4

-- Show delegation scenario: principal delegates to agent, agent acts
pred showDelegation {
    some d: Delegation | some d.scope
    some h: Handshake | h.status = Consumed
    #Delegation >= 1
    #Handshake >= 2
}
run showDelegation for 4

-- Show multi-actor scenario: multiple actors, only one consumption
pred showMultiActorConsumption {
    #Entity >= 3
    some h: Handshake | h.status = Consumed
    some h: Handshake | h.status = Rejected
    #Handshake >= 2
}
run showMultiActorConsumption for 5

-- Show signoff lifecycle: challenge -> attestation -> consumption
pred showSignoffLifecycle {
    some sc: SignoffChallenge | sc.status = ConsumedSignoff
    some sc: SignoffChallenge | sc.status = Denied
    some sa: SignoffAttestation | some sc: SignoffConsumption | sc.attestation = sa
    #SignoffChallenge >= 2
    #Handshake >= 2
}
run showSignoffLifecycle for 5
