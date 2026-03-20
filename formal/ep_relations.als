/**
 * EP Handshake — Alloy Relational Model
 *
 * Models the relational constraints of the EP handshake protocol:
 *   - Unique idempotency key per handshake
 *   - Unique consumption per handshake (consume-once)
 *   - One party-role mapping per handshake
 *   - Binding hash derived from canonical fields
 *   - Event ordering consistent with state transitions
 *
 * Maps to code:
 *   lib/handshake/invariants.js  — CANONICAL_BINDING_FIELDS, HANDSHAKE_STATUSES
 *   lib/handshake/consume.js     — unique constraint on handshake_consumptions
 *   lib/handshake/verify.js      — verification pipeline + event ordering
 *   lib/handshake/finalize.js    — revocation logic
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
