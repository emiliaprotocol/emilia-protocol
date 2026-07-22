/**
 * Bounded relational model for the public experimental DTC Base settlement profile.
 *
 * This checks transition shape, not Solidity bytecode. The executable tests
 * connect the same invariants to the contract implementation.
 */
module dtc_base_escrow

abstract sig Status {}
one sig None, Reserved, Invoked, Indeterminate, Succeeded, Failed, Cancelled extends Status {}

one sig Configuration {
    budget: one Int
}

fact BoundedPositiveBudget {
    Configuration.budget = 3
}

sig Snapshot {
    status: one Status,
    locked: one Int,
    payerClaim: one Int,
    merchantClaim: one Int,
    consumed: one Int,
    settlementsPaused: one Int,
    providerRevoked: one Int
}

pred wellFormed[s: Snapshot] {
    s.locked >= 0
    s.payerClaim >= 0
    s.merchantClaim >= 0
    s.consumed = 0 or s.consumed = 1
    s.settlementsPaused = 0 or s.settlementsPaused = 1
    s.providerRevoked = 0 or s.providerRevoked = 1
    s.status = None iff s.consumed = 0
    s.status = None implies
        s.locked = 0 and s.payerClaim = 0 and s.merchantClaim = 0
    s.status in Reserved + Invoked + Indeterminate implies
        s.locked = Configuration.budget and s.payerClaim = 0 and s.merchantClaim = 0
    s.status in Succeeded + Failed + Cancelled implies
        s.locked = 0 and s.payerClaim + s.merchantClaim = Configuration.budget
}

pred reserve[a, b: Snapshot] {
    a.status = None
    b.status = Reserved
    b.locked = Configuration.budget
    b.payerClaim = 0
    b.merchantClaim = 0
    b.consumed = 1
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred invoke[a, b: Snapshot] {
    a.status = Reserved
    a.settlementsPaused = 0
    a.providerRevoked = 0
    b.status = Invoked
    b.locked = a.locked
    b.payerClaim = a.payerClaim
    b.merchantClaim = a.merchantClaim
    b.consumed = a.consumed
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred indeterminate[a, b: Snapshot] {
    a.status = Invoked
    a.settlementsPaused = 0
    a.providerRevoked = 0
    b.status = Indeterminate
    b.locked = a.locked
    b.payerClaim = 0
    b.merchantClaim = 0
    b.consumed = a.consumed
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred successAllocation[a, b: Snapshot] {
    a.status = Invoked or a.status = Indeterminate
    b.status = Succeeded
    b.locked = 0
    b.payerClaim >= 0
    b.merchantClaim > 0
    b.payerClaim + b.merchantClaim = a.locked
    b.consumed = a.consumed
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred failureAllocation[a, b: Snapshot] {
    a.status = Invoked or a.status = Indeterminate
    b.status = Failed
    b.locked = 0
    b.payerClaim = a.locked
    b.merchantClaim = 0
    b.consumed = a.consumed
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred providerSuccess[a, b: Snapshot] {
    a.settlementsPaused = 0
    a.providerRevoked = 0
    successAllocation[a, b]
}

pred providerFailure[a, b: Snapshot] {
    a.settlementsPaused = 0
    a.providerRevoked = 0
    failureAllocation[a, b]
}

pred agreementSuccess[a, b: Snapshot] {
    successAllocation[a, b]
}

pred agreementFailure[a, b: Snapshot] {
    failureAllocation[a, b]
}

pred cancel[a, b: Snapshot] {
    a.status = Reserved
    b.status = Cancelled
    b.locked = 0
    b.payerClaim = a.locked
    b.merchantClaim = 0
    b.consumed = a.consumed
    b.settlementsPaused = a.settlementsPaused
    b.providerRevoked = a.providerRevoked
}

pred step[a, b: Snapshot] {
    wellFormed[a]
    wellFormed[b]
    reserve[a, b] or invoke[a, b] or indeterminate[a, b]
        or providerSuccess[a, b] or providerFailure[a, b]
        or agreementSuccess[a, b] or agreementFailure[a, b] or cancel[a, b]
}

assert IndeterminatePreservesReservation {
    all a, b: Snapshot |
        step[a, b] and b.status = Indeterminate implies
            b.locked = a.locked and b.payerClaim = 0 and b.merchantClaim = 0
}
check IndeterminatePreservesReservation for 6 but 5 Int

assert TerminalTransitionsConserveValue {
    all a, b: Snapshot |
        step[a, b] and b.status in Succeeded + Failed + Cancelled implies
            b.locked = 0 and b.payerClaim + b.merchantClaim = a.locked
}
check TerminalTransitionsConserveValue for 6 but 5 Int

assert ReceiptConsumptionNeverReverses {
    all a, b: Snapshot | step[a, b] and a.consumed = 1 implies b.consumed = 1
}
check ReceiptConsumptionNeverReverses for 6 but 5 Int

assert TerminalStatesHaveNoOutgoingSettlementStep {
    all a, b: Snapshot |
        wellFormed[a] and a.status in Succeeded + Failed + Cancelled implies not step[a, b]
}
check TerminalStatesHaveNoOutgoingSettlementStep for 6 but 5 Int

assert CompromisedProviderCannotSettle {
    all a, b: Snapshot |
        wellFormed[a] and wellFormed[b]
            and (a.settlementsPaused = 1 or a.providerRevoked = 1)
            implies not providerSuccess[a, b] and not providerFailure[a, b]
}
check CompromisedProviderCannotSettle for 6 but 5 Int

run { some a, b: Snapshot | step[a, b] and b.status = Indeterminate } for 6 but 5 Int
run { some a, b: Snapshot | step[a, b] and b.status = Succeeded } for 6 but 5 Int
run {
    some a, b: Snapshot |
        wellFormed[a] and wellFormed[b]
            and a.settlementsPaused = 1 and a.providerRevoked = 1
            and agreementSuccess[a, b]
} for 6 but 5 Int
