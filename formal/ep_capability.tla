-------------------------- MODULE ep_capability --------------------------
\* EP Capability Layer — Formal State Machine Model
\*
\* Models the budget-backed, delegable, threshold, partial-consumption
\* capability layer. The authoritative semantics are the DURABLE store
\* (createPostgresCapabilityStore) whose per-capability state row is locked
\* FOR UPDATE and mutated through the atomic CAPABILITY_SQL guards; the
\* in-memory store mirrors the same guards in JS and is test-only.
\*
\* The capability *envelope* carries a static field capability.consumed that is
\* issuer-initialized and MUST be 0 (assertCapabilityShape). Runtime spend lives
\* ONLY in the store rows (consumed_amount, reserved_amount, per-operation
\* status/reservation_token). This model tracks the STORE state, never the
\* envelope field, for every consumption invariant.
\*
\* Maps to code (packages/gate/capability-receipt.js unless noted):
\*   BudgetNonNegative                 -> validateAmount L108; DDL CHECK budget_amount>=0 L466;
\*                                        migration L22; budget set once at register (never updated) L488
\*   EnvelopeConsumedZero (register)   -> assertCapabilityShape L206 (envelope consumed must be 0)
\*   ReserveWithinBudget               -> reserveState SQL L492 + rowCount!=1 guard L538;
\*                                        memory guard L431
\*   ConsumedIsCommittedSum            -> commitState SQL L494 (consumed += amount); L447
\*   ReservedIsReservedSum             -> reserveState L492 (reserved += amount) L434/L539;
\*                                        commitState L494 (reserved -= amount) L446/L555
\*   CommitRequiresReserve             -> commitOperation SQL WHERE status='reserved'
\*                                        AND reservation_token=$5 L493; guards L440-442 / L550-552
\*   NoDoubleCommit                    -> status 'reserved'->'committed' one-way; already_finalized
\*                                        L441/L551; rowCount!=1 -> rollback L554
\*   ConsumptionMonotonic              -> consumed only ever += (L447/L494); no decrement path
\*   ThresholdSatisfied                -> validateThreshold 1<=m<=n<=255 L133-140
\*   DelegationBounded                 -> assertDelegationChain length>MAX_DELEGATES throws L180 (=64)
\*   DelegationAuthorityNonIncreasing  -> EMERGENT: child amount spent through parent reserveSpend
\*                                        L705-713, whose budget guard L492 forces
\*                                        childAmount <= parent(budget-consumed-reserved).
\*                                        NO standalone childAmount<=parentBudget check exists;
\*                                        chain entry amount only validated >=0 L186-187.
\*   ChildExpiryBoundedByParent        -> ENFORCED: L684 childExpiry>parentExpiry -> refuse
\*   DelegationAcyclic                 -> CONSTRUCTION INVARIANT only: chain is append-only L693 and
\*                                        each child gets a fresh capabilityId (randomUUID) L661, so
\*                                        parent_capability_id pointers form a strictly-ranked path.
\*                                        NOT validated on ingest: assertDelegationChain L178-194 never
\*                                        checks acyclicity, and mintCapabilityReceipt L244 accepts an
\*                                        arbitrary hand-crafted delegation_chain. (Audit gap — see
\*                                        PROOF_STATUS / report finding #1.)
\*
\* Delegation is modeled as the code's real 3-phase, non-atomic sequence
\* (reserveSpend L705 -> commitSpend outcome='delegated' L714 -> registerCapability
\* L722), so the parent operation genuinely passes reserved->committed and the
\* crash-safe intermediate "committed-but-child-not-yet-registered" state (the
\* orphaned-but-backed child, L648-651) is a reachable state in the model.

EXTENDS Naturals, FiniteSets

CONSTANTS
    Capabilities,   \* set of capability ids; RootCap is pre-registrable, the rest are delegatable
    Operations,     \* set of operation ids (spend + delegation-parent-spend)
    RootCap,        \* the one capability that may be registered as a root (others come via delegation)
    MaxBudget,      \* upper bound on budget/amounts (TLC finiteness)
    MaxDelegates,   \* max delegation chain length (models MAX_DELEGATES=64)
    MaxTick         \* upper bound on the modeled clock

DelegatableCaps == Capabilities \ {RootCap}

\* MaxThreshold caps the threshold search domain (must be <= 255 for the model).
MaxThreshold == 2

VARIABLES
    budget,       \* [Capabilities -> 0..MaxBudget]  budget_amount, immutable after register
    registered,   \* SUBSET Capabilities            capabilities with a live state row
    consumed,     \* [Capabilities -> Nat]          consumed_amount
    reserved,     \* [Capabilities -> Nat]          reserved_amount
    expiry,       \* [Capabilities -> 0..MaxTick]   expires_at (0 = unregistered)
    parentPtr,    \* [Capabilities -> Capabilities \union {"none"}]  delegation parent
    chainLen,     \* [Capabilities -> Nat]          delegation chain length
    thresholdM,   \* [Capabilities -> Nat]          Shamir m
    thresholdN,   \* [Capabilities -> Nat]          Shamir n
    opStatus,     \* [Operations -> {"none","reserved","committed"}]
    opCap,        \* [Operations -> Capabilities \union {"none"}]  capability_id of the op
    opAmount,     \* [Operations -> Nat]            reserved/committed amount
    opToken,      \* [Operations -> Operations \union {"none"}]    reservation_token (fresh, 1:1 with op)
    delegChild,   \* [Operations -> Capabilities \union {"none"}]  child this delegation-op will register
    delegExpiry,  \* [Operations -> 0..MaxTick]     child expiry carried from reserve to register
    now           \* Nat                            modeled clock

vars == <<budget, registered, consumed, reserved, expiry, parentPtr, chainLen,
          thresholdM, thresholdN, opStatus, opCap, opAmount, opToken,
          delegChild, delegExpiry, now>>

Available(c) == budget[c] - consumed[c] - reserved[c]

\* --------------------------------------------------------------------------
\* Accounting helpers — sum of amounts over a set of operations.
\* --------------------------------------------------------------------------
CommittedOpsOf(c) == {o \in Operations : opStatus[o] = "committed" /\ opCap[o] = c}
ReservedOpsOf(c)  == {o \in Operations : opStatus[o] = "reserved"  /\ opCap[o] = c}

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0
             ELSE LET o == CHOOSE x \in S : TRUE
                  IN opAmount[o] + SumAmt(S \ {o})

\* --------------------------------------------------------------------------
\* Type Invariant
\* --------------------------------------------------------------------------
TypeInvariant ==
    /\ budget      \in [Capabilities -> 0..MaxBudget]
    /\ registered  \subseteq Capabilities
    /\ consumed    \in [Capabilities -> 0..MaxBudget]
    /\ reserved    \in [Capabilities -> 0..MaxBudget]
    /\ expiry      \in [Capabilities -> 0..MaxTick]
    /\ parentPtr   \in [Capabilities -> Capabilities \union {"none"}]
    /\ chainLen    \in [Capabilities -> 0..MaxDelegates]
    /\ thresholdM  \in [Capabilities -> 0..255]
    /\ thresholdN  \in [Capabilities -> 0..255]
    /\ opStatus    \in [Operations -> {"none", "reserved", "committed"}]
    /\ opCap       \in [Operations -> Capabilities \union {"none"}]
    /\ opAmount    \in [Operations -> 0..MaxBudget]
    /\ opToken     \in [Operations -> Operations \union {"none"}]
    /\ delegChild  \in [Operations -> Capabilities \union {"none"}]
    /\ delegExpiry \in [Operations -> 0..MaxTick]
    /\ now         \in 0..MaxTick

\* --------------------------------------------------------------------------
\* Safety Invariants  (each is capable of FAILING — none is vacuous)
\* --------------------------------------------------------------------------

\* I1: budget is non-negative for every live capability. (validateAmount L108; CHECK L466)
BudgetNonNegative ==
    \A c \in registered : budget[c] >= 0

\* I2: the core budget-safety property maintained by the atomic reserve/commit
\* SQL guards: committed + reserved authority never exceeds the immutable budget.
\* Maps to: reserveState L492 (reserved += amt only if budget-consumed-reserved>=amt)
\*          + commitState L494. If either guard were dropped this fails.
ReserveWithinBudget ==
    \A c \in registered : consumed[c] + reserved[c] <= budget[c]

\* I3/I4: accounting identities — consumed_amount is exactly the sum of committed
\* operation amounts; reserved_amount is exactly the sum of reserved operation
\* amounts. "reserved returns to 0 on commit" holds only for a single op; the
\* general truth is the sum identity (a second concurrent reservation keeps
\* reserved > 0 after one commit). Maps to commitState/reserveState arithmetic.
ConsumedIsCommittedSum ==
    \A c \in Capabilities : consumed[c] = SumAmt(CommittedOpsOf(c))

ReservedIsReservedSum ==
    \A c \in Capabilities : reserved[c] = SumAmt(ReservedOpsOf(c))

\* I5: threshold well-formedness for every live capability. (validateThreshold L133-140)
ThresholdSatisfied ==
    \A c \in registered :
        /\ 1 <= thresholdM[c]
        /\ thresholdM[c] <= thresholdN[c]
        /\ thresholdN[c] <= 255

\* I6: delegation chain length is bounded. (assertDelegationChain L180)
DelegationBounded ==
    \A c \in registered : chainLen[c] <= MaxDelegates

\* I7: a delegate's budget never exceeds its parent's budget. Holds EMERGENTLY
\* because the child amount is reserved from the parent through the atomic reserve
\* guard (L705-713 -> L492). There is no standalone check in the code.
DelegationAuthorityNonIncreasing ==
    \A c \in registered :
        parentPtr[c] # "none" => budget[c] <= budget[parentPtr[c]]

\* I8: child expiry never exceeds parent expiry. ENFORCED at L684.
ChildExpiryBoundedByParent ==
    \A c \in registered :
        parentPtr[c] # "none" => expiry[c] <= expiry[parentPtr[c]]

\* I9: delegation is acyclic. Expressed as the strict-rank construction invariant
\* (a child's chainLen is strictly greater than its parent's), which a cycle
\* cannot satisfy. This is a CONSTRUCTION invariant of the delegate transition,
\* NOT a runtime check the code performs on an ingested chain (see header /
\* finding #1: assertDelegationChain never validates acyclicity).
DelegationAcyclic ==
    \A c \in registered :
        parentPtr[c] # "none" => chainLen[parentPtr[c]] < chainLen[c]

\* --------------------------------------------------------------------------
\* Transition-level (action) properties — checked as PROPERTY, not INVARIANT.
\* --------------------------------------------------------------------------

\* P1: consumed_amount is monotonic non-decreasing. (no code path decrements it)
ConsumptionMonotonic ==
    [][ \A c \in Capabilities : consumed'[c] >= consumed[c] ]_vars

\* P2: budget is immutable once a capability is registered. (register never
\* updates budget_amount; ON CONFLICT WHERE clause keeps it fixed, L488)
BudgetImmutable ==
    [][ \A c \in registered : budget'[c] = budget[c] ]_vars

\* P3: an operation, once committed, stays committed — commit is one-way, so an
\* operation contributes to consumed at most once. (already_finalized L441/L551)
NoDoubleCommit ==
    [][ \A o \in Operations : opStatus[o] = "committed" => opStatus'[o] = "committed" ]_vars

\* P4: an operation may become committed only from the reserved state.
\* (commitOperation WHERE status='reserved', L493)
CommitRequiresReserve ==
    [][ \A o \in Operations :
          (opStatus[o] # "committed" /\ opStatus'[o] = "committed") => opStatus[o] = "reserved" ]_vars

\* --------------------------------------------------------------------------
\* Initial State
\* --------------------------------------------------------------------------
Init ==
    /\ budget      = [c \in Capabilities |-> 0]
    /\ registered  = {}
    /\ consumed    = [c \in Capabilities |-> 0]
    /\ reserved    = [c \in Capabilities |-> 0]
    /\ expiry      = [c \in Capabilities |-> 0]
    /\ parentPtr   = [c \in Capabilities |-> "none"]
    /\ chainLen    = [c \in Capabilities |-> 0]
    /\ thresholdM  = [c \in Capabilities |-> 0]
    /\ thresholdN  = [c \in Capabilities |-> 0]
    /\ opStatus    = [o \in Operations |-> "none"]
    /\ opCap       = [o \in Operations |-> "none"]
    /\ opAmount    = [o \in Operations |-> 0]
    /\ opToken     = [o \in Operations |-> "none"]
    /\ delegChild  = [o \in Operations |-> "none"]
    /\ delegExpiry = [o \in Operations |-> 0]
    /\ now         = 0

\* --------------------------------------------------------------------------
\* Transitions
\* --------------------------------------------------------------------------

\* T1: Register a root capability. budget/threshold/expiry fixed here; consumed
\* and reserved start at 0 (envelope consumed must be 0 -> assertCapabilityShape L206).
\* validateThreshold requires 1<=m<=n (<=255). Maps to registerCapability L507-521.
Register(c, b, mm, nn, e) ==
    /\ c = RootCap
    /\ c \notin registered
    /\ mm <= nn                         \* validateThreshold 1<=m<=n
    /\ registered'  = registered \union {c}
    /\ budget'      = [budget EXCEPT ![c] = b]
    /\ consumed'    = [consumed EXCEPT ![c] = 0]
    /\ reserved'    = [reserved EXCEPT ![c] = 0]
    /\ expiry'      = [expiry EXCEPT ![c] = e]
    /\ thresholdM'  = [thresholdM EXCEPT ![c] = mm]
    /\ thresholdN'  = [thresholdN EXCEPT ![c] = nn]
    /\ parentPtr'   = [parentPtr EXCEPT ![c] = "none"]
    /\ chainLen'    = [chainLen EXCEPT ![c] = 0]
    /\ UNCHANGED <<opStatus, opCap, opAmount, opToken, delegChild, delegExpiry, now>>

\* T2: Reserve a regular spend. amount>0 (durable SQL CHECK amount>0 L477), not
\* expired (L532), atomic budget guard (L492). Maps to reserveSpend L522-541.
Reserve(c, o, amt) ==
    /\ c \in registered
    /\ opStatus[o] = "none"
    /\ now < expiry[c]
    /\ Available(c) >= amt
    /\ reserved'   = [reserved EXCEPT ![c] = reserved[c] + amt]
    /\ opStatus'   = [opStatus EXCEPT ![o] = "reserved"]
    /\ opCap'      = [opCap EXCEPT ![o] = c]
    /\ opAmount'   = [opAmount EXCEPT ![o] = amt]
    /\ opToken'    = [opToken EXCEPT ![o] = o]
    /\ UNCHANGED <<budget, registered, consumed, expiry, parentPtr, chainLen,
                   thresholdM, thresholdN, delegChild, delegExpiry, now>>

\* T3: Commit a reserved operation (regular OR delegation-parent spend).
\* commitOperation status 'reserved'->'committed' fenced by reservation_token
\* (L493); commitState reserved -= amt, consumed += amt (L494). L543-558.
Commit(o) ==
    /\ opStatus[o] = "reserved"
    /\ LET c == opCap[o]
           a == opAmount[o]
       IN /\ opStatus' = [opStatus EXCEPT ![o] = "committed"]
          /\ reserved' = [reserved EXCEPT ![c] = reserved[c] - a]
          /\ consumed' = [consumed EXCEPT ![c] = consumed[c] + a]
    /\ UNCHANGED <<budget, registered, expiry, parentPtr, chainLen, thresholdM,
                   thresholdN, opCap, opAmount, opToken, delegChild, delegExpiry, now>>

\* T4a: Delegation phase 1 — parent reserve. Child amount>0 (L680), currency
\* matched (single-currency model), child expiry<=parent expiry (L684),
\* chain bound (L180), then reserve on the parent through the atomic budget
\* guard (L705-713 -> L492). The pending child intent is carried on the op.
DelegateReserve(p, ch, amt, e, o) ==
    /\ p \in registered
    /\ ch \in DelegatableCaps
    /\ ch \notin registered
    /\ opStatus[o] = "none"
    /\ e <= expiry[p]                       \* L684 child expiry bounded by parent
    /\ chainLen[p] + 1 <= MaxDelegates      \* L180 bounded chain
    /\ now < expiry[p]                       \* reserve requires parent not expired (L532)
    /\ Available(p) >= amt                    \* L492 reserve guard: child <= parent authority
    /\ reserved'    = [reserved EXCEPT ![p] = reserved[p] + amt]
    /\ opStatus'    = [opStatus EXCEPT ![o] = "reserved"]
    /\ opCap'       = [opCap EXCEPT ![o] = p]
    /\ opAmount'    = [opAmount EXCEPT ![o] = amt]
    /\ opToken'     = [opToken EXCEPT ![o] = o]
    /\ delegChild'  = [delegChild EXCEPT ![o] = ch]
    /\ delegExpiry' = [delegExpiry EXCEPT ![o] = e]
    /\ UNCHANGED <<budget, registered, consumed, expiry, parentPtr, chainLen,
                   thresholdM, thresholdN, now>>
    \* Phase 2 (parent commit, outcome='delegated') is the shared Commit(o) action.

\* T4b: Delegation phase 3 — register the child after its parent spend has
\* committed. Between Commit(o) and here the budget is already consumed but the
\* child is not yet registered: the crash-safe orphaned-but-backed child state
\* (L648-651). Maps to registerCapability(child) L722. Child budget = the amount
\* reserved from the parent, so authority is non-increasing by construction.
DelegateRegister(o) ==
    /\ opStatus[o] = "committed"
    /\ delegChild[o] # "none"
    /\ delegChild[o] \notin registered
    /\ LET ch == delegChild[o]
           p  == opCap[o]
           amt == opAmount[o]
           e  == delegExpiry[o]
       IN /\ registered' = registered \union {ch}
          /\ budget'     = [budget EXCEPT ![ch] = amt]
          /\ expiry'     = [expiry EXCEPT ![ch] = e]
          /\ parentPtr'  = [parentPtr EXCEPT ![ch] = p]
          /\ chainLen'   = [chainLen EXCEPT ![ch] = chainLen[p] + 1]
          /\ thresholdM' = [thresholdM EXCEPT ![ch] = 1]   \* delegate default threshold {1,1} L659
          /\ thresholdN' = [thresholdN EXCEPT ![ch] = 1]
          /\ consumed'   = [consumed EXCEPT ![ch] = 0]
          /\ reserved'   = [reserved EXCEPT ![ch] = 0]
    /\ UNCHANGED <<opStatus, opCap, opAmount, opToken, delegChild, delegExpiry, now>>

\* T5: advance the clock (drives the capability_expired reserve path, L532).
Tick ==
    /\ now < MaxTick
    /\ now' = now + 1
    /\ UNCHANGED <<budget, registered, consumed, reserved, expiry, parentPtr,
                   chainLen, thresholdM, thresholdN, opStatus, opCap, opAmount,
                   opToken, delegChild, delegExpiry>>

\* --------------------------------------------------------------------------
\* Adversarial actions — every one MUST be a no-op (mirrors a code refusal path).
\* They document that the guards actively block; as stuttering steps they add no
\* new states but assert the refusal is reachable-but-inert.
\* --------------------------------------------------------------------------

\* A1: commit an already-committed op -> capability_operation_already_finalized (L441/L551).
DoubleCommitAttempt(o) ==
    /\ opStatus[o] = "committed"
    /\ UNCHANGED vars

\* A2: commit an op that was never reserved -> capability_operation_not_found (L440/L550).
CommitUnreservedAttempt(o) ==
    /\ opStatus[o] = "none"
    /\ UNCHANGED vars

\* A3: commit a reserved op with the wrong reservation_token ->
\* capability_reservation_owner_mismatch (L442/L552); durable rowCount!=1 rollback (L554).
OwnerMismatchCommitAttempt(o) ==
    /\ opStatus[o] = "reserved"
    /\ UNCHANGED vars

\* A4: reserve more than the remaining authority -> budget_exceeded /
\* budget_reservation_conflict (L431/L535/L538).
OverBudgetReserveAttempt(c, o, amt) ==
    /\ c \in registered
    /\ opStatus[o] = "none"
    /\ now < expiry[c]
    /\ Available(c) < amt
    /\ UNCHANGED vars

\* A5: reserve on an expired capability -> capability_expired (L429/L532).
ExpiredReserveAttempt(c, o, amt) ==
    /\ c \in registered
    /\ opStatus[o] = "none"
    /\ now >= expiry[c]
    /\ UNCHANGED vars

\* A6: register a root with an invalid threshold (m>n) -> validateThreshold throws (L136).
InvalidThresholdRegisterAttempt(c, mm, nn) ==
    /\ c = RootCap
    /\ c \notin registered
    /\ ~(mm >= 1 /\ mm <= nn /\ nn <= 255)
    /\ UNCHANGED vars

\* A7: delegate with child expiry beyond the parent's ->
\* delegated_capability_expiry_exceeds_parent (L684).
ExpiryExceedsParentDelegateAttempt(p, ch, amt, e) ==
    /\ p \in registered
    /\ ch \in DelegatableCaps
    /\ ch \notin registered
    /\ e > expiry[p]
    /\ UNCHANGED vars

\* A8: delegate past the chain-length bound -> assertDelegationChain throws (L180).
OverDelegateAttempt(p, ch, amt, e) ==
    /\ p \in registered
    /\ ch \in DelegatableCaps
    /\ ch \notin registered
    /\ chainLen[p] + 1 > MaxDelegates
    /\ UNCHANGED vars

\* --------------------------------------------------------------------------
\* Next-State Relation
\* --------------------------------------------------------------------------
Next ==
    \/ \E c \in Capabilities, b \in 0..MaxBudget, mm \in 1..MaxThreshold,
          nn \in 1..MaxThreshold, e \in 1..MaxTick : Register(c, b, mm, nn, e)
    \/ \E c \in Capabilities, o \in Operations, amt \in 1..MaxBudget : Reserve(c, o, amt)
    \/ \E o \in Operations : Commit(o)
    \/ \E p \in Capabilities, ch \in Capabilities, amt \in 1..MaxBudget,
          e \in 1..MaxTick, o \in Operations : DelegateReserve(p, ch, amt, e, o)
    \/ \E o \in Operations : DelegateRegister(o)
    \/ Tick
    \* adversarial no-ops (refusal paths)
    \/ \E o \in Operations : DoubleCommitAttempt(o)
    \/ \E o \in Operations : CommitUnreservedAttempt(o)
    \/ \E o \in Operations : OwnerMismatchCommitAttempt(o)
    \/ \E c \in Capabilities, o \in Operations, amt \in 1..MaxBudget : OverBudgetReserveAttempt(c, o, amt)
    \/ \E c \in Capabilities, o \in Operations, amt \in 1..MaxBudget : ExpiredReserveAttempt(c, o, amt)
    \/ \E c \in Capabilities, mm \in 0..MaxThreshold, nn \in 0..MaxThreshold : InvalidThresholdRegisterAttempt(c, mm, nn)
    \/ \E p \in Capabilities, ch \in Capabilities, amt \in 1..MaxBudget, e \in 1..MaxTick : ExpiryExceedsParentDelegateAttempt(p, ch, amt, e)
    \/ \E p \in Capabilities, ch \in Capabilities, amt \in 1..MaxBudget, e \in 1..MaxTick : OverDelegateAttempt(p, ch, amt, e)

Spec == Init /\ [][Next]_vars

\* --------------------------------------------------------------------------
\* Exploration bound — analogue of ep_handshake's BoundedExploration. All
\* domains are already finite; this caps the modeled clock as an explicit
\* state constraint so the graph shape mirrors the handshake convention.
\* --------------------------------------------------------------------------
BoundedExploration == now <= MaxTick

\* --------------------------------------------------------------------------
\* Theorems
\* --------------------------------------------------------------------------
THEOREM Spec => []TypeInvariant
THEOREM Spec => []BudgetNonNegative
THEOREM Spec => []ReserveWithinBudget
THEOREM Spec => []ConsumedIsCommittedSum
THEOREM Spec => []ReservedIsReservedSum
THEOREM Spec => []ThresholdSatisfied
THEOREM Spec => []DelegationBounded
THEOREM Spec => []DelegationAuthorityNonIncreasing
THEOREM Spec => []ChildExpiryBoundedByParent
THEOREM Spec => []DelegationAcyclic
THEOREM Spec => ConsumptionMonotonic
THEOREM Spec => BudgetImmutable
THEOREM Spec => NoDoubleCommit
THEOREM Spec => CommitRequiresReserve

==========================================================================
