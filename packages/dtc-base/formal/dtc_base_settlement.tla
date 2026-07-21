--------------------------- MODULE dtc_base_settlement ---------------------------
EXTENDS Naturals

CONSTANTS Budget, Spend

ASSUME /\ Budget \in Nat \ {0}
       /\ Spend \in 1..Budget

VARIABLES status,
          locked,
          payerClaim,
          merchantClaim,
          payerPaid,
          merchantPaid,
          receiptConsumed,
          settlementsPaused,
          providerRevoked

vars == <<status, locked, payerClaim, merchantClaim,
          payerPaid, merchantPaid, receiptConsumed,
          settlementsPaused, providerRevoked>>

Statuses == {"NONE", "RESERVED", "INVOKED", "INDETERMINATE",
             "SUCCEEDED", "FAILED", "CANCELLED"}

Terminal == {"SUCCEEDED", "FAILED", "CANCELLED"}

Init ==
    /\ status = "NONE"
    /\ locked = 0
    /\ payerClaim = 0
    /\ merchantClaim = 0
    /\ payerPaid = 0
    /\ merchantPaid = 0
    /\ receiptConsumed = FALSE
    /\ settlementsPaused = FALSE
    /\ providerRevoked = FALSE

Reserve ==
    /\ status = "NONE"
    /\ status' = "RESERVED"
    /\ locked' = Budget
    /\ receiptConsumed' = TRUE
    /\ UNCHANGED <<payerClaim, merchantClaim, payerPaid, merchantPaid,
                   settlementsPaused, providerRevoked>>

Invoke ==
    /\ status = "RESERVED"
    /\ ~settlementsPaused
    /\ ~providerRevoked
    /\ status' = "INVOKED"
    /\ UNCHANGED <<locked, payerClaim, merchantClaim,
                   payerPaid, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

MarkIndeterminate ==
    /\ status = "INVOKED"
    /\ ~settlementsPaused
    /\ ~providerRevoked
    /\ status' = "INDETERMINATE"
    /\ UNCHANGED <<locked, payerClaim, merchantClaim,
                   payerPaid, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

SettleSuccess(fromStatus) ==
    /\ status = fromStatus
    /\ fromStatus \in {"INVOKED", "INDETERMINATE"}
    /\ status' = "SUCCEEDED"
    /\ locked' = 0
    /\ merchantClaim' = Spend
    /\ payerClaim' = Budget - Spend
    /\ UNCHANGED <<payerPaid, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

SettleFailure(fromStatus) ==
    /\ status = fromStatus
    /\ fromStatus \in {"INVOKED", "INDETERMINATE"}
    /\ status' = "FAILED"
    /\ locked' = 0
    /\ payerClaim' = Budget
    /\ merchantClaim' = 0
    /\ UNCHANGED <<payerPaid, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

ProviderSettleSuccess(fromStatus) ==
    /\ ~settlementsPaused
    /\ ~providerRevoked
    /\ SettleSuccess(fromStatus)

ProviderSettleFailure(fromStatus) ==
    /\ ~settlementsPaused
    /\ ~providerRevoked
    /\ SettleFailure(fromStatus)

AgreementSuccess(fromStatus) == SettleSuccess(fromStatus)

AgreementFailure(fromStatus) == SettleFailure(fromStatus)

CancelExpired ==
    /\ status = "RESERVED"
    /\ status' = "CANCELLED"
    /\ locked' = 0
    /\ payerClaim' = Budget
    /\ merchantClaim' = 0
    /\ UNCHANGED <<payerPaid, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

WithdrawPayer ==
    /\ payerClaim > 0
    /\ payerPaid' = payerPaid + payerClaim
    /\ payerClaim' = 0
    /\ UNCHANGED <<status, locked, merchantClaim, merchantPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

WithdrawMerchant ==
    /\ merchantClaim > 0
    /\ merchantPaid' = merchantPaid + merchantClaim
    /\ merchantClaim' = 0
    /\ UNCHANGED <<status, locked, payerClaim, payerPaid, receiptConsumed,
                   settlementsPaused, providerRevoked>>

PauseSettlements ==
    /\ ~settlementsPaused
    /\ settlementsPaused' = TRUE
    /\ UNCHANGED <<status, locked, payerClaim, merchantClaim, payerPaid,
                   merchantPaid, receiptConsumed, providerRevoked>>

UnpauseSettlements ==
    /\ settlementsPaused
    /\ settlementsPaused' = FALSE
    /\ UNCHANGED <<status, locked, payerClaim, merchantClaim, payerPaid,
                   merchantPaid, receiptConsumed, providerRevoked>>

RevokeProvider ==
    /\ ~providerRevoked
    /\ providerRevoked' = TRUE
    /\ UNCHANGED <<status, locked, payerClaim, merchantClaim, payerPaid,
                   merchantPaid, receiptConsumed, settlementsPaused>>

Next ==
    \/ Reserve
    \/ Invoke
    \/ MarkIndeterminate
    \/ ProviderSettleSuccess("INVOKED")
    \/ ProviderSettleSuccess("INDETERMINATE")
    \/ ProviderSettleFailure("INVOKED")
    \/ ProviderSettleFailure("INDETERMINATE")
    \/ AgreementSuccess("INVOKED")
    \/ AgreementSuccess("INDETERMINATE")
    \/ AgreementFailure("INVOKED")
    \/ AgreementFailure("INDETERMINATE")
    \/ CancelExpired
    \/ WithdrawPayer
    \/ WithdrawMerchant
    \/ PauseSettlements
    \/ UnpauseSettlements
    \/ RevokeProvider

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ status \in Statuses
    /\ locked \in Nat
    /\ payerClaim \in Nat
    /\ merchantClaim \in Nat
    /\ payerPaid \in Nat
    /\ merchantPaid \in Nat
    /\ receiptConsumed \in BOOLEAN
    /\ settlementsPaused \in BOOLEAN
    /\ providerRevoked \in BOOLEAN

MoneyConservation ==
    locked + payerClaim + merchantClaim + payerPaid + merchantPaid
        = IF receiptConsumed THEN Budget ELSE 0

ReceiptMatchesLifecycle == receiptConsumed = (status # "NONE")

NoClaimsBeforeTerminal ==
    status \in {"RESERVED", "INVOKED", "INDETERMINATE"}
        => payerClaim + merchantClaim = 0

IndeterminateFreezesFullBudget == status = "INDETERMINATE" => locked = Budget

TerminalUnlocksBudget == status \in Terminal => locked = 0

SuccessAllocationBounded ==
    status = "SUCCEEDED" => merchantClaim + merchantPaid = Spend

NoMerchantPaymentOnFailure ==
    status \in {"FAILED", "CANCELLED"} => merchantClaim + merchantPaid = 0

ProviderRevocationMonotonic ==
    [][providerRevoked => providerRevoked']_vars

=============================================================================
