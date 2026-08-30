# Cedulon × AEB adoption packet

Status: **candidate for external review; no adoption claim**

This packet is the smallest path from the checked-in Cedulon Decision Token
crossing profile to one buyer-controlled pilot. It gives the native author a
short semantic checklist, gives an independent runner fixed reproduction
commands, and gives a buyer a fail-closed Gate pilot runbook.

## Scope

The profile verifies one pinned Cedulon Decision Token as pre-settlement
machine-policy evidence and maps the six fields evaluated by the Cedulon PDP
to one exact `cedulon.payment.attempt.1` action:

`amount`, `currency`, `payee`, `tool`, `nonce`, and `manifestHash`.

The current subset requires non-null `tool` and `manifestHash`. It pins the
source material identified in `../source-lock.json`; a different Cedulon
revision requires a new review and source lock.

## What a passing result means

A passing local run shows that, for the pinned fixtures and adapter:

- the configured Ed25519 issuer key, COSE envelope, claims, expiry, detached
  request, policy hash, and status inputs pass the profile checks;
- all six request fields map without loss to the expected CAID action; and
- the checked-in hostile vectors are refused or withheld as specified.

The native-author checklist asks whether that mapping preserves Cedulon's
intended semantics. The independent-run record shows that another operator ran
the fixed commands at an exact commit. The pilot runbook adds the production
controls that the offline profile cannot prove.

Cedulon's allow is consumed on the first settlement attempt, including a
fail-closed abort. `singleUseId` and `nonce` remain terminal in every outcome,
including `NOT_ENTERED`; reconciliation cannot restore them. Any retry requires
a newly issued Decision Token with fresh identities.

## Claim boundary

| Claim | This packet establishes it? |
| --- | --- |
| Deterministic reproduction of the pinned offline profile | Only after a runner records a passing exact-commit run |
| Native semantics preserved | Only after the native author confirms the checklist |
| Cedulon or EMILIA endorsement/certification | **No** |
| Human approval or authorization to enter a provider | **No** |
| Payment execution, settlement, finality, or rail completeness | **No** |
| Production deployment or complete mediation | **No** |
| Security of Cedulon, AEB, Gate, or the buyer's system in general | **No** |
| Compliance, audit opinion, or legal conclusion | **No** |

`SATISFIED` is evidence-requirement satisfaction for an exact action. Gate
still must make a separate local authorization decision at a buyer-controlled,
completely mediated provider boundary.

## Review order

1. Native author completes `native-author-confirmation.md` or supplies
   corrections. This confirms meaning, not endorsement.
2. An independent operator follows `independent-runner.md` and returns the
   resulting unsigned run record plus any external signature they choose.
3. A buyer executes `buyer-gate-pilot-runbook.md` in a non-production test
   environment before any live provider credential is introduced.

None of these steps may be described as completed until its named external
party returns the corresponding evidence.
