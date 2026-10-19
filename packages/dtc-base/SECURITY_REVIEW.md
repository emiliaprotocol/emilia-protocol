# DTC Base implementer security review

**Status:** public implementer review; not an independent audit

**Deployment verdict:** do not deploy with customer funds or market as production DTC infrastructure.

## Reviewed artifacts

- `contracts/DTCBaseSettlement.sol`
- `contracts/interfaces/IDTCBaseSettlement.sol`
- `lib/receipt-program-bridge.ts` and its emitted declarations
- functional, hostile, audit-regression, and real Gate integration tests
- bounded TLA+ and Alloy models

Artifact hashes are recorded in `security/results/artifact-manifest.txt`; formal model hashes and bounded-run summaries
are recorded in `formal/results/`. Dedicated CI regenerates both in a temporary directory and fails closed on drift.

## Hostile-review findings and disposition

| Finding | Disposition | Enforcement evidence |
| --- | --- | --- |
| Executor could lock escrow using an arbitrary invocation hash | Closed | Provider must sign exact `Invocation`; executor identity is independently enforced; settlement pause blocks entry. |
| Signed authorization did not bind provider key | Closed | `providerSigner` and `providerConfigVersion` are EIP-712 fields and must equal the live merchant binding. |
| Provider outcome did not attest the invocation | Closed | Every `Outcome` signs `invocationHash` and `providerRequestId`; contract requires exact stored values. |
| Frozen compromised provider key could not be contained | Closed | Separate settlement pause plus irreversible signer revocation; provider finalization is blocked while party-agreement recovery remains available. |
| Reconciliation freshness was hash inequality only | Closed | Terminal evidence must sign the prior indeterminate digest and have a strictly later observation time. |
| One external consequence could settle multiple operations | Closed within the modeled merchant boundary | Merchant-scoped provider request, invocation, and evidence replay keys are single-use across signer rotation. |
| Nonce was signed but unenforced; receipt replay scope was ambiguous | Closed | Receipt and nonce keys are consumed under the authorization-signer and payer namespace. |
| Default admin could transfer immediately | Closed | OpenZeppelin delayed two-step default administration with a fixed 48-hour delay. |
| Contract claimants could strand pull-payment claims | Closed | `withdrawTo` lets the claimant redirect value without changing ownership of the claim. |

## Verification executed

- Solidity compile against Cancun EVM: pass.
- Strict TypeScript typecheck and build: pass.
- Hardhat functional/hostile/integration suite: pass.
- Production dependency audit (`npm audit --omit=dev`): zero reported vulnerabilities.
- Development-only toolchain audit: no high or critical advisory at the October 19, 2026 review.
  `http-cache-semantics` is pinned to 4.3.0, outside GHSA-ch52-4w7c-c8xp's affected range
  (`<=4.2.0`). Its October 4 release cleared the seven-day quarantine on October 11.
  The former exception is removed. CI fails on every high or critical advisory and on
  missing, malformed, or inconsistent audit data. Lower-severity development findings
  are not included in the separate production-dependency zero-vulnerability statement.
- Solidity coverage: high statement/function coverage; branch coverage remains below a production release target.
- TLC 2.19: complete bounded graph, eight invariants plus monotonic-revocation property, no error.
- Alloy 6.2.0: five assertions held, three scenarios satisfiable.
- Slither 0.11.5: no untriaged drain, reentrancy, access-control, or state-variable finding.

### Slither triage

Slither reports intended constructs that require human review:

- strict `amount == 0` check before withdrawal: exact zero is the intended absence-of-claim sentinel;
- timestamp comparisons: expiry and signed evidence-time windows are protocol semantics, not randomness;
- low-level value call in pull withdrawal: required to support contract recipients and guarded by checks-effects-interactions plus `nonReentrant`.

These are accepted design uses, not suppressed detector output.

## Residual release blockers

1. **No independent smart-contract audit.** This document and the hostile review were produced inside the implementation
   process.
2. **Two-ledger atomicity.** The receipt-program bridge coordinates EMILIA's capability ledger and Base through a saga,
   not one atomic transaction. A pre-effect Base failure is compensated on-chain, but the current Gate conservatively
   records the already-entered callback as indeterminate and consumes the capability reservation. Production requires a
   durable outbox/recovery design and an explicit operator runbook.
3. **Provider evidence trust.** The merchant-pinned provider adapter signs boundary and outcome evidence. The contract
   proves who signed and what was bound; it cannot prove that the external provider told the truth.
4. **Dispute liveness.** A revoked/unavailable provider can be bypassed only by an exact outcome signed by both payer and
   merchant. If they disagree, funds remain locked. Adding unilateral arbitration would create a new custody power and
   needs a separately reviewed trust model.
5. **Custody and legal perimeter.** This prototype directly holds native ETH. It is not the licensed external-custodian
   Action Escrow profile described by EMILIA's production architecture.
6. **Asset scope.** Native ETH only; no ERC-20, fee-on-transfer, bridge, chargeback, or fiat settlement semantics.
7. **Operations.** Production still needs multisig role owners, key ceremonies, monitoring, incident drills, verified
   source publication, RPC redundancy, and an independently operated reconciliation service.
8. **Formal scope.** TLA+ and Alloy check bounded abstract state machines, not Solidity bytecode, compiler correctness,
   provider behavior, or the cross-store saga.
9. **Development toolchain isolation.** The formerly excepted high advisory is patched,
   but an advisory-free result does not establish build-system safety. Keep the toolchain
   isolated before any production release process relies on it.

## Claim boundary

The public experimental artifact demonstrates an enforceable Base settlement profile joined to the real EMILIA receipt-program
kernel. It does not establish that the system is independently audited, deployed, legally an escrow service, or safe for
production funds. No Base mainnet target is configured.
