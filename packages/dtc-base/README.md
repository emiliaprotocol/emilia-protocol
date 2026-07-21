# DTC Base Settlement Profile (private experiment)

This package is an optional Base settlement profile for EMILIA. It binds a verified EMILIA authorization to a
native-ETH reservation, a provider-boundary marker, authenticated provider evidence, and a terminal certificate.

It is deliberately a **courthouse, not the DTC brain**. The current EMILIA Gate and receipt-program execution kernel
remain the source of authorization semantics, CAID resolution, bounded-capability checks, quorum, and evidence-chain
verification. This contract accepts a narrowly scoped EIP-712 attestation from an authorized bridge after those checks
have succeeded; it does not reimplement them in Solidity.

## Status

- Private and local only.
- Not independently audited.
- Not deployed.
- Not suitable for customer funds.
- Base Sepolia is the only configured remote network; there is no Base mainnet target.
- The off-chain bridge and operational scripts are strict TypeScript; the on-chain state machine is Solidity.

## State machine

```text
NONE -> RESERVED -> INVOKED -> SUCCEEDED
                 |         -> FAILED
                 |         -> INDETERMINATE -> SUCCEEDED
                 |                          -> FAILED
                 -> CANCELLED (only after expiry and before provider entry)
```

`INDETERMINATE` is intentionally sticky. It keeps the full reservation locked and rejects blind replay. It can reach a
terminal state through fresh, causally chained provider evidence plus a reconciler, or through an exact terminal outcome
signed by both payer and merchant. Provider-signed boundary entry is required before `INVOKED`; the executor cannot lock
funds by asserting an unconfirmed request hash.

## Security invariants

1. Every material instruction field is signed and frozen: receipt, CAID, action, program, input, payer, executor,
   merchant, amount, expiry, provider signer and configuration version, authorization signer, and nonce.
2. The EIP-712 domain binds signatures to one chain and one contract.
3. Receipt and nonce replay keys are namespaced by authorization signer and payer and remain consumed after success,
   failure, or cancellation.
4. The frozen provider must sign the exact invocation and provider request ID before the frozen executor can mark entry.
5. Provider signer and configuration version are part of the signed authorization and snapshotted at reservation.
6. Outcomes sign the exact invocation, provider request, prior outcome digest, evidence, amount, and observation time.
7. Provider request, invocation, and evidence replay keys prevent one external record from settling multiple operations.
8. Reconciliation evidence must be temporally newer and cryptographically chained to the indeterminate outcome.
9. A provider signer can be revoked permanently; its in-flight operations can then settle only by payer/merchant
   agreement. A separate settlement pause blocks provider finalization without blocking party recovery or withdrawals.
10. No cancellation or unilateral refund is possible after provider-confirmed entry.
11. Terminal settlement uses pull payments, supports redirected withdrawal, and cannot run twice.
12. `totalLocked + totalClaimable` tracks contract liabilities. Forced ETH can make the raw balance larger, never
   smaller; this package intentionally exposes no administrator sweep.
13. Default administration uses OpenZeppelin's delayed two-step transfer with a fixed 48-hour delay.

## Trust boundaries and limitations

- The bridge signer is trusted to have verified the canonical EMILIA receipt and the exact CAID/action/program/input
  join. A bridge compromise can authorize an invalid reservation.
- The provider signer is trusted to report the external effect honestly. A provider compromise can lie about outcome
  or amount within the authorized maximum.
- The administrator controls signer roles and provider bindings. The delayed transfer reduces accidental or instant
  admin replacement, but production still needs a multisig and reviewed role/key ceremonies.
- If the provider is unavailable and payer and merchant cannot agree, funds remain locked. A unilateral arbitration
  path would create a new custody/trust power and is deliberately not hidden inside this prototype.
- This profile handles native ETH only. It does not support ERC-20 tokens, fee-on-transfer assets, chargebacks,
  licensed fiat custody, or legal escrow.
- EIP-712 verifies secp256k1 EOAs and EIP-1271 smart wallets. It does not claim to verify EMILIA's Ed25519 or ML-DSA
  signatures on-chain; those remain in the bridge verification boundary.
- The terminal certificate is a deterministic on-chain commitment, not a representation that the external evidence is
  legally conclusive.

## Run locally

```bash
npm ci
npm run verify
npm run formal:verify
npm run demo
```

The demo executes the decisive failure mode: the provider boundary is entered, the first response is indeterminate,
the full value remains frozen, and fresh provider-signed evidence is required before settlement.

## Guarded Base Sepolia deployment

Copy `.env.example`, provide non-development keys, and review `scripts/deploy.ts`. The script refuses unsupported
chains and refuses a remote deployment unless the explicit private/unaudited acknowledgement is present.

```bash
npm run deploy:base-sepolia
```

Deployment is not audit, production authorization, or permission to hold customer funds.

## Artifact map

- `contracts/DTCBaseSettlement.sol` — settlement and evidence state machine.
- `contracts/interfaces/IDTCBaseSettlement.sol` — stable contract surface.
- `test/DTCBaseSettlement.test.cjs` — functional acceptance suite.
- `test/DTCBaseSettlement.hostile.test.cjs` — adversarial and replay suite.
- `scripts/demo.ts` — typed, runnable indeterminate-to-reconciled scenario.
- `scripts/deploy.ts` — typed, fail-closed Base Sepolia deployment.
- `lib/receipt-program-bridge.ts` — strict TypeScript Gate receipt-program to Base saga adapter and public types.
- `test/DTCReceiptProgram.integration.test.cjs` — executed/indeterminate/pre-effect cross-ledger vectors.
- `test/ReceiptProgramBridge.characterization.test.cjs` — deterministic-hash and fail-closed API contract.
- `tsconfig.json` — strict NodeNext compiler contract; generated `dist/` output is local and ignored.
- `formal/dtc_base_settlement.tla` — bounded transition-system model.
- `formal/dtc_base_escrow.als` — relational transition model.
- `SECURITY_REVIEW.md` — hostile findings, static-analysis triage, and release blockers.
