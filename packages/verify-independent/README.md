# @emilia-protocol/verify-independent

Clean-room, zero-dependency implementation of the EMILIA Protocol conformance vector verifier.

This package contains the independent implementation logic (originally developed in examples/external-verification/out/run-independent.mjs).

## Usage

```js
import { verifyReceipt, verifyQuorum, ... } from '@emilia-protocol/verify-independent';
```

## Exported

- verifyReceipt
- verifyQuorum
- verifyTimestampProof
- verifyConsumptionProof
- evaluateCurrency
- validateInitiatorAttestation
- (supporting functions)

## Testing

```bash
npm test
```

Should report 161/161.

See INTEGRATION_REPORT.md for details.
