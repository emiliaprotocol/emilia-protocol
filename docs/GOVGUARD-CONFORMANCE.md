# GovGuard Conformance — GG-1

[![GovGuard: GG-1](https://img.shields.io/badge/GovGuard-GG--1-22c55e)](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/GOVGUARD-CONFORMANCE.md)

GG-1 is the minimum runtime bar for a GovGuard government-fraud control.

A GovGuard deployment earns **GG-1 Enforced** only when CI proves all of these
checks:

1. Missing receipt is refused before execution.
2. Wrong organization is refused.
3. Wrong approver is refused.
4. Self-approval is refused.
5. Class-C/software approval cannot satisfy a Class-A action.
6. Replayed receipt is refused.
7. Tampered amount, destination, or recipient is refused.
8. System-of-record execution mismatch is refused.
9. Observe-mode evidence export shows what enforce mode would have done.

Reference check:

```bash
npm run test:run -- tests/govguard-gg1-conformance.test.js
```

The reference implementation exercises the same primitives used by the v1 API:
tenant binding, GovGuard policy evaluation, Class-A assurance, one-time
consumption, execution-field binding, and the procurement evidence packet.

GG-1 is not fraud detection. It proves action-level control: high-risk
government payment, benefit, provider, and override actions cannot be treated as
authorized unless the receipt and execution binding match the policy.
