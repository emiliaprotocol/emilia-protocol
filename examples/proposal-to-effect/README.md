<!-- SPDX-License-Identifier: Apache-2.0 -->
# Proposal-to-Effect demo

This example runs the complete local orchestration path:

1. derive a short-lived, non-authoritative proposal from a material action;
2. verify a signed, relying-party-pinned AEB evaluation;
3. verify an `EP-RECEIPT-v1` with the real Gate;
4. reserve the operation before invoking the effect;
5. commit the operation after success; and
6. refuse a second attempt even when it presents another valid receipt.

From the repository root:

```bash
node examples/proposal-to-effect/demo.mjs
```

The example uses generated keys and in-memory stores. It is conformance and
integration evidence, not production deployment guidance. Production requires
durable Gate and AEB stores and an authenticated provider-evidence verifier for
reconciliation.
