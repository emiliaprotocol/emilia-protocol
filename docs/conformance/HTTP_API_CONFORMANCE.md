<!--
SPDX-License-Identifier: Apache-2.0
Copyright the EMILIA Protocol authors.
-->

# HTTP/API Conformance

Verifier conformance proves that JavaScript, Python, and Go agree on receipt
validity. HTTP/API conformance proves the adoption claim at the boundary where a
real system would mutate state.

An EMILIA Receipt Required API earns **HTTP-RR-1** when it demonstrates:

1. **Missing receipt -> 428.** The endpoint refuses before mutation and returns
   a machine-readable `Receipt-Required` challenge.
2. **Exact-action receipt -> runs.** A receipt bound to the exact action and
   target reaches the simulated executor.
3. **Replay -> refused.** The same receipt cannot authorize the action twice.
4. **Tamper -> refused.** A forged or modified receipt fails closed.
5. **Evidence -> exported.** The success response includes the receipt id,
   authorized action, policy id, and offline verification notes.

The public test target is:

```text
POST /api/demo/require-receipt
```

It covers three high-risk families:

- funds release
- repository deletion
- vendor bank-account change

Run the conformance check:

```bash
npx vitest run tests/http-api-conformance.test.js
```

Schema/security drift checks are separate operational gates and should continue
to run with:

```bash
npm run schema:security
```
