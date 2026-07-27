<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-1 conformance pack

This directory is the stable entry point for the open AEB-1 Consequence
Admission self-assessment.

- Profile: [`docs/conformance/AEB-1-CONSEQUENCE-ADMISSION.md`](../../docs/conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
- Vectors: [`conformance/vectors/aeb-consequence-conformance.v1.json`](../vectors/aeb-consequence-conformance.v1.json)
- Implementation: [`packages/verify/src/aeb-consequence-conformance.ts`](../../packages/verify/src/aeb-consequence-conformance.ts)
- Tests: [`packages/verify/aeb-consequence-conformance.test.ts`](../../packages/verify/aeb-consequence-conformance.test.ts)

Run the repository reference result with:

```sh
npm run conformance:aeb-1
```

The output is self-attested conformance evidence. It is not independent
certification, a production-deployment claim, or authorization for any action.
