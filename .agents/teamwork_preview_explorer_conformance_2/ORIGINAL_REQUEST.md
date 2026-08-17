## 2026-07-07T05:14:39Z
You are a Conformance Suite Explorer.
Your working directory is: C:\Users\jkintzele\Documents\emilia-protocol\.agents\teamwork_preview_explorer_conformance_2
Please analyze:
1. The new vector added to `conformance/vectors/trust-receipt.exec.v1.json`:
   - `reject_pinned_class_a_bare_signature_downgrade`
2. How the reference implementation `packages/verify/index.js` handles trust receipt verification and class A/B key validation/pinning.
3. How `examples/external-verification/out/run-independent.mjs` implements `verifyTrustReceipt` and handles key class checks.
4. Recommend a precise fix strategy to update `run-independent.mjs` to properly implement these checks and return `valid: false` (matching `expect.valid`) for this vector.
Write your analysis and recommendations to a handoff.md in your working directory.
