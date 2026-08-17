## 2026-07-06T23:20:37-04:00
You are the Clean-Room Verifier Developer.
Your workspace directory is: C:\Users\jkintzele\Documents\emilia-protocol\.agents\worker_verifier_implementation

### Mandatory Integrity Warning:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A Forensic Auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

### Task:
Develop a clean-room independent Node.js verifier runner in `examples/external-verification/out/run-independent.mjs` that verifies all 16 EMILIA Protocol conformance suites to achieve a 158/158 passing vector count, without importing or relying on `packages/verify/`.

1. Read the technical specifications at: `C:\Users\jkintzele\.gemini\antigravity-cli\brain\5c66dcda-fadb-41f1-b0e7-ced6dd6fd755\protocol_analyzer_specs.md`
2. Read the existing scratch module at: `C:\Users\jkintzele\.gemini\antigravity-cli\brain\9ea56448-e20d-42bb-b516-1a54e74679c1\scratch\verify_vectors.js`
3. Study the reference implementation files under `packages/verify/` to make sure your verifier logic behaves identically and passes all vector checks.
4. Your verifier MUST:
   - Use only native Node.js `crypto` modules (no external cryptographic dependencies).
   - Read the input JSON vector file path passed via `process.argv[2]`.
   - Process every vector inside it.
   - Output a JSON array of `{"id": "...", "valid": boolean}` to stdout.
5. Create a shell command or script that runs this runner against all 16 JSON vector suites located in `conformance/vectors/`, writing the output files into `examples/external-verification/out/results/<suite-file-name>.results.json`.
6. Run `node examples/external-verification/sign-statement.mjs --results examples/external-verification/out/results --verifier-id ext:verifier:cleanroom --verifier-name "Clean-Room" --org "Self-Verified" --implementation "NodeJS-Independent-Runner" --key examples/external-verification/out/private-key.pem --out examples/external-verification/out` to generate the Verification Statement.
7. Verify that all 158/158 vectors pass and the resulting `statement.json` has `result.status === 'verified'`.
8. Write a detailed `handoff.md` in your workspace directory detailing your work, how to execute the runner, and the verification output showing all 158 vectors passed.
