# Regulatory mobile oversight, end to end

This example turns the native mobile ceremony into a portable evidence package
for a regulator or independent auditor. It is jurisdiction-neutral, uses only
synthetic records, and claims no government or health-plan deployment.

## Run it

```sh
npm run mobile:regulator-demo

node examples/regulatory-mobile-oversight/verify-export.mjs \
  examples/regulatory-mobile-oversight/out/evidence.json \
  examples/regulatory-mobile-oversight/out/regulator-pins.json
```

The first command runs the protected workflow and writes two files. The second
simulates a later offline review with the operator unavailable.

- `evidence.json` is the evidence presented by the regulated operator.
- `regulator-pins.json` is the relying party's trust bundle. It is separate on
  purpose: a verifier must provision these keys and policies out of band, never
  accept replacement keys carried by the evidence under review.

Generated output is ignored by Git.

## The complete path

```text
synthetic system of record
  -> CAID for the exact action
  -> server-resolved action and review presentation
  -> EP-MOBILE-CHALLENGE-v1
  -> user-verified P-256 passkey assertion
  -> context-bound platform-attestation verification
  -> atomic one-time challenge consumption
  -> strict atomic audit append
  -> Class-A EP authorization receipt
  -> signed operator execution record
  -> portable evidence + separately provisioned regulator pins
  -> local acceptance of the same evidence package
  -> synthetic system-of-record update
  -> offline accept/refuse report
```

The Node client constructs the same WebAuthn assertion bytes consumed by the
native iOS and Android reference apps. For repeatable CI it uses a cryptographic
platform-attestation test double through the real App Attest adapter. It does
**not** obtain or claim an Apple assertion. A production pilot replaces that
single injected verifier with Apple certificate/assertion validation or the
official Google Play Integrity server response.

The native Android reference app already sends the same challenge and ceremony
objects to the same server controller. The Node path is the deterministic CI
driver, not evidence of a live-device ceremony. A regulator-facing field run
must capture an assertion from the native app on enrolled hardware and preserve
the platform provider's server-verification record.

The runnable fixture marks the included in-memory challenge and audit backends
as durable only to exercise the service contract. That is not deployment
evidence. Enforcement requires transactional durable implementations, outage
drills, and an independently reviewed retention and recovery design.

## What the auditor learns

The offline verifier directly recomputes:

- the CAID and exact action digest;
- the Class-A passkey signature under an out-of-band pinned reviewer key;
- WebAuthn user-presence and user-verification flags;
- policy, RP ID, origin, app, enrollment, action, and presentation joins;
- receipt-log inclusion and its pinned checkpoint signature; and
- the operator execution-record signature and exact audit-record join.

The execution record is explicitly an `operator_runtime_attestation`. Its
signature makes the operator accountable for stating that platform attestation,
one-time consumption, and durable audit append passed at execution time. Those
three runtime facts are not independently replayed against Apple, Google, or the
operator's storage during offline review.

The example does not update even its synthetic system of record until the
generated package passes the same verifier used by the later auditor. Evidence
construction or local verification failure therefore leaves the action
unexecuted and requires a fresh challenge.

The package does not establish clinical correctness, legal compliance, reviewer
licensure beyond the regulator's own directory, comprehension, honest display
pixels on a compromised device, complete mediation, or real-world effect.

## Privacy boundary

All identifiers and codes in this example are conspicuously synthetic. That is
why the generated fixture contains no real PHI. This is not a claim that hashing
an MRN makes a production receipt non-PHI: patient-linked hashes and
pseudonymous identifiers can remain regulated data. A real deployment needs a
documented minimum-necessary schema, disclosure purpose, retention policy,
access controls, and any required BAA or equivalent agreement.

## Regulator acceptance path

Use this demo in shadow mode first. A pilot is ready for enforcement only after
the regulator or its independent reviewer has:

1. provisioned the reviewer, log, runtime-statement, RP, app, and profile pins;
2. inspected the system-of-record mapping for every material field;
3. run tamper, key-substitution, replay, storage-outage, attestation-outage, and
   bypass drills;
4. confirmed accessibility, records-retention, incident-response, and privacy
   controls; and
5. documented which claims are independently verified, operator-attested, and
   outside the protocol.
