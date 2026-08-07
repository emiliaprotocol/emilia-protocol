<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1

`EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1` lets a relying party state which
Gate-recorded outcomes it requires from one signed
`EP-BOUNDED-EXECUTION-PROGRAM-v1`. A verifier combines the signed profile with
a signed `EP-BOUNDED-EXECUTION-REPORT-v1` and produces one deterministic
verdict:

- `RECORDED_PROCESS_ACCEPTED`
- `RECORDED_PROCESS_NOT_ACCEPTED`
- `INDETERMINATE`

This closes a deliberately separate question from admission. The bounded
execution program defines what may execute. The acceptance profile defines
which recorded terminal outcomes a relying party requires before it accepts
the recorded process result.

## Signed profile

The relying party signs a closed profile that binds:

- profile and relying-party identifiers;
- the exact bounded program ID, version, and digest;
- a validity interval;
- accepted program statuses;
- maximum unresolved and still-reserved occurrence counts; and
- required nodes, each with a minimum terminal-occurrence count, accepted
  recorded outcomes, and an explicit rule for additional terminal outcomes.

The profile signer MUST be the relying party. Verification uses an
out-of-band trusted key pin and caller-pinned profile, relying-party, program,
version, digest, and verification time. Presented key material never selects
its own trust context.

## Evaluation

Evaluation first verifies both signed objects and their caller-owned contexts.
It then requires exact agreement on relying party and program identity.

An unresolved post-entry occurrence or still-reserved occurrence above the
profile's threshold produces `INDETERMINATE`. It is not converted into failure
or success. A fully determinate report produces
`RECORDED_PROCESS_NOT_ACCEPTED` when the program status is disallowed, a
required node or count is missing, or a disallowed terminal outcome exists.
Only a determinate report satisfying every requirement produces
`RECORDED_PROCESS_ACCEPTED`.

Additional accepted outcomes do not hide a disallowed outcome unless the
profile explicitly permits additional terminal outcomes for that node.

## Portable evidence pack

`EP-BOUNDED-EXECUTION-EVIDENCE-PACK-v1` carries the signed acceptance profile,
the signed bounded execution report, the deterministic evaluation, the claim
boundary, and a canonical package digest. Verification rechecks both
signatures, every out-of-band binding, the package digest, and the evaluation.
The pack remains valid when its verdict is not accepted or is indeterminate;
failure and uncertainty are evidence, not malformed artifacts.

## Claim boundary

The profile expresses one relying party's acceptance of Gate-recorded program
outcomes only. The profile, report, evaluation, and evidence pack do not prove:

- legal or regulatory compliance;
- external effect truth or event chronology;
- that the bounded program is safe, lawful, correct, or complete;
- complete mediation of every mutation path; or
- the absence of actions performed outside Gate.

The implementation therefore exposes no `compliant` boolean. A party claiming
legal compliance must supply the applicable rule, interpretation, scope, and
independent evidence outside this artifact.

## Experimental reference vectors

`conformance/vectors/bounded-execution-acceptance.v1.json` contains one
deterministic known-answer profile, signed report, evaluation, evidence pack,
canonical bytes, and hostile mutations. Regenerate or check it with:

```bash
node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-acceptance.mjs
node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-acceptance.mjs --check
```

These are same-team experimental reference vectors. They are not independent
or cross-language conformance, interoperability, standardization, or
certification evidence.
