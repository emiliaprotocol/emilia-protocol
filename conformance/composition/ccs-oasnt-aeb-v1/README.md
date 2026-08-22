<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS + OASNT to AEB composition v1

This kit proves one bounded two-leg composition:

- the pinned CCS PyPI HMAC result is verified as `machine-policy-decision`;
- the published OASNT-02 token is verified as `human-authorization`;
- each adapter independently maps its native artifact to the same exact
  `payment.transfer.1` action, CAID, and action digest;
- AEB keeps both roles separate, requires both, signs the evaluation, reserves
  both native replay identities before provider entry, preserves an
  `INDETERMINATE` outcome, and refuses a second admission; and
- action substitution fails at both the native and AEB composition layers.

Run the reference implementation:

```bash
npm run conformance:composition:ccs-oasnt
```

Emit a report with runner-supplied metadata:

```bash
node conformance/composition/ccs-oasnt-aeb-v1/run.mjs \
  --emit \
  --output /tmp/ccs-oasnt-aeb-report.json \
  --runner-name "Your name" \
  --runner-affiliation "Your project" \
  --runner-revision "your-source-revision" \
  --executed-at "2026-08-11T20:00:00Z"
```

The report includes a sentence designed for an Internet-Draft Implementation
Status section. It says exactly what ran and states that executing EMILIA's
runner is a reproduction, not an independent implementation.

An external runner may sign the exact canonical report by adding:

```bash
  --signing-key /path/to/ed25519-private-key.pem \
  --key-id "runner:your-key-id"
```

The private key is read locally and is never copied into the repository.

## Scope limits

The CCS checks cover the distribution labeled `ccs-verifier==1.1.0`, whose
installed runtime identifies as `0.4.1`. They do not claim conformance to later
CCS draft text. The OASNT checks use the published `-02` compact-token vector
and pin the archived `draft-thallapelly-oasnt-02.txt` bytes as
`sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603`.
The token's request fingerprint remains signed, but this profile deliberately
joins only the exact native action. A passing report is not independent
implementation evidence, deployment evidence, certification, IETF adoption,
or endorsement.
