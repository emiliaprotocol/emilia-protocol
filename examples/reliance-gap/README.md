<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reliance gap report: specialty prior auth, five relying parties

Same transaction, five parties, five pinned profiles, one portable evidence
packet. This example runs the acceptance preflight
(`packages/verify/reliance-gap.js`) over a fully synthetic specialty
prior-authorization action packet and shows how the SAME evidence produces a
different closed verdict under each relying party's own pinned
EP-RELIANCE-PROFILE-v1.

Everything here is synthetic and de-identified: fake identifiers, digests of
synthetic strings, no PHI shapes. The packet rides beside a (synthetic) NCPDP
transaction by digest; it never carries transaction contents.

## The packet

`specialty-pa-packet.json` contains:

- `action` - the prior-auth approval, bound to the NCPDP transaction digest
  and the payer benefit policy hash;
- `evidence` - a valid authorization receipt (Class-B intake software plus a
  Class-A device-bound payer reviewer, checkpointed in a transparency log), a
  signed EP-AUTHORITY-PROOF-v1 for the reviewer, a revocation freshness
  attestation checked 30 minutes before evaluation, an unconsumed consumption
  state, and one deliberately foreign artifact (`x-demo-fax-confirmation`)
  that no verifier registers - the report records it as unverifiable presence
  and never counts it as evidence;
- `context` - the pinned approver keys, log key, and WebAuthn RP ID the
  relying party verifies against;
- `evaluated_at` - the evaluation instant (`2026-07-08T15:00:00Z`). The tool
  never reads the wall clock.

## The five profiles

Each profile in `profiles/` pins genuinely different requirements:

| profile | assurance floor | authority | revocation bound | other pins |
| --- | --- | --- | --- | --- |
| `pharmacy.json` | `class_a` | required | 3600 s | benefit policy, consumption |
| `payer-pbm.json` | `signed` | required | 86400 s | benefit policy |
| `prescriber-ehr.json` | `quorum` | not required | - | none |
| `medicaid-auditor.json` | `class_a` | required | 900 s | benefit policy, consumption |
| `hub-vendor.json` | `signed` | not required | - | its OWN contracted policy hash |

## Single-profile run

```bash
node packages/verify/cli.js reliance-gap \
  examples/reliance-gap/specialty-pa-packet.json \
  --profile examples/reliance-gap/profiles/pharmacy.json
```

Expected: `kernel_verdict: "rely"`, exit code 0. The report still lists one
gap (`verifiable_evidence_only:x-demo-fax-confirmation`) because the foreign
artifact is present but unverifiable; it does not affect the verdict.

## Five-profile run

```bash
node packages/verify/cli.js reliance-gap \
  examples/reliance-gap/specialty-pa-packet.json \
  --profiles examples/reliance-gap/profiles
```

Expected verdicts (exit code 2, because not every party can rely):

| profile | verdict | why |
| --- | --- | --- |
| `pharmacy.json` | `rely` | every pinned leg composes within its bounds |
| `payer-pbm.json` | `rely` | signed floor plus authority and a day-old freshness bound |
| `prescriber-ehr.json` | `do_not_rely_quorum_unsatisfied` | demands a two-person quorum; the packet has none |
| `medicaid-auditor.json` | `do_not_rely_stale_revocation` | the eligibility check is 30 minutes old, its bound is 15 |
| `hub-vendor.json` | `do_not_rely_policy_mismatch` | the action cites the payer benefit policy, not the hub's contracted policy |

Add `--out report.json` to write the JSON report to a file (the human summary
then prints to stdout), or `--now <rfc3339>` to override the packet's
`evaluated_at`. Exit codes: 0 = rely (all rely in `--profiles` mode),
2 = any `do_not_rely_*`, 1 = operational error.

## Regenerating the fixtures

```bash
node examples/reliance-gap/generate-fixtures.mjs
```

The log and registry keys derive from fixed seeds so the profiles are stable;
the Class-A reviewer key is generated fresh and carried in the packet's
`context`, so the packet stays self-consistent after regeneration.
