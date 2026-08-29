# CCS v1.4 + AEB GitHub consequence profile

This independent composition fixture pins Correctover's public CCS v1.4.0
conformance bundle, verifies its public ALLOW receipt, and maps a compatible CCS
ALLOW to one executor-owned GitHub issue-update action and CAID.

The CCS receipt is evidence that a machine-policy decision allowed a tool call.
It is not execution authority. Provider entry additionally requires a current
AEB evaluation for the exact action and a separate EMILIA relying-party
authorization decision.

Run:

```sh
npm run conformance:composition:ccs-v14-aeb-github
```

For an independent handoff with no EMILIA package imports, copy these six
files into an otherwise empty directory:

- `run.standalone.mjs`
- `upstream-01-allow.receipt.json`
- `report.reference.json`
- `vectors.reference.json`
- `standalone.manifest.json`
- `THIRD_PARTY_NOTICES.txt`

Then run:

```sh
node run.standalone.mjs --check
```

The standalone runner requires only Node.js 20.19 or newer. It is generated
from the same tested runner and imports only Node built-ins. The manifest pins
the bundle, every bundled source input, all four support files, and the
generator version. The repository isolation test copies the handoff into a
fresh temporary directory with no `node_modules` or repository parent and runs
all eight cases there.

The bundle contains deterministic private signing keys used only to construct
test fixtures. They are public test material and MUST NOT be trusted or reused
outside this harness.

The eight deterministic cases demonstrate within this fixture that the valid
composition enters the counting provider once; receipt tampering, wrong
relying party, stale status,
action substitution, and absent EMILIA authority enter it zero times; and a
lost provider response returns `INDETERMINATE` and prevents blind re-entry.

`vectors.reference.json` is the proposed CCS examples fixture. It serializes
the pinned CCS receipt, exact GitHub action and CAID, relying party, and
provider. It does not by itself serialize or prove the full boundary: the
signed AEB evaluation, status observation, separate local-authority decision,
and provider-entry lifecycle are explicit inputs exercised by the standalone
runner and recorded in `report.reference.json`.

Limits: the checked-in upstream receipt uses Correctover's public deterministic
conformance key. The GitHub-shaped receipt is an EMILIA-authored compatible
fixture, not a Correctover certification. The provider is a test stub and does
not modify GitHub. The result is at-most-one provider entry, not exactly-once
physical execution; `INDETERMINATE` requires authenticated reconciliation.
