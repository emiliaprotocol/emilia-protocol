# Contributing to EMILIA Protocol

EMILIA is an open authority and evidence substrate for consequential machine
actions. This repository contains the protocol artifacts, reference verifiers,
conformance suites, Gate enforcement code, SDKs, integrations, formal models,
and the public web application.

## Before you change anything

Read these sources in order:

1. [`AGENTS.md`](AGENTS.md) for repository boundaries and evidence rules.
2. [`AI_CONTEXT.md`](AI_CONTEXT.md) and
   [`public/.well-known/emilia-context.json`](public/.well-known/emilia-context.json)
   for generated current context and source precedence.
3. The implementation and negative tests for the behavior you intend to
   change.

This is a public repository. Do not add private company strategy, fundraising,
buyer lists, outreach, competitive research, credentials, customer data, or
unpublished security material. The executable boundary check is:

```bash
npm run check:repository-boundary
```

## Useful contributions

- Clean-room or independently maintained implementations evaluated against the
  public conformance contract.
- Adversarial, reject, and cross-language vectors that strengthen a named
  protocol profile.
- Precise specification issues, especially where prose, verifiers, and vectors
  disagree.
- Executor-boundary integrations that demonstrate both admission and refusal,
  including replay and indeterminate-outcome handling where applicable.
- Reproducible examples that keep verification, matching, evidence
  satisfaction, authorization, provider entry, and observed effects distinct.

## Development environment

Use Node.js 24 for root development and tests; `.nvmrc` selects it because
Vitest 5 does not support Node 20. The package runtime compatibility boundary
remains Node.js 20.19 or later and is exercised separately in CI. Use the
committed npm lockfile rather than refreshing dependencies incidentally.

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
nvm use
npm ci
```

The repository contains both TypeScript and JavaScript. Some `.js` files are
generated standalone companions for TypeScript sources; do not edit a generated
companion when its source file or generator is authoritative. Follow the module
and build conventions of the package you are changing.

Most unit, verifier, and conformance tests are self-contained. Connected app,
database, deployment, and live-interoperability tests require the environment
documented beside that surface. Never substitute production credentials into a
local test fixture.

## Test the change

Run the narrowest relevant test first. Common forms are:

```bash
npm run test:run -- path/to/file.test.ts
node --test path/to/file.test.mjs
npm --prefix packages/gate test
```

Then run the applicable repository checks. The baseline for a code change is:

```bash
npm run lint
npm run typecheck
npm run test:run
node scripts/run-package-suites.mjs
npm run conformance
npm run build
```

Claim-bearing, protocol, evidence, or release changes also require the relevant
checks below:

```bash
npm run check:protocol
npm run conformance:manifest:check
npm run check:security-case -- --drift-report /tmp/security-case-drift.json
npm run check:proof-stats -- --drift-report /tmp/proof-stats-drift.json
npm run check:public-conformance-claims
npm run check:llm-context
npm run check:standalone-runtimes
npm run check:packed-package-exports
npm run check:release-chain
node scripts/check-language-governance.js
```

With `--drift-report`, the security case still executes every claim and
fails on any difference from the checked-in case outside its derived digests,
which it records instead; the proof-stats check still fails on everything it
verifies (a failing measured suite, the security case outside its derived
digests, formal and conformance evidence, every derived proof field) and only
records drift in the measured test counts. `main` refreshes both after merge; see
[Volatile evidence](#volatile-evidence). Without `--drift-report` both checks
compare byte for byte, as `main` and every release do.

Some governed checks need pinned external runtimes installed by CI, including
the formal-methods toolchain. The jobs in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) are authoritative for
the complete matrix; no single local command represents every CI lane.

A pull request that changes only prose under `docs/`, `standards/` or `papers/`
(or a root `*.md`), where no code run by a skipped job names the changed file,
takes the docs lane: every check that reads prose still runs, and the
security case, Gate product suite, SDK, wheel and package suites are skipped.
CI decides this with the classifier as it is on `main`, never the pull
request's copy; a pull request that touches `.github/` or `scripts/ci/` always
runs the full lane, and so does every pull request while `main`'s latest push
run has not passed the security case (including the window between a merge
that changed a pinned file and the refresh pull request that re-pins it).
`node scripts/ci/change-lane.mjs --event local --base origin/main` prints the
classifier's lane and reason before you push. Label a pull request
`evidence-autopilot` to have CI regenerate the derived evidence files
(formal traces, conformance manifest, security case, the derived proof fields
and the LLM context, keeping `main`'s test counts); once the
autopilot's GitHub App is provisioned it commits them back (Dependabot pull
requests get this automatically). The publisher checks only the bundle's shape
and transit integrity; the required checks on the new commit decide whether the
evidence is correct. See `.github/workflows/evidence-autopilot*.yml`.

### Volatile evidence

`lib/proof-stats.json` records the exact number of test cases and test files,
and the four LLM context artifacts (`AI_CONTEXT.md`, `public/llms.txt`,
`public/llms-full.txt`, `public/.well-known/emilia-context.json`) repeat those
counts. `security/security-case.json` records the SHA-256 of every file the
security case pins (about 264), the evidence bundle hash over them, the
release tarball hashes, and each claim's copy of those hashes. Both change on
almost every merge, so `main` owns them and pull requests do not carry them.
Everything else in these six files stays strict.

What this means for a pull request:

- Do not regenerate the security case for a change that only touches files
  it pins. The `security-case` job still executes every claim on the merge
  commit and fails on any difference from the checked-in case outside its
  derived digests (`evidence_bundle_sha256`, `evidence_file_count`,
  `evidence_files`, each release artifact's `sha256`, `file_count`, `version`
  and `filename`, and each claim's `release_artifact_hashes[].sha256`; the
  list is `SECURITY_CASE_DERIVED_FIELDS` in
  `scripts/ci/derived-evidence-drift.mjs`). On `pull_request` and
  `merge_group` runs it reports digest drift in its job summary and does not
  fail on it. `lib/proof-stats.json` and the LLM context take their copies of
  the digests from the checked-in case, so leaving the case as `main` has it
  leaves them current as well: such a pull request commits no derived
  evidence at all. Locally, `npm run check:security-case -- --drift-report
  /tmp/security-case-drift.json` gives the same verdict.
- A change to a claim in `security/claims.v1.json`, or to anything else the
  case restates (the execution record, the scenario counts, an artifact's
  kind or package), still needs the regenerated case. A pull request that
  changes `security/security-case.json` at all must make it exactly what the
  writer resolves for the merge commit; a hand-edited or outdated digest
  fails. If a rebase conflicts in the generated files and your change alters
  no claim, take `main`'s copies (`git checkout origin/main --
  security/security-case.json lib/proof-stats.json AI_CONTEXT.md
  public/llms.txt public/llms-full.txt public/.well-known/emilia-context.json`),
  re-run `npm run sync:llm-context` if your change alters one of its inputs,
  and commit.
- Do not update the test counts. On `pull_request` and `merge_group` runs,
  the `language-governance` job reports test-count drift in its job summary
  and does not fail on it.
- Deny by default: drift in anything else fails the job. That covers every
  other `lib/proof-stats.json` field (security case, formal evidence taxonomy,
  Tamarin, TLA+, Alloy, selected-scenario conformance, conformance vectors,
  external implementation, red-team catalog) and every LLM context file. If
  your change alters any of their inputs, commit it, then run:

  ```bash
  npm run sync:proof-stats -- --bootstrap-derived-evidence  # when a proof field drifted
  npm run sync:llm-context
  ```

  and commit the results. The first command re-executes and re-emits the
  security case and refreshes every derived proof field without running the
  suite; it keeps the base's test counts and their `generatedAt`. Labeling
  the pull request `evidence-autopilot` does the same in CI. A new or removed
  security claim is one such change, and `/proof` refuses to build without it.
- A pull request that changes `lib/proof-stats.json` must leave its test
  counts and `generatedAt` exactly as the base has them, or make the counts
  exactly what the suite measures for the merge commit (`npm run
  sync:proof-stats`), with a `generatedAt` no earlier than the base's and not
  in the future. Hand-edited public evidence does not merge.
- Still strict in your pull request: the formal traces, the conformance
  manifest, the clean-room pins, the standalone runtimes and everything in
  the security case except its derived digests. The LLM context tests and the
  public-claim audit read the generator's output for your sources, and pinned
  proof counts are derived from the sources.

After a merge, `.github/workflows/volatile-evidence-refresh.yml` regenerates the
six files on `main` with the official writers and opens (or supersedes) one
pull request, `chore(evidence): refresh volatile evidence`, committed by the
evidence autopilot App and set to auto-merge (provisioning:
[docs/operations/EVIDENCE-AUTOPILOT.md](docs/operations/EVIDENCE-AUTOPILOT.md)).
On that pull request a stale file fails CI, and so does any change to another
path. The writers are idempotent, so a run on a current `main` publishes
nothing. On `main` the security case is strict: a push run whose case has
stale digests fails its `security-case` job and does not attest the case until
the refresh pull request lands (the job's other checks still run, and the
conformance manifests are still attested). The push run and the refresh run fail once the
test counts have lagged for more than 24 hours; the refresh also runs every 12
hours, so on a quiet `main` that failure appears within about 36 hours of the
merge that staled them. Releases stay strict: npm package publication runs the
security case, proof-stats and LLM context checks without `--drift-report`, and
the protected consequence-control deployment runs the security case and
proof-stats checks the same way, so cut them from a `main` commit after the
refresh has landed.

## Contribution workflow

1. Fork the repository and branch from current `main`.
2. Keep the change focused and include regression coverage for behavior
   changes. Security fixes should prove the former bypass now refuses.
3. Run the narrow tests and applicable gates above.
4. Commit with a Developer Certificate of Origin sign-off:

   ```bash
   git commit -s
   ```

   CI checks that each pull-request commit contains a `Signed-off-by` line
   matching its commit-author metadata. The only exemptions rest on what
   GitHub itself reports, never on the author name or email written into the
   commit: commits GitHub verified as created by Dependabot, commits GitHub
   verified as created by the evidence autopilot App that change nothing but
   the regenerated derived-evidence files, and, in the merge queue, the merge
   commits GitHub creates (see
   [`.github/workflows/dco.yml`](.github/workflows/dco.yml)). Repository policy
   separately requires the accountable author and signer to be a natural person.
5. Open a pull request against `main`. Describe the trust boundary changed,
   the refusal or negative controls exercised, and the commands you ran.

The current [CODEOWNERS](.github/CODEOWNERS) file assigns review responsibility
to the maintainer. A green check is evidence about that check, not independent
review or deployment.

## Protocol and conformance changes

Follow [`GOVERNANCE.md`](GOVERNANCE.md):

1. Open an issue or pull request explaining the proposed semantic change.
2. Change normative text, reference verifiers, and conformance vectors
   together, or not at all.
3. Preserve released version semantics. A semantic change requires a new
   explicit protocol or profile version string.
4. Update the authoritative suite registry in `conformance/suites.mjs` and its
   versioned vectors when the conformance surface changes.
5. Regenerate governed manifests only through their source generators, then
   run their `check` commands and review the resulting diff.

The JavaScript, Python, and Go verifiers in this repository are same-team ports.
Agreement among them is cross-language consistency, not independent
implementation evidence. Internet-Drafts in `standards/` are individual
submissions unless the live IETF Datatracker states otherwise.

## Integration examples

Place a runnable example under the relevant `examples/<topic>/` directory and:

- include an SPDX Apache-2.0 header in new source files;
- exercise refusal as well as the happy path;
- bind the decision to the actual executor input, not caller-supplied labels;
- disclose shortcuts such as fixed clocks, ephemeral keys, or mocked providers;
- include a deterministic test and invocation instructions; and
- avoid calling an example conformant unless a registered suite establishes it.

## Repository map

| Path | Role |
| --- | --- |
| `packages/gate/` | Executor-boundary admission, one-time consumption, provider-entry, outcome, and reconciliation controls |
| `packages/verify/`, `packages/issue/`, `packages/require-receipt/` | Core public verification, issuance, and receipt-required libraries |
| `conformance/` and `caid/` | Registered suites, versioned vectors, runners, and exact-action mapping tests |
| `security/` and `formal/` | Governed executable claims, evidence bindings, and bounded formal models |
| `sdks/`, `integrations/`, `mcp-server/` | Language, framework, and tool-protocol integrations |
| `app/` and `apps/` | Reference web and service surfaces |
| `standards/` | Internet-Draft sources and posted historical revisions |
| `docs/` | Architecture, deployment boundaries, canonical language, and operator guidance |

## Language and generated context

Use [`docs/CANONICAL-LANGUAGE.md`](docs/CANONICAL-LANGUAGE.md) for public
terminology. Keep `VERIFIED`, `MATCH`, `SATISFIED`, `AUTHORIZED`, provider
entry, `EXECUTED`, and `INDETERMINATE` distinct.

Do not edit `AI_CONTEXT.md`, `public/llms.txt`, `public/llms-full.txt`, or
`public/.well-known/emilia-context.json` directly. Edit their declared source
(`docs/ai/context-source.v1.json`) or the underlying evidence, then run
`npm run sync:llm-context` and commit the four artifacts; CI fails a stale one
(see [Volatile evidence](#volatile-evidence)). To preview the rendering without
touching the checkout:

```bash
node scripts/generate-llm-context.mjs --write --out-dir /tmp/llm-context
```

## License and contact

Contributions are licensed under Apache-2.0. Questions and security reporting
paths are listed in [`SECURITY.md`](SECURITY.md); general implementation
questions may be opened as GitHub issues.
