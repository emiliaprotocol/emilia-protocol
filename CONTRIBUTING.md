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

The root package requires Node.js 20.19 or later; `.nvmrc` selects Node 20.
GitHub Actions also exercises supported surfaces on Node 24. Use the committed
npm lockfile rather than refreshing dependencies incidentally.

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
npm run check:security-case
npm run check:proof-stats -- --drift-report /tmp/proof-stats-drift.json
npm run check:public-conformance-claims
npm run check:llm-context -- --drift-report /tmp/llm-context-drift.json
npm run check:standalone-runtimes
npm run check:packed-package-exports
npm run check:release-chain
node scripts/check-language-governance.js
```

With `--drift-report`, the proof-stats and LLM context checks still fail on
everything they verify (a failing measured suite, the security case, formal
and conformance evidence, generator assertions) but only report whether the
checked-in volatile files match; see [Volatile evidence](#volatile-evidence).

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
run has not passed the security case.
`node scripts/ci/change-lane.mjs --event local --base origin/main` prints the
classifier's lane and reason before you push. Label a pull request
`evidence-autopilot` to have CI regenerate the strict derived evidence files
(formal traces, conformance manifest, security case); once the
autopilot's GitHub App is provisioned it commits them back (Dependabot pull
requests get this automatically). The publisher checks only the bundle's shape
and transit integrity; the required checks on the new commit decide whether the
evidence is correct. See `.github/workflows/evidence-autopilot*.yml`.

### Volatile evidence

Five derived files change on almost every merge, so `main` owns them and pull
requests do not carry them:

- `lib/proof-stats.json` (exact test counts and derived proof fields)
- `AI_CONTEXT.md`, `public/llms.txt`, `public/llms-full.txt` and
  `public/.well-known/emilia-context.json` (rendered from it and other evidence)

What this means for a pull request:

- Do not regenerate or commit these files. On `pull_request` and `merge_group`
  runs, the `language-governance` job reports their drift in its job summary
  and does not fail on it. If a pull request does change one of them, that
  file must be exactly what the writers produce for the merge commit, or the
  job fails: hand-edited public evidence does not merge. The LLM context tests and the public-claim audit read
  the generator's output for your sources, and pinned proof counts are derived
  from the sources, so they do not depend on these files being current.
- The strict derived evidence is unchanged: `security/security-case.json`, the
  formal traces, the conformance manifest, the clean-room pins and the
  standalone runtimes must still be current in your pull request.
- One exception: a pull request that adds or removes a security claim must
  refresh `lib/proof-stats.json`, because `/proof` refuses to build when the
  file's claim taxonomy misses a claim. Commit your change, run
  `npm run sync:proof-stats` (it re-emits the security case and measures the
  suite) and commit the result; it must match the merge commit exactly, so
  regenerate it again if `main` moves.

After a merge, `.github/workflows/volatile-evidence-refresh.yml` regenerates the
five files on `main` with the official writers and opens (or supersedes) one
pull request, `chore(evidence): refresh volatile evidence`, committed by the
evidence autopilot App and set to auto-merge. On that pull request a stale file
fails CI. On `main`, the push run and the daily refresh run fail once the files
have been stale for more than 24 hours, one scheduled refresh cycle. Releases
stay strict (npm package publication checks all five files, the protected
consequence-control deployment checks `lib/proof-stats.json`), so cut them from
a `main` commit after the refresh has landed.

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
(`docs/ai/context-source.v1.json`) or the underlying evidence; `main`
regenerates the artifacts after merge (see [Volatile evidence](#volatile-evidence)).
To preview the rendering without touching the checkout:

```bash
node scripts/generate-llm-context.mjs --write --out-dir /tmp/llm-context
```

## License and contact

Contributions are licensed under Apache-2.0. Questions and security reporting
paths are listed in [`SECURITY.md`](SECURITY.md); general implementation
questions may be opened as GitHub issues.
