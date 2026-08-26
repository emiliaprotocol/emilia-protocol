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
npm run check:proof-stats
npm run check:public-conformance-claims
npm run check:llm-context
npm run check:standalone-runtimes
npm run check:packed-package-exports
npm run check:release-chain
node scripts/check-language-governance.js
```

Some governed checks need pinned external runtimes installed by CI, including
the formal-methods toolchain. The jobs in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) are authoritative for
the complete matrix; no single local command represents every CI lane.

## Contribution workflow

1. Fork the repository and branch from current `main`.
2. Keep the change focused and include regression coverage for behavior
   changes. Security fixes should prove the former bypass now refuses.
3. Run the narrow tests and applicable gates above.
4. Commit with a Developer Certificate of Origin sign-off:

   ```bash
   git commit -s
   ```

   CI checks that each non-Dependabot pull-request commit contains a
   `Signed-off-by` line matching its commit-author metadata. Repository policy
   separately requires the accountable author and signer to be a natural person.
   An AI system cannot provide the DCO sign-off or be a co-author. AI-assisted work must follow
   [`docs/AI-ASSISTED-DEVELOPMENT.md`](docs/AI-ASSISTED-DEVELOPMENT.md).
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
or underlying evidence, then run:

```bash
npm run sync:llm-context
npm run check:llm-context
```

## License and contact

Contributions are licensed under Apache-2.0. Questions and security reporting
paths are listed in [`SECURITY.md`](SECURITY.md); general implementation
questions may be opened as GitHub issues.
