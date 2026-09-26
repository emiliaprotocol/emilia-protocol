# LLM context system

EMILIA's LLM-facing documentation is generated from one stable doctrine file
plus current machine-readable evidence. This avoids a second set of hand-edited
claims drifting away from the repository.

## Editable source

- `docs/ai/context-source.v1.json` contains low-volatility definitions,
  boundaries, source-precedence rules, standards links, and code entry points.
- Current counts and evidence status come from `lib/proof-stats.json`,
  `conformance/conformance-manifest.json`, `security/security-case.json`, and
  `conformance/external/rust-cleanroom-jdieselny.v1.json`.

## Generated outputs

- `AI_CONTEXT.md` - the read-first repository context.
- `public/llms.txt` - the concise website discovery index.
- `public/llms-full.txt` - the full website context.
- `public/.well-known/emilia-context.json` - machine-readable facts, evidence
  pointers, assumptions, and freshness metadata.

Do not edit generated outputs directly. Edit their declared source or the
underlying evidence, then run:

```bash
npm run sync:llm-context
npm run check:llm-context
```

CI runs the check strictly on every pull request, merge group and push: the
outputs are rendered only from checked-in inputs, so a conformance, security
case, standards or context-source change cannot land while the LLM surfaces
still describe the previous state. The one figure that may lag is the
automated test count, which the surfaces take from `lib/proof-stats.json`:
`main` refreshes those counts after merge
(`.github/workflows/volatile-evidence-refresh.yml` runs `npm run
sync:proof-stats` and `npm run sync:llm-context` and opens an auto-merging
refresh pull request), so they may lag the source revision by one refresh
cycle. The surfaces label that value as the test-count snapshot, and npm
package publication checks all of it strictly. See
`CONTRIBUTING.md#volatile-evidence`.

Preview a rendering without touching the checkout:

```bash
node scripts/generate-llm-context.mjs --write --out-dir /tmp/llm-context
```
