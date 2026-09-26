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

Do not edit generated outputs directly. They are volatile evidence that `main`
regenerates after merge with the official writer
(`.github/workflows/volatile-evidence-refresh.yml` runs
`npm run sync:llm-context` and opens an auto-merging refresh pull request).
Preview a rendering without touching the checkout:

```bash
node scripts/generate-llm-context.mjs --write --out-dir /tmp/llm-context
```

CI runs `npm run check:llm-context` on every pull request and merge group, but
there it only reports drift; every input assertion still fails the run, and the
LLM context tests assert on a fresh rendering. On `main`, CI fails once the
surfaces have described a previous state for more than 24 hours (one scheduled
refresh cycle), and npm package publication checks them strictly. See
`CONTRIBUTING.md#volatile-evidence`.
