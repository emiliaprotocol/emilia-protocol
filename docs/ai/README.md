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

Do not edit generated outputs directly. Run:

```bash
npm run sync:llm-context
npm run check:llm-context
```

CI executes the check. A conformance, proof-statistics, security-case, or
external-evidence change therefore cannot land while the LLM surfaces still
describe the previous state.
