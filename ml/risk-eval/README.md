# EP Risk-Classifier eval harness

Benchmarks any `classify(input)` against `cases.jsonl`. Design + the
advisory-not-enforcement rule: [`docs/ml/risk-classifier.md`](../../docs/ml/risk-classifier.md).

## Run

```bash
node ml/risk-eval/eval.mjs            # baseline: the REAL rule engine (lib/guard-policies.js)
node ml/risk-eval/eval.mjs tinker     # future self-hosted model (set EP_RISK_MODEL_URL)
```

## What it checks

- **Covered cases** — the deterministic engine must get these right. A covered
  case whose expected decision is a gate (`deny` / `allow_with_signoff`) that the
  classifier returns as `allow` is a **DANGEROUS MISS** → exit code 1. Run this
  as a regression gate on the rule engine (wire it into CI).
- **Perimeter cases** — fuzzy/novel actions the exact-match rules miss: a renamed
  money field (`payout_destination`), a novel destructive action
  (`delete_production_database`), injected intent in free-form reasoning. Reported
  as a coverage % — the scoreboard a fine-tuned model must beat. The rules are
  *expected* to miss these; that gap is the whole reason for the model.

## Add a case

Append one line to `cases.jsonl` (`input` is exactly the shape
`evaluateGuardPolicy` accepts):

```json
{"id":"...","tier":"covered|perimeter","input":{"actionType":"...","targetChangedFields":[],"riskFlags":[]},"expected":{"decision":"allow|allow_with_signoff|deny"},"note":"..."}
```

## Plug in the model

Add `classifiers/<name>.mjs` exporting `classify(input)`, then
`node ml/risk-eval/eval.mjs <name>`. Output is **advisory** — it may only *raise*
the tier the verified engine enforces.

> Importing the engine logs a one-time Node `MODULE_TYPELESS_PACKAGE_JSON`
> warning (repo is CommonJS, the engine is ESM). Harmless.
