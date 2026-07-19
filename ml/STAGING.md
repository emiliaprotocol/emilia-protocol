# STAGE — fine-tuned risk classifier (weights + training)

Status: **STAGED, unfired.** This branch merges the *shippable* half of the ML
risk layer: the deterministic advisory classifier
(`ml/risk-eval/classifiers/heuristic.mjs`) and the eval harness that gates it.
The *unfired* half — a fine-tuned model and its weights — is described here and
**not** built. It needs a GPU, real pilot data, and the lead's go.

## What is merged and real (this branch)

- `ml/risk-eval/classifiers/heuristic.mjs` — a deterministic feature/lexical/
  near-duplicate detector (no LLM, no network). Advisory, raise-only, falls back
  to `evaluateGuardPolicy` on uncertainty.
- `ml/risk-eval/classifiers/heuristic.selftest.mjs` — `node --test` suite
  proving the raise-only contract and each signal.

### Measured, on `ml/risk-eval/cases.jsonl` (14 cases), via `node ml/risk-eval/eval.mjs`

| classifier | covered (regression gate) | perimeter coverage | dangerous misses |
|-----------|---------------------------|--------------------|------------------|
| `rules` (baseline = the verified engine) | 8/10 exact | **0/4 (0%)** | 0 (PASS) |
| `heuristic` (this branch) | 8/10 exact | **4/4 (100%)** | 0 (PASS) |

The heuristic beats the rules baseline on perimeter coverage, 0% → 100%, with
**zero** new false escalations: the two covered "over-escalation (safe)" rows
are identical in both runs because they come from the engine's own critical
key-class floor, not the advisory layer (the layer only ever touches a bare
`allow`, and never lowers a gated decision). Precision on the escalations this
layer *adds* is 4/4 = 100% on this set.

Reproduce:

```bash
node ml/risk-eval/eval.mjs                 # rules baseline: perimeter 0%
node ml/risk-eval/eval.mjs heuristic       # this branch:   perimeter 100%
node --test ml/risk-eval/classifiers/heuristic.selftest.mjs
```

## What a fine-tuned model would add (the staged, unfired part)

The heuristic encodes high-signal tokens by hand. It is deliberately auditable
and will miss what it has no lexicon for: paraphrase and multilingual injection,
obfuscated/encoded intent, semantically-novel destructive actions that share no
token with the destructive-verb list, and long-context reasoning where risk is
implied rather than stated. A small fine-tuned classifier **generalizes** past
the lexicon — that is the entire reason to train one, and only once real pilot
traffic exists to train on (`docs/ml/risk-classifier.md` "Sequencing").

The model's contract is identical to the heuristic's and non-negotiable
(`docs/ml/risk-classifier.md`, "The one rule"): **advisory, raise-only.** It
emits `{ tier, injection_suspected }`; `evaluateGuardPolicy` still decides; a
human still signs off. The model never lowers a tier, never auto-allows, never
auto-denies. It plugs in exactly where `classifiers/tinker.mjs` already points
(`EP_RISK_MODEL_URL` → a self-hosted endpoint), so it is scored by this same
harness before it is trusted.

### Why self-hosted (Tinker → LoRA weights)

EP's buyers (banks, government, regulated) cannot send agent-action data to a
closed API. The plan: LoRA fine-tune an open model → ship the **weights** → the
classifier runs **inside the customer's VPC, zero data egress**.

### Training command (NOT run here — no GPU in this environment)

```bash
# Prereqs (unmet here): a CUDA GPU, a Tinker API key, and a labeled dataset
# ml/risk-eval/data/train.jsonl built from (a) the rule engine as the oracle for
# covered actions + (b) reviewed synthetic + real pilot perimeter labels
# (docs/ml/risk-classifier.md "Data strategy"). None of these exist in this
# environment, so nothing below was executed.

python ml/train/finetune_risk_lora.py \
  --base-model Qwen/Qwen3-0.6B \
  --train ml/risk-eval/data/train.jsonl \
  --eval  ml/risk-eval/cases.jsonl \
  --method lora --lora-rank 16 \
  --epochs 3 --lr 1e-4 \
  --out ml/weights/risk-lora/           # <-- the staged, unfired artifact

# Then serve inside the customer VPC and point the existing stub at it:
export EP_RISK_MODEL_URL=http://localhost:8000/classify
node ml/risk-eval/eval.mjs tinker        # must clear the eval bar the heuristic set
```

## The gate

Weights + training are **staged, not fired.** Firing requires, in order:
1. A GPU and a Tinker key (absent here).
2. Real pilot traffic to build `train.jsonl` — a synthetic-only model will not
   generalize (`docs/ml/risk-classifier.md` "Sequencing": launch → land a design
   partner → then train).
3. The lead's explicit go.

Until then the deterministic engine + the advisory heuristic in this branch are
the useful, shippable, verifiable layer. `classifiers/tinker.mjs` stays a stub
that throws until `EP_RISK_MODEL_URL` is set — no fabricated model, no silent
fallback to a fake verdict.
