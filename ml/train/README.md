# EP Risk Classifier — training pipeline

Scaffolding for the **advisory** risk classifier in
[`docs/ml/risk-classifier.md`](../../docs/ml/risk-classifier.md). The model never
decides — it may only *raise* the tier the verified engine enforces.

> **Don't train yet.** A classifier trained on synthetic data won't generalize.
> Build the dataset from a real pilot's traffic. Until then, `label.mjs` (the
> weak-labeler) and the eval harness are the useful, runnable half.

## The pipeline

```
real agent traffic ──▶ label.mjs ──▶ train.jsonl ──▶ tinker_train.py ──▶ LoRA adapter
   (JSONL of actions)   weak-label    (+ human review)   (Tinker)          │
                                                                            ▼
                                                  serve in customer VPC (EP_RISK_MODEL_URL)
                                                                            │
                                                                            ▼
                                              node ml/risk-eval/eval.mjs tinker  (scoreboard)
```

### 1. `label.mjs` — bootstrap labels from the engine (runnable today)

```bash
node ml/train/label.mjs ml/train/sample-actions.jsonl > train.jsonl
```

For every action the rules already decide, `evaluateGuardPolicy` is ground truth
→ auto-labeled (`source: rule_oracle`). Actions the rules default-allow but that
look high-impact are flagged `label: null` (`source: human_review`) — that
flagged set is the **perimeter** a human labels and the model then learns. On the
sample corpus: 5 auto-labeled, 3 flagged for review.

### 2. `tinker_train.py` — LoRA SFT (template)

A skeleton for fine-tuning a small Qwen3/Llama-3 via Tinker. Needs Tinker access
and `train.jsonl`. Adapt the calls to the current Tinker SDK / Cookbook.

### 3. Serve + eval

Serve the adapter **inside the customer's network** (zero data egress — the whole
reason to use an open model), point `EP_RISK_MODEL_URL` at it, then:

```bash
node ml/risk-eval/eval.mjs tinker
```

Watch perimeter coverage climb from the baseline 0%. The covered-case regression
gate must stay green the whole time.
