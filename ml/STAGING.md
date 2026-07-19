# STAGE — advisory risk classifier

Status: **deterministic layer gateable; remote/training boundary closed; no
model or weights built.**

The useful ML-adjacent layer is runnable without a network:

- `ml/risk-eval/classifiers/heuristic.mjs` is deterministic, advisory, and
  raise-only.
- `ml/risk-eval/eval.mjs` supports an explicit perimeter coverage threshold.
- `ml/risk-eval/classifiers/tinker.mjs` wraps a future self-hosted endpoint with
  a deterministic decision floor, timeout, strict output validation, and
  fail-closed human signoff.
- `ml/train/label.mjs` creates weak labels while holding suspicious allows for
  human review.
- `ml/train/prepare.py` validates reviewed JSONL and emits provider-neutral SFT
  data plus an optional digest manifest.

There is no training SDK integration, model download, external call, adapter,
or weights artifact in this stage.

## Reproducible gate

```bash
npm run ml:gate
```

That command runs:

```bash
node --test \
  ml/risk-eval/classifiers/heuristic.selftest.mjs \
  ml/risk-eval/classifiers/tinker.selftest.mjs
python3 ml/train/prepare.selftest.py
node ml/risk-eval/eval.mjs heuristic --min-perimeter=100
```

Current result on `ml/risk-eval/cases.jsonl`:

| classifier | covered exact | perimeter | dangerous misses |
|---|---:|---:|---:|
| `rules` baseline | 8/10 | 0/4 (0%) | 0 |
| `heuristic` gate | 8/10 | 4/4 (100%) | 0 |

The two safe covered-case over-escalations are from the engine’s existing
critical key-class floor and occur in the rules baseline as well; the heuristic
does not introduce them.

The self-test gate covers 20 Node tests and 5 Python tests, including:

- deterministic deny/signoff floors against a remote `allow`;
- malformed JSON/schema/tier;
- timeout, HTTP error, and network error;
- adversarial `injection_suspected`;
- advisory handling of a remote `deny`;
- pending review, malformed labels, and conflicting training examples.

## Local data-preparation path

```bash
node ml/train/label.mjs ml/train/sample-actions.jsonl \
  > /tmp/ep-risk-labeled.jsonl

python3 ml/train/prepare.py \
  --train /tmp/ep-risk-labeled.jsonl
```

This demonstration yields five prepared examples and three rows held for human
review. Nothing is trained. For real pilot data, reviewers must fill every
`label: null` row and confirm `injection_suspected`, then run:

```bash
python3 ml/train/prepare.py \
  --train /path/to/reviewed-risk-labels.jsonl \
  --require-no-pending \
  --out /path/to/ep-risk-sft.jsonl \
  --manifest /path/to/ep-risk-sft.manifest.json
```

The manifest deliberately records `training_backend: null` and `weights: null`.
This is an honest handoff contract, not a claim that training occurred.

## Future firing conditions

Fitting a model remains blocked until all of these are real:

1. representative, consented pilot traffic and completed human review;
2. a selected local training backend with pinned dependencies;
3. documented base-model license, hardware, privacy, and deployment contracts;
4. generated weights served inside the customer boundary;
5. shadow-mode evidence and a passing remote eval at the required threshold;
6. explicit approval to move from shadow mode to escalate-only use.

The served endpoint contract and failure semantics are documented in
[`ml/risk-eval/README.md`](risk-eval/README.md). The data contract is documented
in [`ml/train/README.md`](train/README.md).
