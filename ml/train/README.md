# EP Risk Classifier — data preparation

This directory contains the runnable, local part of the advisory classifier’s
future training path. It validates labels and emits provider-neutral
supervised-fine-tuning (SFT) JSONL. It does **not** train, download a model, call
a service, or create weights.

The model remains advisory: its output can raise a deterministic `allow` to
human signoff, but it cannot lower the result from `evaluateGuardPolicy` and
cannot deny by itself.

## Runnable pipeline

```text
real action JSONL
  -> label.mjs (rule-oracle tier + deterministic injection weak label)
  -> human review of every label=null row
  -> prepare.py (schema validation, deduplication, SFT export + digest)
  -> a future, separately pinned local training backend
```

Create weak labels from the included demonstration actions:

```bash
node ml/train/label.mjs ml/train/sample-actions.jsonl > /tmp/ep-risk-labeled.jsonl
```

Validate them without writing any artifact:

```bash
python3 ml/train/prepare.py --train /tmp/ep-risk-labeled.jsonl
```

The sample produces five complete rows and three `label: null` rows held for
human review. `prepare.py` omits pending rows from SFT output and reports them;
it never guesses their tier.

After a reviewer has completed every pending row, enforce training readiness and
emit SFT JSONL plus a digest-bearing manifest:

```bash
python3 ml/train/prepare.py \
  --train /path/to/reviewed-risk-labels.jsonl \
  --require-no-pending \
  --out /path/to/ep-risk-sft.jsonl \
  --manifest /path/to/ep-risk-sft.manifest.json
```

## Input contract

Each labeler/reviewer row is one JSON object:

```json
{
  "input": {
    "actionType": "vendor_bank_account_change",
    "targetChangedFields": ["bank_account"],
    "riskFlags": []
  },
  "label": "allow_with_signoff",
  "injection_suspected": false,
  "source": "rule_oracle"
}
```

- `label` is `allow`, `allow_with_signoff`, `deny`, or `null`.
- `null` is permitted only with `source: "human_review"` and is never exported.
- `injection_suspected` must be boolean. `label.mjs` supplies an explicit weak
  label and records its provenance in `injection_source`; a human reviewer owns
  the final value for reviewed rows.
- Duplicate actions with conflicting labels are rejected.
- `--require-no-pending` makes any unfinished human review a hard failure.

## Output and backend contract

The SFT output uses a `messages` array with:

1. a system instruction defining the advisory/raise-only boundary;
2. the canonical action JSON as the user message; and
3. an assistant JSON object containing exactly `tier` and
   `injection_suspected`.

No training SDK is claimed or vendored here. Before fitting a model, a separate
change must choose a local backend, pin its package versions, document the base
model license and hardware requirements, consume `ep-risk-sft-v1`, and prove its
served output through `npm run ml:gate` plus the remote-adapter self-tests. That
is intentionally future work; there is no fabricated adapter or weights path in
this repository.

## Tests

```bash
python3 ml/train/prepare.selftest.py
npm run ml:gate
```
