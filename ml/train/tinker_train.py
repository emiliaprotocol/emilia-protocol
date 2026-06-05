# SPDX-License-Identifier: Apache-2.0
"""SKELETON: LoRA fine-tune a small open model as EP's *advisory* risk classifier.

This is a template, not a runnable script. It needs Tinker access
(https://thinkingmachines.ai/tinker/) and a labeled dataset from
`ml/train/label.mjs` + human review. Adapt the calls to the *current* Tinker SDK
and the Tinker Cookbook — `forward_backward` / `sample` are Tinker's documented
primitives, but method names/signatures evolve, so treat the body as shape, not
gospel.

Pipeline:
    1. node ml/train/label.mjs traffic.jsonl > train.jsonl   # rule-oracle + human labels
    2. python ml/train/tinker_train.py                       # -> a LoRA adapter
    3. serve the adapter INSIDE the customer's VPC; point EP_RISK_MODEL_URL at it
    4. node ml/risk-eval/eval.mjs tinker                      # watch perimeter coverage climb

The model is ADVISORY. Its output may only RAISE the tier that
lib/guard-policies.js (deterministic, formally verified) then enforces — never
lower one, never decide alone. That boundary is what keeps EP's proofs valid.
"""

import json

LABELS = ("allow", "allow_with_signoff", "deny")

PROMPT = (
    "You are an action risk classifier sitting in front of a verified policy gate.\n"
    "Given an agent action, output exactly one tier: allow, allow_with_signoff, or deny.\n"
    "Escalate when uncertain — a needless signoff is cheap; a missed one is the whole risk.\n\n"
    "ACTION:\n{action}\n\nTIER:"
)


def load(path):
    """Keep only human-confirmed / rule-oracle rows (drop label == null)."""
    rows = []
    for line in open(path):
        ex = json.loads(line)
        if ex.get("label") in LABELS:
            rows.append({
                "prompt": PROMPT.format(action=json.dumps(ex["input"], sort_keys=True)),
                "completion": " " + ex["label"],
            })
    return rows


def train(examples):
    import tinker  # pip install tinker  (requires access)

    client = tinker.ServiceClient()  # auth via TINKER_API_KEY
    tr = client.create_lora_training_client(
        base_model="Qwen/Qwen3-4B",  # smallest model that clears the eval bar
        rank=16,
    )

    data = [tr.build_supervised_example(e["prompt"], e["completion"]) for e in examples]

    epochs, batch = 3, 16
    for epoch in range(epochs):
        for i in range(0, len(data), batch):
            tr.forward_backward(data[i:i + batch], loss="cross_entropy")  # accumulate grads
            tr.optim_step(lr=1e-4)                                        # apply
        # periodic smoke check on a known perimeter case
        probe = PROMPT.format(action='{"actionType":"delete_production_database"}')
        print(f"epoch {epoch}: {tr.sample(probe)!r}")

    tr.save_weights("ep-risk-lora")  # ship THIS adapter on-prem
    print("saved adapter: ep-risk-lora")


if __name__ == "__main__":
    rows = load("train.jsonl")
    print(f"training on {len(rows)} labeled examples")
    if not rows:
        raise SystemExit("No labeled rows. Run label.mjs on real traffic and human-review the flagged set first.")
    train(rows)
