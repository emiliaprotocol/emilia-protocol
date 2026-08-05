# Focused ePrint candidate

This directory contains a new, focused preprint candidate. It preserves the earlier broad manuscript under `papers/preprint/` and does not claim that the broad manuscript was submitted in this form.

The paper centers one result: an action-bound signature can provide portable offline evidence, while one-time admission requires a shared atomic consumption domain or equivalent coordination.

Status: not submitted.

## Build

From the repository root:

```sh
tectonic -X compile papers/eprint-action-bound-authorization/main.tex
```

The output is `papers/eprint-action-bound-authorization/main.pdf`.

`SUBMISSION.md` contains the proposed title, category, keywords, abstract, and editor-facing scope check.

## Verify the models

See `RESULTS.md` for the pinned container digest, model hashes, exact commands, and expected positive and negative results.
