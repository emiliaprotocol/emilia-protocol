# EMILIA Protocol Style Guide

This file is the stable entry point used by language-governance checks. The
single source of truth for public terminology, claim boundaries, canonical
lines, and retired wording is
[`CANONICAL-LANGUAGE.md`](CANONICAL-LANGUAGE.md).

Do not maintain a second phrase list here. Before changing public copy:

1. Apply `CANONICAL-LANGUAGE.md` and keep `VERIFIED`, `MATCH`, `SATISFIED`,
   `AUTHORIZED`, provider entry, `EXECUTED`, and `INDETERMINATE` distinct.
2. Preserve the complete-mediation and relying-party-pinned trust boundaries.
3. Run `node scripts/check-language-governance.js`.
4. If generated LLM surfaces are affected, edit their declared source
   (`docs/ai/context-source.v1.json`); do not hand-edit generated context
   files. `main` regenerates them after merge; preview with
   `node scripts/generate-llm-context.mjs --write --out-dir /tmp/llm-context`.
