<!-- SPDX-License-Identifier: Apache-2.0 -->
# scripts/ts-loader

TypeScript migration support. Source files are being renamed `.js` -> `.ts`
while import specifiers keep the `.js` extension — the bundler/NodeNext
convention already used repo-wide (see `next.config.js`'s webpack
`resolve.extensionAlias` for the equivalent Next.js already relies on).
Webpack and vite both resolve that automatically. Plain `node` does not.

- `resolve-ts.mjs` + `register.mjs`: a Node module-customization hook
  (`node --import scripts/ts-loader/register.mjs <script>`) that resolves an
  otherwise-unresolvable `.js`/`.mjs` specifier to its `.ts`/`.tsx`/`.mts`
  sibling if one exists on disk.
- `resolve-source-path.mjs`: the same idea for scripts that read a source
  file by a literal `fs` path rather than importing it.

## Wiring this into CI: per-step `env:`, never `$GITHUB_ENV`, never workflow/job-level

**GitHub Actions refuses to let a workflow command set `NODE_OPTIONS` via
`$GITHUB_ENV`** ("Can't store NODE_OPTIONS output parameter using '$GITHUB_ENV'
command") — a deliberate security restriction, since an env var persisted that
way would apply to every later step in the job, including any Node-based
GitHub Action, and NODE_OPTIONS is exactly the kind of variable a compromised
action/dependency could abuse to hijack a later trusted action's execution.

**Workflow-level or job-level `env:` has the opposite problem**: it applies
from the very first step, including `actions/checkout` itself — which runs
*before* the repo (and this loader file) exists on disk, so every JS-based
action in the job crashes with `ERR_MODULE_NOT_FOUND` looking for a file that
hasn't been checked out yet. (Confirmed the hard way: this took down 30+
unrelated CI jobs in one push.)

The only mechanism GitHub Actions allows for this is a **step-scoped `env:`
key**, declared statically in the workflow YAML on the exact step that needs
it:

```yaml
- name: Some step that runs node against renamed lib/ files
  env:
    NODE_OPTIONS: "--import ${{ github.workspace }}/scripts/ts-loader/register.mjs"
  run: node some-script.mjs
```

This is authored, reviewable YAML (not a runtime command), so it isn't
subject to the `$GITHUB_ENV` restriction, and because it's scoped to one step
it never touches `actions/checkout`/`actions/setup-node`/etc. Use
`${{ github.workspace }}` (absolute), never a relative path — a relative
`--import` path resolves against the *spawning process's* cwd, which breaks
the moment a test spawns `node` with a different `cwd` (also confirmed the
hard way).

**Only add this to a step that actually needs it.** Test empirically
(`unset NODE_OPTIONS; run the exact command CI runs, including any
`working-directory:`) rather than assuming — a script that looks like it
touches `lib/` may not, and one with a `working-directory:` override resolves
relative specifiers differently than the same command run from repo root.
