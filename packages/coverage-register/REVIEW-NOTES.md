# Review notes for this branch

`feat/agent-authorization-coverage-register`

Sol, this is a new package plus one standards document. Nothing existing was
modified, so the blast radius is additive. Tests: **26/26 passing** via
`node --test packages/coverage-register/test.mjs`.

## What this is

A generator for dated, reproducible editions of a public register answering one
question per target: does a publicly declared agent action surface state a human
authorization precondition on the consequential capabilities it advertises?

It reuses the seven categories from `packages/scan/risk-packs.js` by import
rather than redefining them, so the register cannot drift from what the Gate
enforces. The rubric is split into a separate implementation-neutral document at
`standards/rubric/AGENT-AUTHORIZATION-COVERAGE-v1.md` specifically so that
someone can cite the vocabulary without citing us.

## Why the design is defensive in the places it is

**No target is ever contacted.** Only the public registry index is read.
Invoking a third party's declared money-movement tool to observe whether it
refuses is the fact pattern that got a competitor's logged-in surface enjoined
under the CFAA. `fetch-snapshot.mjs` is the only network code in the package and
its provenance block says so in writing.

**Every verdict is a claim about a document, never about a runtime.**
`assertVerdictIsDocumentClaim` throws on "vulnerable", "insecure", "does not
require" and similar, and requires the sentence to open with
`As published on <date>`. The point: a target whose runtime genuinely does
require approval, but whose declaration is silent, is still accurately described.
The sentence survives being wrong about their internals.

**Derivation never reads the clock.** `deriveVerdict` refuses an undated call and
`buildEdition` refuses a snapshot without `provenance.as_of`, so any edition
re-derives byte-identically from its snapshot. `--reproduce` proves it and I ran
it against live data.

## The thing I most want you to check

**Precision, and the review gate.** I hand-checked every finding against live
registry data twice.

First pass: 28 findings, roughly 55% precision. The false positives were bad in
an instructive way. `"no API keys"`, a *negation*, scored eight servers as
permission changes. `"Read-only access to production logs"` scored as a deploy
capability. A merchant directory scored as money movement. A screenplay tool's
file export scored as bulk data export.

After adding negation detection, read-only suppression, and mutation-shaped
keyword sets: 5 findings, roughly 80% precision. The survivor reads
`"debug deployment"` as a deploy capability, which it is not.

**Eighty percent is not good enough to attach a dated verdict to a named
company.** So `buildEdition` marks every finding `candidate` and stamps the
edition `DRAFT`; a human must promote each to `confirmed`. Nothing is publishable
on machine output. This mirrors the discipline already used for the six verified
Fire Drill reports, which cite a real handler by file and symbol.

If you think the gate is too strict, that is the argument to have. I would rather
ship a smaller reviewed edition than a larger one containing a verdict we have to
retract.

## Merging is not publishing

Merging this adds a generator, a rubric, and tests. It publishes nothing. There
is no route, no page, and no deployment in this branch, which is deliberate.

Publishing a dated verdict about a named third party is a decision for Iman, not
a side effect of a merge. If we do go there, three things need to exist first and
none is in this branch:

1. a confirmed (not candidate) edition,
2. the correction workflow actually staffed, since the policy promises public
   correction within 24 hours,
3. a decision on whether `registry-declaration` granularity is strong enough at
   all, or whether the target class should move up to the frameworks and gateways
   sitting in the action path.

## Live numbers, for context

200 registry rows, deduped to 109 targets, `as_of 2026-07-29`:

- 5 candidate findings, 0 confirmed, 0 publishable
- 104 no consequential action declared
- 0 declared an authorization precondition, and I verified this is not a detector
  bug: zero of the 200 raw rows contain any authorization phrase at all
- 107 distinct declarations across 109 targets

`snapshot-sample.json` and `edition-sample.json` are committed as fixtures so the
reproduce path is exercisable without network access. Drop them if you would
rather not carry sample data.

## Open questions for you

1. Is `standards/rubric/` the right home, or should the rubric live under
   `standards/staged/` until it has a draft number?
2. `records.delete` still matches bare `delete` and `destroy`, which I expect to
   be noisy on a full run. It produced zero findings in this sample so I left it
   alone rather than tuning blind. Worth a look on a full 43k pass.
3. Should `regulated.decision_override` stay exempt from read-only suppression?
   My reasoning: a determination can be rendered by a system that describes its
   data access as read-only. I am not certain.
