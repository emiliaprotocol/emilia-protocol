# @emilia-protocol/coverage-register

Builds dated, reproducible editions of the **Agent Authorization Coverage**
register: for every publicly declared agent action surface, does its own
published declaration state a human authorization precondition on the
consequential capabilities it advertises?

The rubric is a separate, implementation-neutral document:
[`standards/rubric/AGENT-AUTHORIZATION-COVERAGE-v1.md`](../../standards/rubric/AGENT-AUTHORIZATION-COVERAGE-v1.md).
It is meant to be citable without citing this package.

## Run it

```bash
node fetch-snapshot.mjs --out snapshot.json --limit 200 --as-of 2026-07-29
node build-edition.mjs --snapshot snapshot.json --out edition.json
node build-edition.mjs --snapshot snapshot.json --reproduce edition.json
node --test test.mjs
```

`fetch-snapshot.mjs` is the only file that touches the network, and it touches
one host: the public MCP registry index. **No target server is contacted,
probed, or invoked.** Everything else is offline and deterministic.

## The four hard rules, enforced in code

**1. No probing.** Verdicts come from what a target published about itself.
Calling a third party's advertised money-movement tool to see whether it refuses
is a CFAA fact pattern, not a research method.

**2. Verdicts are document claims.** `assertVerdictIsDocumentClaim` rejects any
sentence containing "vulnerable", "insecure", "does not require", and similar,
and requires the opening `As published on <date>`. A sentence that would only be
true given an assumption about someone's runtime cannot ship.

**3. Undated is refused.** `deriveVerdict` throws without an explicit
`YYYY-MM-DD`, and `buildEdition` throws without `provenance.as_of`. The clock is
never read during derivation, so an edition re-derives identically years later.

**4. Nothing publishes on machine output.** Findings start as `candidate`. A
human promotes them to `confirmed` by reading the declaration. Any edition with
an unreviewed candidate is stamped `DRAFT`.

```js
buildEdition(snapshot, { review: { 'vendor/server': 'confirmed' } });
```

## Precision, measured not assumed

Hand-checked against the first live 200-row sample:

| Stage | Findings | Precision |
| --- | --- | --- |
| First pass | 28 | ~55% |
| After negation + read-only + mutation-shaped keywords | 5 | ~80% |

Real false positives that drove each fix, all from live data:

- `"no API keys"` scored as a permission change, across eight servers sharing one
  vendor's boilerplate. Fixed by `NEGATION_PREFIXES`.
- `"Read-only access to production logs"` scored as a deploy capability. Fixed by
  `READ_ONLY_MARKERS` plus removing bare `production` as a keyword.
- A merchant *directory* scored as money movement, and an API-test tool scored on
  naming Stripe as a profile. Fixed by requiring capability phrasings.
- A screenplay tool's file export scored as bulk data export. Fixed by requiring
  bulk/data qualifiers.

The one surviving error reads `"debug deployment"` as a deploy capability. This
is why rule 4 exists.

## Anti-inflation

One vendor republishing identical boilerplate across many entries would inflate
every count. `boilerplateDigest` hashes the prose without the target name, so
twins collapse; each edition reports `distinct_declarations` beside `total`, and
`findings_distinct_declarations` beside the finding count.

## Files

| File | Role |
| --- | --- |
| `rubric.mjs` | Categories derived from `packages/scan/risk-packs.js`, verdict vocabulary, negation and read-only markers |
| `verdict.mjs` | One declaration to one verdict, plus the wording guard |
| `edition.mjs` | Deterministic edition assembly, review gate, reproduce |
| `fetch-snapshot.mjs` | The only network code |
| `build-edition.mjs` | CLI to build or reproduce |
| `test.mjs` | 26 tests |

Categories are never redefined here. They are imported from the shipped
enforcement manifest so the register cannot drift from what the Gate enforces.
