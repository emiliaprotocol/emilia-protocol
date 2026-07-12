<!-- SPDX-License-Identifier: Apache-2.0 -->
# Assurance-letter migration: legacy A/B/C values to Class S/H/V/Q

**Status: planned, not started. Blocked on the in-flight AEC hardening pass
landing on main (its conformance-manifest changes must merge before any vector
here is touched).**

On 2026-07-12 the assurance taxonomy of `draft-schrock-ep-assurance-classes`
was renamed from Class C/B/A/Q to **Class S < Class H < Class V < Class Q**, so
its identifiers stay disjoint from the key-custody Classes A/B/C of
receipts-06 Section 5.1 (which promises exactly that disjointness). The drafts,
`packages/verify/reliance-agreement.js`, and the docs are done. What remains is
the registry-side code and data, which still store the legacy assurance
letters `A`/`B`/`C` as wire values.

Two invariants govern every step:

1. **Key-custody Classes A/B/C are frozen.** `key_class`, `approver_key_class`,
   `keyClass` comparisons, and the `approver_credentials` data never change.
   Only ASSURANCE-sense letters migrate (stored `A` → `V`, `B` → `H`,
   `C` → `S`).
2. **Legacy letters stay accepted as deprecated aliases** while
   authority-registry enforcement is in shadow. Unknown labels keep failing
   closed. The alias window closes in a later, separate change.

One caution before starting: `lib/authority/resolver.js` binds
`assurance_class` into `authority_result_hash`, so migrating stored values
changes the authority-fact hashes of receipts minted afterward. Migrate while
enforcement is still shadow, never after.

## Step 1 — one shared normalizer, then the rank maps

Add `normalizeAssuranceClass()` (legacy alias map `{C:'S', B:'H', A:'V'}`,
unknown → null) in one place and import it everywhere below.

- `lib/guard-authority.js:13` — rank map `{C,B,A}` → `{S:1,H:2,V:3,Q:4}`;
  normalize both `have` and `required` before ranking.
- `lib/authority/resolver.js:74` — same rank map duplicated; same change.
- `lib/authority/store.js:32` — record-selection tiebreak; same change (live
  rows carry legacy letters until Step 5).

## Step 2 — the cross-taxonomy comparison sites

These compare an ASSURANCE letter on one side against the CUSTODY class on the
other; the same letter means two things. Introduce
`requiresDeviceVerifiedHuman(requiredAssurance)` (true for `V`, and for legacy
`A` via the alias) and leave every custody `keyClass !== 'A'` comparison
literal.

- `lib/guard-tier.js:43`
- `lib/govguard-gg1.js:71` (fixture at :164 flips to `V` in Step 4)
- `lib/guard-signoff.js:116` (the signoff LEVELS low/substantial/high in
  `lib/signoff/invariants.js` are a third, unrelated vocabulary — untouched)
- `app/api/v1/trust-receipts/[receiptId]/consume/route.js:201` (three checks)
- `app/api/v1/trust-receipts/route.js:273`
- `app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js:133`

## Step 3 — comments and prose

- `lib/guard-signoff-uv.js:6` header comment: `'V' (legacy 'A')` on the
  assurance side; custody `key_class: "A"` references unchanged.

## Step 4 — vectors, tests, examples (one commit, manifest regen after)

- `conformance/vectors/authority.v1.json` — entries `A`→`V`, `C`→`S`; ADD a
  legacy-alias acceptance case; keep `reject_unknown_assurance_label`
  rejecting `CLASS_A` as-is. Regenerate the conformance manifest in the same
  commit.
- `examples/authority/authority-closure-vector.mjs:37` — flip in lockstep with
  the vector; regenerate committed proof output.
- `tests/authority-registry.test.js`, `tests/guard-authority.test.js`,
  `tests/v1-api.test.js`, `tests/mutation-security-kernel.test.js:345` — flip
  letters, keep the unknown-label fail-closed rows, add alias regression tests
  in both directions.

## Step 5 — data migration

New Supabase migration translating `authorities.assurance_class` values
(`A`→`V`, `B`→`H`, `C`→`S`). Note the history: migration 102 introduced the
column with custody-flavored glosses, and migration 119's backfill copied
custody `key_class` verbatim into `assurance_class` — an identity mapping that
becomes wrong once the letters diverge. Any future backfill/repair must
translate custody→assurance (`key_class A` → assurance `V`, `B` → `H`,
`C` → `S`). The 119 file itself is history; the translation lives in the new
migration. Verify the live schema and live values before applying (repo
migrations are not reliably all applied in prod).

## Step 6 — public API surface

- `openapi.yaml:4561` — `required_assurance` enum `[A]` becomes transitional
  `[A, V]` with `A` documented as a deprecated alias of `V`; tighten to `[V]`
  when the alias window closes. Update the description to "device-verified
  human (Class V)".

## Out of scope, flagged so it is not mistaken for a rename target

- `lib/frontier/model-to-matter.js:51` ranks a `class_b` value that is outside
  the frozen receipt wire set (`software`/`class_a`/`quorum`). Reconcile
  separately: either register it as an official wire value in the assurance
  companion (it maps naturally to Class H) or drop it from the map.
