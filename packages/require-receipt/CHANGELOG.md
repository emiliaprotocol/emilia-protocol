<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/require-receipt` are documented here.

## Unreleased

### Security

- `validateActionRiskManifest` now requires a non-empty
  `execution_binding.required_fields` on every entry with
  `receipt_required: true`, the same author-time floor already applied to
  `assurance_class`. Without it the enforcement point binds a receipt to the
  action TYPE alone (an empty field list makes execution binding a no-op), so a
  claim signed for one payload authorizes any other under the same type.
  Compatibility note: an existing guarded manifest that declares no
  `execution_binding` is now invalid and must name the material fields the
  executor observes from its system of record.

## 0.8.1 (2026-08-30)

### Security

- Refuse contradictory selector identities instead of falling through to a
  legacy first-match classification.
- Bind executor-observed action material to the actual invocation arguments so
  an approved observation cannot authorize a different execution.
- Preserve detached argument custody across callbacks and fail closed on
  selector or action-binding ambiguity.

## 0.8.0 (2026-08-05)

### Security

- Add one shared executor-action binder over the complete canonical tool input,
  with receipt transport fields excluded and optional occurrence identity.
- Reject accessors, executable or non-JSON structures, malformed action names,
  and ambiguous occurrence identifiers before deriving authority.

## 0.7.2 (2026-08-01)

### Packaging

- Make a clean package build regenerate the drop-in runtime after `dist/` is
  removed, and remove the redundant tracked `dist/README.md`, so the
  reproducibility oracle no longer depends on stale build assets.

## 0.7.1 (2026-08-01)

### Security

- Apply one strict JSON domain to receipt, approval-action, and JWS
  canonicalization. Cycles, sparse arrays, accessors, symbol members, non-plain
  objects, malformed UTF-16, unsafe numbers, and values outside JSON fail
  closed before hashing or verification.
- Inspect approval fields through data-property descriptors so getters cannot
  change signed action meaning during verification.
- Normalize receipt identifiers before consumption and refuse whitespace-only
  identifiers rather than admitting ambiguous store keys.

### Packaging

- Rebuild the drop-in Gate and declarations from the hardened TypeScript
  sources.
