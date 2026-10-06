<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/require-receipt` are documented here.

## Unreleased

## 0.9.0 (2026-10-06)

### Breaking: current CAID selectors

- Action-risk-manifest `caid_field` selectors, approval-acquisition responses,
  receipt verification, and the edge handler now accept only the current
  `canactid:1:<action-type>:<suite>:<digest>` spelling. The scheme is
  provisionally registered by IANA; provisional registration is not IETF
  endorsement.
- The obsolete `caid:` spelling is refused instead of being silently accepted,
  translated, or rebound. Immutable historical signed evidence belongs behind
  Verify's explicitly selected CAID-04 legacy profile; this package's current
  enforcement path does not provide a dual-scheme compatibility mode.
- The generated zero-dependency drop-in carries the same current-only selector
  behavior.

## 0.8.2 (2026-10-04)

### Added

- `strictJsonGate(text, { refuseNoncharacters: true })` also refuses a
  string or member name that holds a Unicode noncharacter after unescaping,
  which I-JSON (RFC 7493) excludes. It is opt-in: without the option the
  gate behaves as before. The option is available through the package helper
  and generated drop-in; this release does not enable it for every JSON
  caller or change receipt and authorization semantics.

## 0.8.1 (2026-08-30)

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
