<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/require-receipt` are documented here.

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
