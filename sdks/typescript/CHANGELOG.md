<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## 0.11.1 (2026-10-04)

- Remove trailing base URL slashes in linear time. Long interior slash runs
  no longer trigger regex backtracking, while interior paths and request URLs
  retain their existing meaning.
- Keep the emitted SDK version aligned with the package version. API route,
  receipt, and authorization contracts are unchanged.

## 0.11.0 (2026-08-30)

- Rebaseline supported client methods on current API route, verb, and request
  contracts and add a machine-checked SDK route inventory.
- Publish exact-action observation and execution-state types together with the
  v1 receipt, signoff, consume-once, execution-attestation, and evidence flow.
