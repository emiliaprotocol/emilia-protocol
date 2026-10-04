<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## 2.1.4 (2026-10-04)

- Publish the rebuilt bundle with fast-uri 3.1.8 port validation and IP-literal
  host checks, addressing GHSA-qw65-cvwx-89v3 and GHSA-58mr-gqgx-xq4g in the
  copy inlined by ajv. Dependency overrides alone do not update installed bundles.
- Rebuild with the current locked MCP SDK 1.30.1. Keep the package, runtime,
  and MCP Registry versions aligned.
- Retain the supported Verify 3.x dependency range. This release does not add
  AEC-08 evaluation or claim that every dependency advisory is exploitable
  through the MCP server's configured tools.

## 2.1.3 (2026-09-13)

- Correct the locked verifier integrity to the verified npm 3.21.0 release bytes.
- Keep package, runtime, and MCP Registry versions aligned. The unused 2.1.2 source tag remains unchanged.

## 2.1.2 (2026-08-30)

- Rebuild the MCP distribution against `@emilia-protocol/verify` 3.21.0 and
  keep the advertised implementation and Registry manifest versions aligned.
