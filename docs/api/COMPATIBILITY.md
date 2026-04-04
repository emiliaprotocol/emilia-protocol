# API Stability and Compatibility Policy

This document defines what guarantees EMILIA Protocol makes about API stability, breaking-change policy, and support lifecycle for each component.

---

## Version Scheme

EMILIA Protocol uses **Semantic Versioning 2.0** (`MAJOR.MINOR.PATCH`) for the core protocol and reference implementation:

| Part | When it increments |
|---|---|
| `MAJOR` | Breaking change to the protocol spec or a public API surface |
| `MINOR` | New backward-compatible capabilities (new endpoints, new fields, new MCP tools) |
| `PATCH` | Bug fixes, security patches, documentation corrections — no behavior change |

**Current stable version**: `1.0.x`

SDKs and the MCP server follow independent versioning:
- TypeScript SDK: `0.x` (pre-stable, minor versions may break)
- Python SDK: `0.x` (pre-stable, minor versions may break)
- MCP server: `0.x` (pre-stable)

---

## What Is Stable

These surfaces carry full `1.x` stability guarantees:

### Protocol Spec
- All state transitions in the handshake lifecycle (`initiated → pending_verification → verified → consumed`)
- All terminal states and their irreversibility guarantee
- Binding structure: `binding_hash`, `payload_hash`, `nonce`, `expires_at`, `consumed_at`
- All RPC function signatures in `supabase/migrations/` that are `CREATE OR REPLACE FUNCTION` with documented parameters
- Error code strings (e.g. `binding_already_consumed`, `nonce_required`, `policy_hash_mismatch`) — these are stable identifiers used in client error handling

### HTTP API (`/api/...` endpoints)
- All endpoints listed in `docs/api/ROUTES.md` as "protocol-essential" (17 endpoints)
- Request body field names and their semantics for stable endpoints
- `resource_ref` is the canonical resource identifier field — this name will not change in `1.x`
- RFC 7807 error envelope format (`type`, `title`, `status`, `detail`)
- Response field names for 200/201 responses on stable endpoints

### MCP Tools (protocol-core tools only)
- `ep_evaluate_trust`, `ep_submit_receipt`, `ep_initiate_handshake`, `ep_verify_handshake`, `ep_consume_handshake`, `ep_issue_signoff_challenge`, `ep_approve_signoff`, `ep_consume_signoff`
- Tool names and their required/optional parameter semantics

---

## What Is Not Stable (Yet)

These surfaces may change in minor versions during the `1.x` cycle without a MAJOR increment, with deprecation notices:

| Surface | Status | Notes |
|---|---|---|
| TypeScript SDK | `0.x` — pre-stable | Method signatures may change; follow `CHANGELOG.md` |
| Python SDK | `0.x` — pre-stable | Same as TypeScript SDK |
| MCP server tools (non-core) | `0.x` — pre-stable | Advanced tools may be renamed or split |
| Cloud API (`/api/cloud/...`) | `1.x` — stable for authenticated operators | Cloud-specific endpoints are stable; new fields may be added |
| Internal telemetry log format | Advisory only | Log field names used for observability may evolve; build on the `_ep_telemetry: true` filter, not specific field paths |
| Supabase table schemas | Additive-only guarantee | Columns will not be removed or renamed in `1.x`; new columns may be added |

---

## Breaking Change Policy

A **breaking change** is any change that requires a client to update their code to continue working. Breaking changes are only shipped in a new MAJOR version.

**What counts as breaking:**
- Removing or renaming a field in a stable request/response body
- Changing the meaning of an existing field (e.g., changing a boolean to an enum)
- Removing a stable endpoint
- Changing an error code string that clients match on
- Removing a parameter from a stable RPC function

**What does NOT count as breaking:**
- Adding a new optional field to a request body
- Adding a new field to a response body (clients must tolerate unknown fields)
- Adding a new endpoint
- Adding a new error code (clients should handle unknown codes gracefully)
- Changing the default value of an optional parameter (if backward-compatible)
- Security patches that change behavior to close a vulnerability (these take precedence)

---

## Deprecation Process

Before removing or changing a stable surface:

1. **Deprecation notice**: The surface is marked deprecated in the docs and with a `Deprecation-Notice` response header (for HTTP endpoints) for at minimum **one MINOR release cycle** (approximately 3 months).
2. **Migration guide**: A migration path is documented in `docs/api/DEPRECATIONS.md`.
3. **Removal**: Only in the next MAJOR release.

For security-critical changes, the deprecation window may be shortened or skipped. Security patches are never treated as breaking changes regardless of behavior impact.

---

## Support Lifecycle

| Version | Status | Support ends |
|---|---|---|
| `1.0.x` (current) | **Actively supported** | Until `2.0.0` is released + 12 months |
| `0.9.x` and below | **Unsupported** | Ended 2026-03-18 (v1.0.0 release date) |

**Security patches** are backported to the current stable `1.x` branch for the duration of active support. Protocol-breaking security vulnerabilities trigger an immediate patch release.

---

## Migration from `0.x`

If you are running a pre-`1.0` version:

1. Review `CHANGELOG.md` for all `1.0.0` changes (especially the handshake lifecycle additions, EP Commit, and signoff chain)
2. Ensure your client handles RFC 7807 error envelopes
3. Ensure your client forwards `nonce` from the binding response to the verify step — this is required in `1.x` (see `docs/api/ERRORS.md#nonce_required`)
4. If you use direct Postgres queries against EP tables: migrate to the public RPC layer — direct table access is not a stable interface

---

## Compatibility Guarantees Summary

| Guarantee | Applies to |
|---|---|
| No field removal without MAJOR bump | All stable HTTP API endpoints and MCP core tools |
| No endpoint removal without MAJOR bump | All endpoints in `docs/api/ROUTES.md` |
| No error code string changes without MAJOR bump | All error codes in `docs/api/ERRORS.md` |
| Additive-only schema changes | All Supabase tables (columns added, never removed in `1.x`) |
| Security patches may change behavior | Any surface, any time — security takes precedence |

---

## Asking Questions / Reporting Compatibility Issues

- **GitHub Discussions**: Open a discussion tagged `compatibility` for questions about the stability policy
- **Security issues**: Follow `SECURITY.md` for responsible disclosure
- **Breaking change proposals**: Open a GitHub issue with the `breaking-change` label — all breaking changes are discussed publicly before adoption

*This policy applies to `v1.0.0` and later. It supersedes all prior informal stability commitments.*
