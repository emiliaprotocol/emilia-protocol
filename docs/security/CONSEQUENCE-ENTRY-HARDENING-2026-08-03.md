<!-- SPDX-License-Identifier: Apache-2.0 -->
# Consequence-entry hardening record — 2026-08-03

This record separates confirmed gaps from stale or unsupported review claims.
It describes repository behavior, not a claim that every deployment has these
controls enabled or that a customer pilot exists.

## Closed in this release

1. **Organization emergency stop.** A typed-confirmation Cloud control invokes
   one database transaction that locks and suspends the tenant, revokes its
   live tenant API keys, and advances an immutable control epoch. Receipt
   consumption takes the same lock and permanently refuses pre-panic receipts.
2. **Last-moment state changes.** `providerEntryGuard` runs after authorization
   and reservation but before the external effect. Throws and malformed,
   stale, unauthenticated, or negative observations fail closed.
3. **Runtime value limits.** Base-currency limits use the exact observed action.
   Non-USD actions require a fresh Ed25519-signed value attestation pinned by
   source, key, exact action digest, asset, validity window, and value ceiling.
4. **Class-A attention policy.** Approval binds a deterministic display hash,
   server-owned ceremony-policy digest, action-specific confirmation hash, and
   server-measured review start. An atomic database counter limits approvals
   per approver and organization; denials remain unthrottled.
5. **Display/action consistency.** Challenge issuance independently renders
   the stored canonical action and refuses if its derived action hash differs
   from the receipt-issued action hash.
6. **MongoDB system-of-record adapter.** Bulk delete, bulk update, and collection
   drop use an opaque cluster-pinned connector. Filter and update preimages are
   executed only when their canonical digests match the authorized action.

## Review claims that were already satisfied

AWS, Stripe, GitHub, Supabase/Postgres, and Kubernetes adapters existed before
this release. The connected Class-A route already required canonical-action
rendering and bound its display hash into the WebAuthn-signed context. The
government mobile profile already supports an independently resolved
system-of-record action rather than trusting a requester-authored summary.

## Boundaries that remain true

- An MCP wrapper covers MCP calls, not direct SDK, shell, database, or alternate
  provider paths. Complete mediation requires credential custody plus network
  or system-of-record controls that reject every bypass path.
- eBPF can help force traffic through an enforcement point, but it cannot infer
  exact application semantics from opaque traffic and is not a substitute for
  an action adapter.
- A review interval, confirmation phrase, and biometric assertion do not prove
  comprehension or freedom from coercion.
- No insurance-premium discount, revenue, customer deployment, or design
  partner is asserted by this engineering release. Those require independent
  commercial evidence.
