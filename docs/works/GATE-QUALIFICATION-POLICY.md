<!-- SPDX-License-Identifier: Apache-2.0 -->

# Gate qualification in the marketplace

Status: implemented verifier and request UI. Hosted verification requires operator configuration. It is not an operated certification program or an agent-wide endorsement.

## What the result means

“Qualified for this test scope” binds one candidate manifest, assignment, qualification policy and protected request to a verified evidence graph and a trusted status observation. It is a narrow result at an observed time, not a promise about all tasks or future versions.

The implementation reuses `packages/verify/gate-qualification.js`, the existing Gate Qualification v2 evaluator. It does not define a new signature scheme, qualify an agent from a scan or issue qualification statements. A trusted qualifier must already have signed the statement. The verifier checks its evidence and currentness; it does not substitute its own judgment for the named test policy.

These steps remain separate:

- A **listing** contains a builder's claims.
- A **free scan** inspects declared tools and permissions. It does not run or qualify the agent.
- A **qualification check** verifies signed evidence for the registered test scope.
- A **Gate deployment** enforces the configured authorization boundary for an actual integration. Qualification does not prove that deployment exists.
- **Authorization and provider outcomes** need their own evidence. Qualification cannot grant permission or prove that an external action happened.

Payment may buy agreed testing, integration or operation services. It cannot buy a favorable result. No result here is accredited certification, compliance approval, a safety certificate or a performance guarantee. Unknown, incomplete and failed checks stay distinct from a positive result.

## Hosted request contract

The existing `WORKS_V0=1` flag enables `/works/qualification` and `POST /api/works/qualification`. Without it, both are unavailable. The request has exactly two fields:

```json
{
  "scope_id": "operator-registered-scope",
  "evidence": {
    "candidate_manifest": {},
    "campaigns": [],
    "test_results": [],
    "agent_evaluation_evidence": [],
    "qualification_statement": {},
    "runtime_measurement": {}
  }
}
```

This is a field map, **not valid evidence**. The manifest must satisfy the existing candidate schema. The five evidence categories after the manifest contain the existing signed DSSE artifacts: arrays for campaigns, test results and agent evidence; single envelopes for the qualification statement and runtime measurement. Empty placeholders above do not verify.

The presenter cannot supply a verdict, payment state, installation flag, clock, trust policy, status chain or status observation. Extra fields are rejected. A runtime measurement must be signed by a source accepted by the operator, not just a claim that Gate is installed.

The endpoint accepts JSON only, rejects duplicate keys, limits the complete streamed request to 256 KiB even when Content-Length is absent or false, and applies the existing fail-closed `mcp_tool_call` rate tier with durable limiting required in deployed environments. It does not fetch uploaded URLs, execute tools, retain evidence, create a listing or publish a badge. Handler errors do not echo submitted artifacts or backend error details. Infrastructure-level logging and retention must be separately reviewed before using sensitive data.

The page sends evidence only after the user confirms they may send it and clicks **Verify evidence**. Unlike the free browser-only scan, this check sends evidence to EMILIA. Do not submit credentials, private keys or customer data. Input is not saved to browser storage.

## Operator configuration

Set server-only `EMILIA_WORKS_QUALIFICATION_CONFIG_JSON` to an object matching the exported `MarketplaceQualificationConfiguration` type in `lib/works/marketplace-qualification.ts`. Do not use a `NEXT_PUBLIC_` variable or populate configuration from a request, listing, scan or checkout event.

The configuration has `version: "emilia.works.qualification-config/v1"` and an array of 1–16 registered `scopes`. Each scope has exactly:

| Field | Operator responsibility |
| --- | --- |
| `scope_id` | Stable lowercase identifier, 1–96 characters, using letters, digits, `.`, `_` or `-`; first character is a letter or digit. |
| `scope_label` | Accurate public description of the named test scope, not an agent-wide safety or certification claim. |
| `context` | Existing `QualificationEvaluationContext` **without `now`**. The server supplies its own clock. |
| `qualification_status_chain` | Complete, signed qualification-status chain accepted under this scope's status policy. |
| `qualification_status_observation` | Trusted operator observation containing `authority_id`, `head_payload_digest`, `sequence` and `observed_at`. |

The context pins all expected candidate, assignment, qualification-policy and protected-request digests; runtime measurement authority and mechanism; status authority and minimum sequence; model-pinning floor; freshness limits; and the existing six role-specific trust policies. Those policies cover campaigns, test results, agent evidence, qualification statements, qualification status and runtime measurements. The existing verifier validates the public keys, accepted key IDs, thresholds and alias constraints. There are no bundled production keys or accepted demo signers.

Hosted freshness limits must each be between 1 and 300 seconds. The model-pinning floor must be `VERSION_PINNED` or `IMMUTABLE_DIGEST`; mutable aliases and unpinnable models are not accepted by this hosted profile. All sources, accepted keys and exact scope pins must be chosen through a separate operator review before enabling a scope. Payment is not that review.

### A status observation is not a status oracle

The observation is trusted host input, not a signed claim from the person requesting verification. Obtain it from the accepted status authority through an authenticated operator process. Preserve its actual observation time, exact signed head and sequence. Never refresh `observed_at` merely because a request arrived or the server restarted.

An expired, revoked, suspended, stale, equivocated or sequence-rolled-back chain cannot yield a positive display. The minimum accepted sequence must be maintained across operator updates; restoring an old configuration can undo that floor. This endpoint is not a durable global anti-rollback store, online status poller or guarantee against a revocation that occurs after observation. The operator must refresh trusted status evidence before its freshness window closes. Until then, missing or stale evidence fails closed.

No production scope or status source is enabled by this implementation. With no configuration, a well-formed request returns HTTP 503, `UNAVAILABLE`, `qualification_not_configured`, and no display. Invalid input still returns HTTP 400. Invalid configuration and unregistered scopes also remain unavailable; there is no permissive fallback.

## Results and display rules

Successful evaluation returns the existing evaluator's separate decision, verification, acceptance, candidate match, assignment scope, currentness, evidence graph and checks. The endpoint preserves `NOT_QUALIFIED` and `INDETERMINATE`, including the exact refusal reason. It does not flatten missing evidence, drift or revocation into a generic pass/fail score.

Only `QUALIFIED` can carry the optional `display` projection. It contains the registered scope, exact digests, observed status head, server check time and an expiry. It contains no uploaded envelopes, signatures, private keys or trust configuration. Its expiry is the earliest of signed status expiry, next status update, observation freshness and runtime-measurement freshness. At that exact expiry, the wrapper refuses to issue a positive display.

The UI charges the full request round trip against that server-issued lifetime. It uses the greater of elapsed monotonic and local wall-clock time, never comparing the browser's absolute clock to the server timestamp. This also expires results when a browser's monotonic clock pauses during device sleep. A backward wall-clock change beyond one second invalidates the display. Editing the scope, evidence or consent clears the result and cancels outstanding requests. Late responses cannot restore an old result. Hiding the page discards a positive display and any request in flight; a fresh check is required after returning.

Responses use `Cache-Control: no-store`. No persistent, downloadable or public qualification badge is created. A future public badge must independently verify its exact scope and fresh status whenever shown, with separate publication consent. A saved screenshot is not a current qualification result.

## Local verification

`tests/works-marketplace-qualification.test.ts` uses real, test-only Ed25519 signatures to cover accepted evidence, forged or untrusted artifacts, mismatched pins, candidate drift, incomplete graphs, revoked and stale status, replayed status sequence, exact display expiry, upload validation and rate-limit failure. The public verifier's own negative suite remains the source of truth for its cryptographic semantics. No test key is loaded by the hosted service.
