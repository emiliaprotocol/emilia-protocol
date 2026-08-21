<!-- SPDX-License-Identifier: Apache-2.0 -->
# Customer-owned authority border

EMILIA's customer-owned authority border uses the existing Gate enforcement
core. It does not replace provider authentication, native policy, source truth,
settlement, or effect observation.

## Protection configuration

`EMILIA-PROTECTION-PLAN-v1` is an unsigned owner draft. It compiles the six
plain-language consequence selections into an Action Control Manifest, but the
selection is not authority and is not active protection.

`EP-PROTECTION-ACTIVATION-v1` is a customer signature over the exact draft,
manifest, tenant, gateway, epoch, and validity window. A gateway must verify it
under customer-pinned keys and pin its exact digest again at startup. This is
configuration authority only. Each consequential action still requires its
own valid authorization evidence and one-time admission.

## Customer-owned MCP gateway

`withCustomerOwnedProtectionGateway()` maps the activated manifest's exact MCP
tool selectors to action families and assurance floors. Unknown tools are
irreversible by default. Only a locally configured read-only set bypasses the
receipt challenge. Production assembly refuses an ephemeral consumption store
or provenance ledger. Provider credentials remain in the executor handler and
are never passed to the gateway wrapper.

This establishes behavior only for tool calls that pass through the configured
gateway. A signed activation does not prove installation or complete mediation.

## Adapter revision registry

`EP-ADAPTER-MANIFEST-v1` binds one adapter identity to:

- a named external specification revision, digest, and retrieval URI;
- the adapter implementation artifact digest and source commit;
- a build receipt;
- a conformance profile and receipt; and
- a closed supported-operation set, status, and validity window.

The registry is loaded as an immutable, signed set. Runtime resolution refuses
external revision drift, implementation drift, unsupported operations,
withdrawn adapters, duplicate identities, expiry, and signature failure. These
bindings do not prove an external provider behaved as documented.

## State-domain migration

`migrateStateDomain()` performs a cutover in this order:

1. freeze the source;
2. read its final journal head and unresolved-operation commitment;
3. import the snapshot into a sealed target;
4. verify an external credential, lease, or trust-root fence;
5. activate the target at a higher epoch;
6. tombstone the source; and
7. issue `EP-STATE-DOMAIN-MIGRATION-RECEIPT-v1`.

The function emits no completed receipt before all seven steps succeed. A
failure after target activation is `INDETERMINATE`, while the source remains
frozen. The external fence is required from the first usable version because a
software instance cannot permanently exclude a malicious old copy by asking
that copy to fence itself.

The receipt binds the verified assertions and transition evidence. It cannot
guarantee a non-EMILIA destination preserves consumption state, prevents
replay, or behaves safely.

## Runnable references

- `examples/finance-loss-boundary/`
- `examples/customer-owned-mcp-gateway/`

Both are synthetic and local. They make no network request and do not claim
production deployment or external effect.
