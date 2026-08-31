# EMILIA Protocol Python SDK

`emilia-protocol` is the synchronous, zero-runtime-dependency Python client for
the deliberately narrow EMILIA API surface listed below. Version 0.11.0 uses
the canonical `emilia_protocol` import namespace.

```bash
python -m pip install emilia-protocol==0.11.0
```

```python
from emilia_protocol import EPClient

client = EPClient(api_key="ep_live_...")
decision = client.gate(
    entity_id="principal-123",
    action="payment.release",
    policy="strict",
    value_usd=82_000,
)
print(decision.decision)
```

All calls block until the HTTP response arrives. The SDK uses Python's standard
library rather than `httpx`. It supports Python 3.9 and later.

## Fail-closed mutation wrapper

`require_receipt` creates an enforce-mode receipt, confirms durable evidence,
and consumes the exact `action_hash` before it calls your mutation. A callback
that waits for a human signoff is coordination only: the server-side consume
response remains the authority to proceed.

```python
from emilia_protocol import EPClient, RequireReceiptParams

client = EPClient(api_key="ep_live_...")


def release_payment(context):
    # Execute the server-canonicalized action, not the caller's original draft.
    return payments.release(context.canonical_action)


def read_after_write(context):
    # Independently observe what the system of record actually executed.
    return payments.read_execution(context.result["execution_id"])


outcome = client.require_receipt(
    RequireReceiptParams(
        organization_id="org-123",
        action_type="large_payment_release",
        target_resource_id="payment-123",
        executing_system="payments-api",
        amount=82_000,
        currency="USD",
        after_state={"status": "released"},
        execution_reference_id="attempt-456",
        observed_action=read_after_write,
        execution_id=lambda result: result["execution_id"],
        fetch_evidence=True,
    ),
    release_payment,
)

if outcome.execution_status != "attested":
    # The receipt was already consumed and the mutation may have run.
    # Reconcile using the system of record; do not replay blindly.
    raise RuntimeError("execution evidence is incomplete; manual reconciliation required")
```

If no independent observation is supplied, the mutation can still run after
successful receipt consumption, but the result is explicitly `unobserved` and
no execution attestation is emitted. An attestation or evidence-fetch failure
after the mutation returns `indeterminate`/`do_not_retry` state instead of
pretending the action did not happen. A mutation exception likewise happens
after one-time consumption; callers must reconcile before retrying.

For a signoff-required receipt, pass `approver_id` and an
`on_signoff_required` callback that waits for the external approval ceremony.
The wrapper still calls the consume endpoint after that callback, and it will
not invoke the mutation unless the server confirms `status == "consumed"`.

For a multi-party ceremony, pass a `QuorumPolicy` with role-bound approvers.
The SDK asks the server to fan out those signoff seats, hands the full response
to `on_signoff_required`, and still treats only successful one-time consumption
as authority to invoke the mutation.

```python
from emilia_protocol import QuorumApprover, QuorumPolicy

quorum = QuorumPolicy(
    required=2,
    approvers=[
        QuorumApprover(role="controller", approver="human-1"),
        QuorumApprover(role="treasurer", approver="human-2"),
    ],
    window_sec=600,
)
```

`organization_id` is optional on receipt requests. When omitted, the server
derives it from the authenticated principal; when supplied, the server uses it
only as a tenant-binding cross-check.

## Supported API surface

| Client method | HTTP contract |
| --- | --- |
| `initiate_handshake(...)` | `POST /api/handshake` |
| `get_handshake(handshake_id)` | `GET /api/handshake/{handshakeId}` |
| `present(...)` | `POST /api/handshake/{handshakeId}/present` |
| `verify(handshake_id)` | `POST /api/handshake/{handshakeId}/verify` |
| `revoke_handshake(handshake_id, reason)` | `POST /api/handshake/{handshakeId}/revoke` |
| `gate(...)` | `POST /api/trust/gate` |
| `create_trust_receipt(params)` | `POST /api/v1/trust-receipts` |
| `get_trust_receipt(receipt_id)` | `GET /api/v1/trust-receipts/{receiptId}` |
| `request_signoff(params)` | `POST /api/v1/signoffs/request` |
| `consume_trust_receipt(receipt_id, params)` | `POST /api/v1/trust-receipts/{receiptId}/consume` |
| `attest_execution(receipt_id, params)` | `POST /api/v1/trust-receipts/{receiptId}/execution` |
| `get_trust_receipt_evidence(receipt_id)` | `GET /api/v1/trust-receipts/{receiptId}/evidence` |
| `require_receipt(params, mutate)` | Orchestrates the v1 lifecycle above |

The same surface is recorded in `route-contract.json` and tested against both
the maintained OpenAPI documents and the repository's runtime route handlers.

Methods from older previews that are not backed by the current route contract
are intentionally absent. That includes Eye helpers, handshake consumption,
legacy signoff challenge/attestation helpers, cloud-approval prototypes, and
receipt batching.

## Handshake example

```python
from emilia_protocol import EPClient, Party

client = EPClient(api_key="ep_live_...")
handshake = client.initiate_handshake(
    mode="mutual",
    policy_id="strict",
    parties=[
        Party(entity_ref="agent-a", role="initiator"),
        Party(entity_ref="service-b", role="responder"),
    ],
    action_type="payment.release",
    resource_ref="payment-123",
)

client.present(
    handshake.handshake_id,
    party_role="initiator",
    presentation_type="attestation",
    claims={"subject": "agent-a"},
)
verification = client.verify(handshake.handshake_id)
print(verification.outcome)
```

## Configuration and errors

`EPClient` reads `EP_API_KEY` and `EP_BASE_URL` when constructor arguments are
omitted. The default base URL is `https://emiliaprotocol.ai`. Remote cleartext
HTTP is refused unless `allow_insecure_http=True`; loopback HTTP remains usable
for local development.

```python
from emilia_protocol import EPClient, EPError

client = EPClient(timeout=15, retries=2)
try:
    receipt = client.get_trust_receipt("tr_...")
except EPError as error:
    print(error.status, error.code, str(error))
```

Automatic retries apply only to read-only `GET` requests. State-changing
`POST` requests are never replayed by the client.

The API package and import names differ by Python convention:

- distribution: `emilia-protocol`
- import: `emilia_protocol`

The short `ep` namespace was removed in 0.11.0 because it collides with an
unrelated package on PyPI. Runtime availability of individual routes still
depends on the EMILIA deployment selected by `base_url`.
