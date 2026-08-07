# @emilia-protocol/grpc-guard

> **Reference / experimental. Not production audited.**

Demand an EMILIA authorization receipt for a gRPC call, and bind that receipt to
the exact call. EMILIA rides gRPC; it does not ask you to adopt a new transport.

```js
import { createGrpcReceiptGuard, createServerInterceptor } from '@emilia-protocol/grpc-guard';

const guard = createGrpcReceiptGuard({
  baseAction: 'payments.release',
  target: 'payments.internal.example:443',
  trustedKeys: [process.env.EP_ISSUER_SPKI],   // pinned by you, never inline
  assuranceClass: 'class_a',
  store: postgresConsumptionStore,             // atomic reserve/commit/release
});

const { definition, wrap } = createServerInterceptor({
  guard,
  service: paymentsProto.Payments.service,
  methods: ['releasePayment'],
});

server.addService(definition, wrap(implementation));
```

---

## Read this first: carried is not bound

A receipt sitting in gRPC metadata authorizes nothing on its own. Metadata is
detachable. An attacker who observes one approved call can lift the receipt and
paste it onto a different call — a different beneficiary, a different amount, a
different method — and a guard that only asks "is there a valid receipt here?"
will happily authorize it. The receipt is genuine. The signature verifies. The
approval is fresh and unspent. It is simply not an approval of *this* request.

The only thing that closes that gap is deriving the action from material the
attacker would have to change to mount the substitution. This package derives
it from the **serialized request message bytes**, the **fully-qualified method
path**, and the **target**. Change any of them and the action changes, the
receipt no longer matches, and the call is refused.

---

## What IS bound

Every field below is part of the canonical action that the receipt's signed
`claim.canonical_action` must equal and that its `claim.action_type` digest
covers. Change any one of them and verification fails with `action_mismatch`.

| Field | Meaning |
| --- | --- |
| `transport` | Constant `grpc`. A receipt for an HTTP call cannot be spent on a gRPC call. |
| `method` | The fully-qualified method path, `/package.Service/Method`. |
| `target` | The authority the call is addressed to (`host:port`, `dns:///name`, …). |
| `request_sha256` | SHA-256 over the **serialized request message bytes**. |
| `request_bytes` | Byte length of that message, so truncation is a different action. |
| `request_binding` | `wire` or `reserialized` — where the bytes came from (below). |
| `metadata` | Only the metadata keys you pinned in `materialMetadata`, each bound as its value or as `null` when absent. |

Verification, freshness, assurance-tier evaluation, and one-time consumption are
**not reimplemented here**. The guard constructs `makeReceiptGate` from
`@emilia-protocol/require-receipt` and uses that published path.

## What is NOT bound

- **Any metadata key you did not pin.** Only `materialMetadata` entries enter
  the action. Everything else — tracing headers, auth tokens, user agents — is
  outside the approval and can differ freely between the approved call and the
  executed one.
- **Deadlines, compression, peer address, TLS identity, or channel options.**
  A receipt approved for a call does not constrain how that call is transported.
- **The response.** The approval covers what is asked, not what comes back.
- **Anything at all on streaming methods.** This package guards **unary**
  methods only. A client-streaming or bidirectional method has no single request
  message to bind, and this package will not pretend otherwise. See "Limitations".
- **Ordering or timing between calls.** Two separate calls with identical bytes
  are the same action and each needs its own receipt; consumption, not binding,
  is what stops the second one.
- **The semantic meaning of the bytes.** The guard binds the octets. If your
  proto has two encodings of the same logical request, they are two actions.

---

## The limitation that matters: where the bytes come from

**A server that is handed a deserialized message cannot bind the bytes the peer
sent.** This is the gRPC form of the same problem a proxy has when it does not
buffer the request body, and it is the single most important thing to get right
in a deployment.

Protobuf encoding is **not canonical**. Field order, varint width, and map
ordering are all encoder choices, and unknown fields are usually dropped
entirely on a decode/re-encode round trip. So if the guard only sees a decoded
message and re-serializes it to get bytes, the digest it binds covers *what this
process understood*, not *what the peer sent*. A peer can send bytes that carry
more than the guard ever hashes.

This package therefore has two binding sources, and the source is itself part of
the action so the two can never be confused:

- **`wire` (default, and the only one that binds the peer's octets).** The
  guarded methods are registered with a pass-through request codec, so the
  handler chain receives the raw `Buffer`. `createServerInterceptor` does this
  for you: it returns a rewritten `definition` you must pass to
  `server.addService`, binds the raw bytes, and only then decodes with the
  service's own deserializer before entering your handler.

- **`reserialized` (opt-in, weaker).** The guard was given a decoded message and
  an explicit `serializeRequest`, plus `allowReserializedRequestBinding: true`.
  Without that flag the call is refused with
  `request_bytes_reserialization_not_permitted` rather than silently downgraded.

Because `request_binding` is inside the canonical action, a receipt approved
under `wire` will not verify against a `reserialized` binding or the reverse. A
deployment that quietly changes its own binding strength breaks loudly instead
of accepting weaker evidence.

**If you use the original service definition with the wrapped implementation,
the pass-through codec is gone and the raw bytes never reach the guard.** Use the
`definition` that `createServerInterceptor` returns, or you are running an
unbound receipt.

---

## Refusals

Every refusal is a **returned decision carrying a reason**, never a thrown
exception. A guard that throws on an ordinary refusal converts "you need a
receipt" into a server fault, and a service that faults under load is a service
whose guard gets removed to restore availability.

| Situation | gRPC status | `details` |
| --- | --- | --- |
| No receipt in metadata | `FAILED_PRECONDITION` (9) | `receipt_required` |
| Receipt does not match this call | `PERMISSION_DENIED` (7) | `action_mismatch` |
| Signature, freshness, assurance failure | `PERMISSION_DENIED` (7) | verifier reason |
| Already-spent receipt | `ALREADY_EXISTS` (6) | `replay_refused` |
| Call cannot be bound at all | `INVALID_ARGUMENT` (3) | `method_path_invalid`, `request_bytes_unavailable`, `metadata_ambiguous`, … |
| Request over the size bound | `RESOURCE_EXHAUSTED` (8) | `request_too_large` |
| Consumption store cannot answer | `UNAVAILABLE` (14) | `consumption_store_unavailable` |
| Handler never resolved | `UNKNOWN` (2) | `handler_outcome_indeterminate` |

`FAILED_PRECONDITION` is the gRPC analogue of the HTTP 428 Receipt Required
challenge, and it is the only refusal that means "go get a receipt and retry".
The decision also carries the full challenge body, so a well-behaved agent can
read `required.action`, `required.action_hash`, and the authorization endpoint
and obtain the exact proof rather than dead-ending.

---

## The indeterminate case

Once the downstream handler has been entered, **the authority is consumed on
every exit path** — success, thrown error, and an outcome the handler never
resolved. The guard cannot distinguish "nothing happened" from "the payment left
and the response was lost", so it must not leave a spendable approval behind.

```js
const outcome = await decision.invoke((settle) => {
  handler(call, (error, value) => settle({ error, value }));
});
// outcome.reason === 'handler_outcome_indeterminate' when settle was never called
```

`decision.abandon()` is the only path that **releases** authority, and it is
reachable only while the handler has provably not been entered. After
`invoke()` it returns `authority_not_releasable` and does nothing. Set
`handlerTimeoutMs` so a handler that never answers becomes an indeterminate
outcome rather than an authority held open until the transport deadline fires.

If the commit itself fails, the reservation is deliberately left standing: an
unresolvable consumption state refuses the next attempt instead of allowing it.

---

## Client side

`createClientReceiptAttacher` binds the bytes the client is about to send,
obtains a receipt for exactly that binding, and puts it in metadata.
`createClientInterceptor` wires that into a `@grpc/grpc-js` client interceptor
that holds `start` until the message is known, because the receipt binds the
message and metadata is only sendable once. On any attach failure it fails the
call locally rather than sending it unauthorized.

**The client attach is a convenience, never the enforcement.** If the client
binds different bytes than the server receives, the server refuses. There is no
configuration in which a client-side mistake produces an accepted call. To make
client and server bind literally the same octets, use a pass-through request
codec on both sides and send a `Buffer`.

---

## What is proven, and what is not

Run `npm test` in this directory (52 tests across three suites).

**Proven by execution here:** the binding properties (substituted body, changed
method, changed target, truncation, summarized-request rejection); refusal on
missing, malformed, forged, drifted, and replayed receipts; refusal as a reason
rather than a throw; one-time consumption including the in-flight race; the
indeterminate path never releasing authority; release being unreachable after
invocation; fail-closed behaviour when the consumption store or the commit
fails; and the server interceptor end to end over a plain service definition
with plain handlers.

**Not proven here:** behaviour against a live `@grpc/grpc-js` server or client.
`@grpc/grpc-js` is an optional peer dependency and is not installed in this
repository. The client interceptor is coded to the grpc-js interceptor contract
and exercised against a fake that implements that contract; that is a wiring
test, not an interoperability result. The server interceptor needs no grpc-js
internals — it operates on the service definition and handlers, which are plain
data — so its suite runs the real code path.

---

## Production decisions this package does not make for you

- Pin issuer keys yourself. `allowInlineKey` proves integrity, not trust; leave
  it off outside demos.
- Supply a durable, fleet-wide, ownership-fenced consumption store. The default
  in-memory store is process-local and is not a replay boundary for a fleet.
- Choose the assurance tier. `software` means a machine key signed something; it
  is not evidence that a named human was present.
- Decide how an indeterminate outcome is reconciled operationally. Consumption
  prevents blind replay; it does not tell you whether the effect occurred.
- Guard streaming methods some other way, or do not guard them here.

Apache-2.0.
