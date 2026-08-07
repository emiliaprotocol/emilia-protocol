# @emilia-protocol/gateway-authz

> **Reference / experimental. Not production audited.**

An external-authorization handler that demands an EMILIA authorization receipt
and binds it to the exact request. One pure core, two thin proxy adapters:
Envoy `ext_authz` (HTTP variant) and Kong. EMILIA rides the proxy you already
run; it does not ask you to adopt a new transport.

```js
import { createExternalAuthorizer, createEnvoyHttpHandler } from '@emilia-protocol/gateway-authz';
import { createServer } from 'node:http';

const authorizer = createExternalAuthorizer({
  baseAction: 'payments.release',
  target: 'payments.internal.example',
  trustedKeys: [process.env.EP_ISSUER_SPKI],   // pinned by you, never inline
  materialHeaders: ['idempotency-key'],
  assuranceClass: 'class_a',
  store: postgresConsumptionStore,             // atomic reserve/commit/release
});

createServer(createEnvoyHttpHandler(authorizer)).listen(8788);
```

---

## Read this first: the body, or nothing

**A proxy that does not buffer the request body cannot bind the receipt to the
request, and a deployment that ships anyway is carrying an unbound receipt.**

This is not a footnote. It is the reason the package exists.

An external-authorization call is a *description* of somebody else's request.
The proxy tells the authorizer what it thinks is happening, the authorizer says
yes, and the proxy forwards the real request. If that description omits the
body, the authorizer approved a method and a path — and the body, which is
where the beneficiary, the amount, and the record being deleted actually live,
went entirely unexamined. A receipt approved for `POST /v1/payments` with one
body is then spendable on `POST /v1/payments` with any other body. The receipt
is genuine. The signature verifies. It is simply not an approval of *this*
request.

So this package has no "bind what we have" path. `bodyBytes` is required, and a
descriptor without one is **refused with `request_body_not_buffered` and HTTP
500** — a server-side status, deliberately, because a 4xx would teach operators
to blame callers for a gateway they never configured.

### Envoy

Set `with_request_body` on the `ext_authz` filter, or every request is refused:

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    failure_mode_allow: false          # a refusal that fails open is not a refusal
    with_request_body:
      max_request_bytes: 1048576       # >= your largest guarded body
      allow_partial_message: false     # a prefix of the body is not the body
      pack_as_bytes: true
    http_service: { ... }
```

Envoy signals truncation with `x-envoy-auth-partial-body: true`. This handler
refuses that too (`request_body_truncated`), because a digest over a prefix of
the body is not a digest of the body. If the header is absent entirely,
`with_request_body` was never configured and no body reached the authorizer at
all — also refused.

The pseudo-headers `:method`, `:path`, and `:authority` are not forwarded as
ordinary headers by the HTTP variant. This adapter reads the same
`x-ep-original-*` projection that
[`examples/receipt-required-gateways/envoy/envoy.yaml`](../../examples/receipt-required-gateways/envoy/envoy.yaml)
already establishes with a Lua filter — a filter that **overwrites** those
headers before `ext_authz` sees them, so a client cannot supply its own. Reuse
that config; do not let the client name its own method, path, or host.

That existing reference deliberately pins one immutable action hash precisely
because its auth subrequest carries no authoritative body. This package is the
variable-body answer to that limitation, and it only works if you configure the
body through.

### Kong

`kong.request.get_raw_body()` returns nothing once the body exceeds
`client_body_buffer_size` and nginx spills it to a temporary file. Raise it
above your largest guarded body:

```
nginx_http_client_body_buffer_size = 1m
```

Below that threshold the plugin refuses (`request_body_not_buffered`) rather
than proxying a body no receipt ever covered.

---

## What IS bound

Every field below is part of the canonical action that the receipt's signed
`claim.canonical_action` must equal and that its `claim.action_type` digest
covers. Change any one and verification fails with `action_mismatch`.

| Field | Meaning |
| --- | --- |
| `transport` | Constant `http`. A receipt for a gRPC call cannot be spent here. |
| `method` | Upper-cased request method. |
| `target` | The authority the request is bound for. |
| `path` | Absolute path, with the query string split off. |
| `query` | Raw query string, or `""`. |
| `body_sha256` | SHA-256 over the **buffered request body bytes**. |
| `body_bytes` | Byte length, so truncation is a different action. |
| `headers` | Only the header names you pinned in `materialHeaders`, each bound as its value or as `null` when absent. |

Verification, freshness, assurance-tier evaluation, and one-time consumption are
**not reimplemented here**. The authorizer constructs `makeReceiptGate` from
`@emilia-protocol/require-receipt` and uses that published path.

## What is NOT bound

- **Any header you did not pin.** Only `materialHeaders` entries enter the
  action. Tracing headers, cookies, auth tokens, and user agents are outside the
  approval and can differ freely between the approved request and the executed
  one. If a header changes what the upstream does, pin it.
- **TLS identity, client IP, ALPN, or HTTP version.** A receipt approved for a
  request does not constrain how that request was transported.
- **The upstream selection.** `target` is what the authorizer was told the
  authority is. Binding it stops a receipt for staging being spent on
  production only to the extent that your proxy tells the truth about the host;
  a proxy that lets a client set `:authority` freely is a proxy that lets a
  client choose which action it is asking for.
- **Anything after the allow.** The approval covers the request as it was when
  the authorizer saw it. A filter that mutates the body *after* `ext_authz`
  forwards a body no receipt covers. Do not put body-rewriting filters
  downstream of the authorization filter.
- **The response.** The approval covers what is asked, not what comes back.
- **Semantic equivalence.** The bytes are bound, not their meaning. Two JSON
  encodings of the same logical request are two actions. Normalize upstream of
  the approval if that matters to you.

---

## Refusals

Every refusal is a **returned decision carrying a reason**, never a thrown
exception, and the reason travels in three places: the `x-ep-refusal-reason`
header, the `rejected.reason` field of the `application/problem+json` body, and
the decision object itself. A gateway authorizer that faults instead of refusing
is a gateway authorizer that gets `failure_mode_allow: true` switched on by
whoever is paged at 3am.

| Situation | Status | Reason |
| --- | --- | --- |
| No receipt presented | 428 | `receipt_required` |
| Receipt does not match this request | 428 | `action_mismatch` |
| Signature, freshness, assurance failure | 428 | verifier reason |
| Already-spent receipt | 428 | `replay_refused` |
| **Proxy sent no body / a truncated body** | **500** | `request_body_not_buffered`, `request_body_truncated` |
| Body over the configured bound | 413 | `request_body_too_large` |
| Descriptor unparseable | 400 | `request_path_invalid`, `header_ambiguous`, `content_length_mismatch`, … |
| Consumption store cannot answer | 503 | `consumption_store_unavailable` |

428 is the Receipt Required rail, matching `packages/require-receipt`: the body
is the full challenge, so an agent can read `required.action`,
`required.action_hash`, and the authorization endpoint and obtain the exact
proof rather than dead-ending. The non-428 rows are the cases a caller cannot
fix by getting a better receipt.

Envoy returns a non-2xx ext_authz response to the downstream client verbatim, so
the challenge reaches the agent unchanged. Kong terminates via
`kong.response.exit` with the same status, body, and headers.

---

## The indeterminate case

**Forwarding consumes the authority, unconditionally.** A gateway hands the
request to an upstream it cannot observe. From the moment the allow is returned,
"the upstream refused" and "the upstream acted and the answer was lost" are the
same observation, so no spendable approval may survive.

`createEnvoyHttpHandler` and `createKongAccessHandler` both use
`authorizeAndForward`, which commits before the allow is returned. If you drive
the core yourself, `decision.commitOnForward()` is that step and
`decision.abandon()` is the only path that **releases** — legal only while the
request has provably not been forwarded. After forwarding it returns
`authority_not_releasable` and does nothing.

If the commit itself fails, the reservation is deliberately left standing: an
unresolvable consumption state refuses the next attempt instead of allowing it.

---

## What is proven, and what is not

Run `npm test` in this directory (55 tests across three suites).

**Proven by execution here:** the binding properties (substituted body, changed
method, path, query, target, truncation, summarized-body rejection, unpinned
headers being outside the approval); refusal on missing, malformed, forged,
drifted, and replayed receipts; refusal as a reason rather than a throw for
every malformed input; one-time consumption including the in-flight race;
forwarding consuming the authority and release being unreachable afterwards;
fail-closed behaviour when the body is absent, truncated, oversized, or when the
store or the commit fails. The Envoy handler is exercised over a real
`node:http` server on a live socket — the same thing Envoy talks to.

**Not proven here:** behaviour behind a live Envoy or a live Kong. The Envoy
adapter is coded to the documented `ext_authz` HTTP contract (`with_request_body`,
`x-envoy-auth-partial-body`, non-2xx returned verbatim, allowed upstream
headers) and the Kong adapter to the JS PDK's access-phase surface; those
contracts are exercised against the shapes documented above, not against the
proxies themselves. The pure decision functions `toEnvoyHttpResponse`,
`toKongExit`, `envoyDescriptor`, and `kongDescriptor` are where those contracts
are isolated, so a contract error is a small, reviewable diff rather than a
rewrite.

---

## Production decisions this package does not make for you

- Configure body buffering. Everything above is moot without it.
- Set `failure_mode_allow: false`. An authorizer that fails open is decoration.
- Pin issuer keys yourself. `allowInlineKey` proves integrity, not trust; leave
  it off outside demos.
- Supply a durable, fleet-wide, ownership-fenced consumption store. The default
  in-memory store is process-local and is not a replay boundary for a fleet.
- Strip the proof carrier and the internal `x-ep-original-*` headers before the
  upstream sees them. The decision tells you which headers to remove; the proxy
  has to actually remove them.
- Choose the assurance tier. `software` means a machine key signed something; it
  is not evidence that a named human was present.
- Decide how an indeterminate forward is reconciled operationally. Consumption
  prevents blind replay; it does not tell you whether the effect occurred.

Apache-2.0.
