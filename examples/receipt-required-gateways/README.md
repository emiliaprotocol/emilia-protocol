# Receipt Required gateway references

> **Reference / experimental. Not production audited.** These examples are
> deployable starting points for putting Receipt Required in front of an HTTP
> service without changing that service's code. They are not a substitute for
> an independent review of your keys, proxy, database, action mapping, or
> consequence boundary.

The Cloudflare profile projects and hashes the exact JSON request body. The
Envoy/nginx profile is intentionally limited to one operator-pinned immutable
action hash because their auth subrequests do not carry an authoritative body
in this reference configuration.

All three examples use the same runtime-neutral edge contract in
`packages/require-receipt/src/edge.ts`:

1. bound the request headers and body before doing expensive verification;
2. extract `X-EMILIA-Receipt` without forwarding it upstream;
3. verify the receipt under relying-party-pinned keys and the exact configured
   action;
4. optionally atomically consume `receipt_id` to refuse replay;
5. return either a strict `application/problem+json` HTTP 428 challenge or a
   sanitized allow result containing only the verified action and receipt ID.

The 428 includes `authorization_endpoint`, `EP-APPROVAL-v1`,
`required_fields`, and `caid_selector`, so an agent can obtain the exact proof
and retry instead of dead-ending.

## Cloudflare Worker reverse proxy

The Worker is a complete reverse proxy using the Web Crypto verifier and a
Durable Object as the atomic insert-if-absent replay boundary.

```bash
cd examples/receipt-required-gateways/cloudflare
cp wrangler.toml.example wrangler.toml
npx wrangler secret put EP_TRUSTED_KEYS
npx wrangler deploy
```

`EP_TRUSTED_KEYS` is a JSON array of pinned Ed25519 SPKI-DER public keys in
base64url form. Set `UPSTREAM_ORIGIN`, `EP_ACTION`,
`EP_AUTHORIZATION_ENDPOINT`, and the parameter-binding fields in
`wrangler.toml`. The Worker never follows an upstream redirect.

The example imports repository TypeScript sources so it can be tested before a
new package subpath is published. A package release should export
`@emilia-protocol/require-receipt/edge` and replace those relative imports.

## Envoy `ext_authz` and nginx `auth_request`

Both proxy configurations use `node/auth-service.mts`. The service verifies
with the existing Node Receipt Required verifier and atomically consumes a
receipt through PostgreSQL.

```bash
psql "$DATABASE_URL" -f examples/receipt-required-gateways/node/schema.sql

export DATABASE_URL='postgresql://ep_edge:...@db/ep'
export EP_TRUSTED_KEYS='["MCowBQYDK2VwAyEA..."]'
export EP_ACTION='payment.release'
export EP_ACTION_HASH='sha256:<hash-of-the-one-immutable-canonical-action>'
export EP_AUTHORIZATION_ENDPOINT='https://authorize.example.test/v1/approvals'
export EP_REQUIRED_FIELDS='["action_type","amount","currency","beneficiary_account_hash"]'
export EP_CAID_SELECTOR_FIELD='action_caid'
npx tsx examples/receipt-required-gateways/node/auth-service.mts
```

The SQL file revokes `PUBLIC`; grant `SELECT, INSERT` on the table only to the
dedicated role used by this service. Do not use an application-owner or database
superuser credential.

Then run either proxy after replacing the example upstream cluster/address:

```bash
envoy -c examples/receipt-required-gateways/envoy/envoy.yaml
nginx -c "$PWD/examples/receipt-required-gateways/nginx/nginx.conf" -p "$PWD"
```

Envoy can return the auth service's 428 directly. nginx's `auth_request` module
only understands 2xx/401/403, so its internal subrequest translates a refusal to
403 and an `error_page` location obtains the public 428 problem response. The
protected upstream still sees neither the proof carrier nor the internal proxy
metadata.

## Required production decisions

- Pin issuer keys independently; never trust a receipt's inline key.
- Map each protected route/tool to a server-owned action and exact parameter
  selector. Do not let callers choose the action type.
- Use fleet-wide atomic consumption for one-use receipts. Verification-only
  mode is not sufficient at an irreversible consequence boundary.
- Terminate TLS, authenticate the authorization endpoint, and constrain egress.
- Keep proxy header/body limits aligned with this handler. A proxy rejecting a
  header before the handler runs cannot emit a Receipt Required challenge.
- Decide how an upstream timeout is reconciled. Consumption prevents blind
  replay; it does not prove whether the external effect occurred.
- Run hostile tests and an independent review before production use.
