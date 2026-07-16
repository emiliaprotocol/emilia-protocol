# EMILIA Gate Service

Dependency-light BYOC HTTP enforcement for one complete-mediated action:
`github.repo.delete`.

The service owns both GitHub calls. It resolves the caller's `owner`/`repo`
locator with a fresh repository `GET`, derives the canonical
`owner`, `repo`, `node_id`, `default_branch`, and `visibility` from that response,
binds all five fields through `createTrustedActionFirewall`, and only then issues
the repository `DELETE`.

## Security Contract

- The request body accepts exactly `action`, `owner`, and `repo`. Caller-supplied
  observed fields, receipts, and extra keys are refused.
- The only receipt ingress is `X-EMILIA-Receipt`, carrying canonical base64 or
  base64url of strict JSON. The decoded default limit is 64 KiB; duplicate JSON
  members, malformed UTF-8, mixed alphabets, and non-canonical encoding fail
  closed.
- Receipt-embedded issuer keys are never trusted. Issuer and approver keys must
  be pinned by operator configuration, and `allowInlineKey` is always false.
- A durable ownership-fenced consumption store, durable atomic evidence log,
  and durable action-status store are mandatory configuration dependencies.
  There are no production in-memory fallbacks.
- After the DELETE is dispatched, every connector exception is treated as an
  indeterminate effect. The receipt is committed or left reserved, an
  `indeterminate` execution record is appended, and the service never retries
  the DELETE automatically.
- A stable receipt-derived `Idempotency-Key` is sent with DELETE for BYOC
  gateways and correlation. The service does not assume the upstream GitHub
  endpoint deduplicates requests.
- Logs contain only event name, generated action ID, and closed status. Receipt
  bodies, connector errors, response bodies, tokens, and secrets are never
  passed to the logger.

EMILIA evidence is not caller authentication or GitHub authorization. Put this
service behind the organization's normal identity, permission, and network
controls. The GitHub credential needs repository Administration write access;
see GitHub's [Delete a repository REST documentation](https://docs.github.com/en/rest/repos/repos#delete-a-repository).

## Operator Configuration

`EMILIA_GATE_CONFIG` must name an ESM module whose default export is a config
object or async config factory. Secrets stay inside the operator module and the
connector closure, not in the gate config surface.

```js
import { createGithubRestConnector } from './apps/gate-service/src/github-client.js';

export default async function config() {
  return {
    connector: createGithubRestConnector({
      token: process.env.GITHUB_TOKEN,
      apiVersion: '2026-03-10',
    }),
    consumptionStore, // durable + ownershipFenced + permanentConsumption
    evidenceLog,      // durable + strict + forkAware + atomicAppend
    actionStore,      // durable create/update/get contract
    trustedKeys: issuerPublicKeys,
    approverKeys,
    rpId: 'approve.example.com',
    allowedOrigins: ['https://approve.example.com'],
  };
}
```

The action store contract is deliberately small:

```js
{
  durable: true,
  async create(record) {}, // atomic insert-if-absent; true or false
  async update(id, patch) {}, // durable write; true on success
  async get(id) {}, // record or null
}
```

Start the service from this directory:

```bash
EMILIA_GATE_CONFIG=/absolute/path/to/gate.config.mjs npm start
```

It listens on `127.0.0.1:8787` by default. `HOST` and `PORT` may override the
listener.

## HTTP API

### `POST /v1/actions`

```json
{
  "action": "github.repo.delete",
  "owner": "acme",
  "repo": "production"
}
```

Present a receipt only as:

```text
X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 strict JSON>)
```

A missing, malformed, invalid, mismatched, or replayed receipt returns HTTP 428.
The challenge includes the service-observed action and its canonical hash so the
caller can obtain an exact receipt without supplying observation fields.

### `GET /v1/actions/:id`

Returns the sanitized durable action record. No receipt or connector payload is
stored in this record.

### `GET /v1/health`

Returns static process readiness without probing GitHub or exposing config.

## Tests

All GitHub behavior is mocked; the suite makes no network calls.

```bash
npm test
```
