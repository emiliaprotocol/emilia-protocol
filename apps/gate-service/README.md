# EMILIA Gate Service

Dependency-light BYOC HTTP enforcement for one complete-mediated action:
`github.repo.delete`.

The service owns both GitHub calls. It authorizes the authenticated principal for
the requested repository before touching durable state or GitHub, observes the
repository from GitHub, binds the observed fields to an EMILIA receipt, and only
then dispatches DELETE.

The machine-readable API contract is [openapi.json](./openapi.json).

## Security Contract

- Authentication returns a principal object with a stable `id`. Target
  authorization runs before action creation or connector lookup. Action reads
  are scoped to the principal that created the row.
- The request body accepts exactly `action`, `owner`, and `repo`. Caller-supplied
  observation fields, receipts, and extra keys are refused.
- A 428 response creates or updates one durable challenged row. The caller
  resumes that row at `POST /v1/actions/:id/execute` with the returned challenge
  binding. Resume is an atomic state transition, re-observes GitHub, and never
  accepts replacement target fields.
- The only receipt ingress is `X-EMILIA-Receipt`, carrying canonical base64 or
  base64url of strict JSON. Duplicate JSON members, malformed UTF-8, mixed
  alphabets, and non-canonical encoding fail closed.
- Receipt-embedded issuer keys are never trusted. Issuer and approver keys must
  be pinned by configuration, and `allowInlineKey` is always false.
- A durable ownership-fenced consumption store, durable atomic evidence log,
  and durable action store are mandatory. The evidence log must support scoped
  head, record, history, and verification reads; it cannot be write-only.
- The service persists `executing` before DELETE. Any exception after dispatch
  is `indeterminate`. Startup atomically reconciles interrupted `observing`,
  `authorizing`, and `executing` rows to `indeterminate`; it never retries an
  external effect automatically.
- GitHub response bodies are read incrementally with a hard byte limit. Oversize
  and aborted streams are cancelled without calling `response.text()`.
- `/v1/live` is process-only. `/v1/ready` performs a bounded, coalesced dependency
  check. SIGTERM and SIGINT mark readiness unavailable, stop accepting, drain
  active handlers for the HTTP request-timeout grace, force-close overdue
  connections, and invoke configured adapter `close()` hooks.
- SIEM forwarding is optional and non-authoritative. Delivery failures are
  counted in `/v1/metrics` but never alter authorization or execution.
- Public responses and logs use closed error codes and redacted projections.
  Connector errors, credentials, receipt bodies, subjects, and repository
  metadata are not exposed through evidence or operational endpoints.

EMILIA evidence is not a substitute for caller authentication or GitHub
authorization. The GitHub credential needs repository Administration write
access; see GitHub's [Delete a repository REST documentation](https://docs.github.com/en/rest/repos/repos#delete-a-repository).

## Production Configuration

The default startup path uses the built-in environment-backed Postgres factory
in `src/production-config.js`. Customers do not need to author executable
security configuration. The required Postgres consumption, evidence, and action
tables must already be installed by the operator.

Required environment variables:

| Variable | Purpose |
| --- | --- |
| `EMILIA_GATE_DATABASE_URL` | Postgres connection string for the supported adapters |
| `GITHUB_TOKEN` | GitHub credential captured inside the connector closure |
| `EMILIA_GATE_API_TOKEN` | 32-1024 character Gate bearer token |
| `EMILIA_GATE_PRINCIPAL_ID` | Principal returned for that token |
| `EMILIA_GATE_TENANT_ID` | Fixed tenant scope for actions and evidence |
| `EMILIA_GATE_ID` | Fixed gate scope for actions and evidence |
| `EMILIA_GATE_ALLOWED_REPOSITORIES` | Comma-separated, explicit `owner/repo` allowlist |
| `EMILIA_GATE_TRUST_JSON` | Strict JSON with `trustedKeys`, `approverKeys`, `rpId`, and `allowedOrigins` |

Useful optional variables include `EMILIA_GATE_EVIDENCE_STREAM_ID`,
`GITHUB_API_VERSION`, `EMILIA_GATE_CONNECTOR_TIMEOUT_MS`,
`EMILIA_GATE_READINESS_TIMEOUT_MS`, and the documented size limits mirrored in
`src/production-config.js`.

Optional SIEM forwarding uses:

```text
EMILIA_GATE_SIEM_URL=https://collector.example/v1/events
EMILIA_GATE_SIEM_FORMAT=ocsf
EMILIA_GATE_SIEM_BEARER_TOKEN=...
```

The SIEM URL must use HTTPS. The bearer token is optional. Delivery has a hard
timeout and remains non-authoritative.

Start the built-in production service:

```bash
npm start
```

It listens on `127.0.0.1:8787` by default. `HOST` and `PORT` may override the
listener.

### Custom Adapters

`EMILIA_GATE_CONFIG=/absolute/path/to/gate.config.mjs` remains an explicit
advanced escape hatch. Its default export must return a config satisfying these
security-relevant contracts:

The repository's Helm and Terraform reference modules deliberately use this
escape hatch so operators can own Kubernetes Secret mapping, migrations, and
adapter lifecycle. That deployment choice does not make the custom module
mandatory for direct or Docker use of the built-in production factory.

```js
{
  tenantId: 'tenant-1',
  gateId: 'gate-1',
  authenticateRequest: async (request) => ({ id: 'principal-1' }),
  authorizeAction: async (principal, action, owner, repo) => true,
  authorizeEvidence: async (principal, operation, tenantId, gateId, actionId) => true,

  actionStore: {
    durable: true,
    async create(record) {},
    async get(id, principalId) {},
    async update(id, principalId, patch) {},
    async transition(id, principalId, fromStatuses, patch) {},
    async reconcileInterrupted({ action, statuses, patch }) {},
    async close() {}, // optional
  },

  evidenceLog: {
    durable: true,
    persisted: true,
    strict: true,
    forkAware: true,
    atomicAppend: true,
    async record(entry) {},
    async head({ tenantId, gateId, actionId }) {},
    async getRecord({ tenantId, gateId, actionId, recordId }) {},
    async history({ tenantId, gateId, actionId, cursor, limit }) {},
    async verify({ tenantId, gateId, actionId }) {},
    async close() {}, // optional
  },
}
```

`authorizeAction` and `authorizeEvidence` must return exactly `true`; exceptions
and every other value deny access. Store implementations should enforce the same
principal, tenant, and gate predicates in their queries. `transition` and
`reconcileInterrupted` must be atomic.

## HTTP API

### Health

- `GET /v1/live`: process-only 200 while the HTTP process is serving.
- `GET /v1/ready`: 200 only when startup reconciliation completed and the
  bounded dependency check succeeds; otherwise 503.

Neither route authenticates or exposes dependency details.

### Create an Action

```http
POST /v1/actions
Authorization: Bearer <gate token>
Content-Type: application/json

{
  "action": "github.repo.delete",
  "owner": "acme",
  "repo": "production"
}
```

A missing or invalid receipt returns 428 with `Receipt-Required`, the observed
action, and a resume binding. Obtain a receipt for that observed action and
resume the same row:

```http
POST /v1/actions/<action-id>/execute
Authorization: Bearer <gate token>
X-EMILIA-Receipt: <canonical base64 receipt>
Content-Type: application/json

{
  "action": "github.repo.delete",
  "challenge_binding": "<64 lowercase hex characters>"
}
```

The resume path accepts no owner or repository fields. It atomically claims a
challenged row and performs a fresh GitHub GET before evaluating the receipt.
Concurrent or stale resumes return 409.

### Read an Action

`GET /v1/actions/:id` returns a sanitized record only to the principal that owns
it. Missing and cross-principal records both return 404.

### Evidence

All evidence routes require bearer authentication and the exact `tenant_id`,
`gate_id`, and action-row `action_id` query parameters:

- `GET /v1/evidence/head`
- `GET /v1/evidence/records/:recordId`
- `GET /v1/evidence/history?cursor=0&limit=50`
- `GET /v1/evidence/verify`
- `GET /v1/evidence/export?cursor=0&limit=50`

History and export limits are 1-100. Records expose chain identifiers and closed
decision/execution fields, but omit receipt IDs, subjects, target names, raw
proofs, and provider payloads. Verification returns 409 for a detected tamper,
fork, rollback, or malformed chain.

### Metrics

`GET /v1/metrics?tenant_id=...&gate_id=...&action_id=github.repo.delete`
returns authenticated lifecycle and operational counters. It includes telemetry
forward/drop counts and no repository, credential, or dependency metadata.

## Tests

All GitHub and Postgres behavior is mocked; the suite makes no network calls.

```bash
npm test
```
