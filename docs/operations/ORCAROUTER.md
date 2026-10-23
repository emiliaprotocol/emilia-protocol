# OrcaRouter Cyber Inference

OrcaRouter Cyber Inference is the named model provider in EMILIA's Trust Desk
pipeline. It is an OpenAI-compatible gateway for authorized security-team
inference — red-team and blue-team work that general-purpose gateways often
refuse or silently downgrade. See [OrcaRouter Cyber](https://www.orcarouter.ai/cyber)
and the [cyber model catalogue](https://www.orcarouter.ai/models?tier=cyber).

The integration is ordinary provider wiring: a credential seam, a catalog-driven
model selector, and one chat relay. No other provider's configuration is reused,
and no generic "custom base URL" escape hatch was added.

## Two authentication methods

Both methods yield the same thing — a durable OrcaRouter API key (`sk-orca-…`).
Neither stores a refresh token; there is no refresh grant.

### API key

An operator pastes an existing key into the internal provider settings surface
(`/internal/trust-desk/providers`). The key is validated for shape only, sealed
with the repository's secret box (AES-256-GCM, `epenc:v1:`), and written with
mode `0600`. It is never returned to the browser; status responses carry
`sk-orca-…` and nothing else.

For unattended deployments, `ORCAROUTER_API_KEY` remains supported. A stored
credential takes precedence over the environment, and **clearing the stored
credential never edits the environment**.

### OAuth 2.0 + PKCE

The settings surface offers "Connect with OrcaRouter", which implements the
out-of-band flow (Flow B):

1. The server generates a fresh 32-byte verifier, its S256 challenge, and a
   16-byte `state`, sealed in a pending attempt valid for ten minutes.
2. The browser opens the authorization URL at the **auth origin**
   (`https://www.orcarouter.ai/auth`) with `callback_url=oob`,
   `code_challenge_method=S256`, `state`, `app_name`, and `scope=api`.
3. The consent screen displays a code. The operator pastes it back; the server
   consumes the pending attempt **before** exchanging it at
   `POST https://www.orcarouter.ai/api/v1/auth/keys` with
   `{ code, code_verifier, code_challenge_method: "S256" }`.
4. The granted scope is read from the response (not assumed) and must be `api`.
   The returned key is then sealed exactly like a pasted key.

Flow A (loopback redirect) and Flow C (device grant) are deliberately not
implemented: a self-hosted deployment's address differs per operator, and the
approving browser is not guaranteed to share a listener with the server.

Hard gates:

- verifier and state are fresh cryptographic randomness per attempt;
- only `base64url(sha256(verifier))` travels on the authorize URL;
- the verifier never appears in a URL, log, error, or telemetry event;
- state comparison is constant-time;
- a code is single-use — the attempt is consumed before the exchange, so a
  replay cannot mint a second key;
- a 401 from inference marks exactly the stored **generation** that made the
  request as needing reauthentication; an older generation can never mark a
  newer credential;
- the settings UI releases its busy state on success, denial, exchange error,
  timeout, cancel, auth-method switch, unmount, reload, and `pagehide` (with a
  keepalive cancellation), guarded by an attempt generation so a late response
  cannot overwrite a newer one.

## Origins

Authentication and inference are separate public origins. One is never derived
from the other by swapping hostnames.

| Purpose | Default |
| --- | --- |
| Authorize + code exchange | `https://www.orcarouter.ai` |
| Inference + catalog | `https://api.orcarouter.ai/v1` |

Overrides (explicit values win over the shared base):

- `ORCAROUTER_AUTH_BASE_URL`
- `ORCAROUTER_API_BASE_URL`
- `ORCA_BASE_URL` — shared self-hosted base; auth at its root, inference at `/v1`

Remote origins must be HTTPS. HTTP is accepted only for loopback
(`localhost`, `127.0.0.1`, `[::1]`). Origins may not embed credentials or carry
a query or fragment.

## Models

Selection is catalog-driven. `GET /v1/models?capability=…` is the only source of
truth; there is no free-text model field and a model's name never implies a
capability.

- **Default** — `orcarouter/auto`: any OrcaRouter key can route it.
- **Recommended cyber models** — `orcacyber-ultra-1.0`, `orcacyber-zero-1.5`:
  available to business-verified security teams.
- **Fallback** — `orcarouter/fusion`.

Capability filters:

- **Chat** requires a text endpoint (`openai`, `anthropic`, `gemini`,
  `openai-response`). An entry that explicitly declares non-text output is not a
  chat model.
- **Multimodal chat** (`image`, etc.) fails closed: an entry without declared
  input modalities never satisfies the filter.
- **Embeddings, image generation, video, rerank** each require their exact
  endpoint (`embeddings`, `image-generation`, `openai-video`, `jina-rerank`).

The process cache and the last-known-good file hold the **complete** catalog for
a capability, never a per-request modality slice: an image-filtered request must
not hide text-only models from the next unfiltered request. Filtering is applied
on the way out, every time.

Selections are stored **per capability** (`chat`, `embedding`, …), so choosing a
chat model never changes the embedding model. The embeddings adapter reads the
embedding selection; a legacy single-model settings file is read as the chat
selection.

If live discovery fails, the selector uses this deployment's last-known-good
catalog, then a small verified seed, marked degraded. Seed entries carry the
endpoint and output metadata of their own capability, so each survives the same
filter as a live entry. A successful live response is never merged with either
fallback. Changing capability or modality recomputes the list and clears a
selection that no longer satisfies the filters.

## Configuration

| Variable | Purpose |
| --- | --- |
| `ORCAROUTER_API_KEY` | Unattended API key (`sk-orca-…`). Never committed. |
| `ORCAROUTER_PROVIDER_ADMIN` | `1`/`true`/`enabled` exposes the internal settings surface (a feature flag, not an identity). |
| `TRUST_DESK_SESSION_SECRET` / `TRUST_DESK_REVIEWER_ID` | Signed internal administrator session required by every settings route and the page. |
| `TRUST_DESK_ORCAROUTER_MODEL` | Model override when no explicit selection is stored. |
| `TRUST_DESK_ORCAROUTER_EMBEDDING_MODEL` | Embedding model (default `openai/text-embedding-3-small`). |
| `ORCAROUTER_AUTH_BASE_URL` / `ORCAROUTER_API_BASE_URL` / `ORCA_BASE_URL` | Origin overrides. |
| `ORCAROUTER_STATE_DIR` | Runtime state; default `.emilia/orcarouter` (git-ignored). |
| `EP_SECRET_KEY` | 64-hex secret-box key; required in production. |

## Surfaces

| Route | Method | Purpose |
| --- | --- | --- |
| `/internal/trust-desk/providers` | GET | Settings page (admin-gated). |
| `/api/orcarouter/status` | GET | Masked credential, origins, model layers. |
| `/api/orcarouter/models` | GET | Capability-filtered catalog proxy. |
| `/api/orcarouter/credential` | POST / DELETE | Save or clear a pasted API key. |
| `/api/orcarouter/connect/start` | POST | Begin a PKCE attempt. |
| `/api/orcarouter/connect/complete` | POST | Exchange the displayed code. |
| `/api/orcarouter/connect/cancel` | POST | Release a pending attempt. |
| `/api/orcarouter/preferences` | GET / POST | Read or persist the model selection for one capability. |

Every route authenticates an internal administrator session
(`TRUST_DESK_SESSION_SECRET` + `TRUST_DESK_REVIEWER_ID`) and returns
`Cache-Control: no-store`; `ORCAROUTER_PROVIDER_ADMIN` only decides whether the
surface exists. Mutations require an explicit same-origin `Origin` header, and
PKCE attempts are bound to the administrator that started them, so completion
and cancellation by another principal are refused. The PKCE write is fenced
against the credential generation captured at start: if the credential was
cancelled or replaced while the exchange was in flight, the older approval is
discarded instead of overwriting the newer key. The settings surface never
exposes a key: only `sk-orca-…` status is returned.

## Verification

```sh
npx vitest run tests/orcarouter-provider.test.ts tests/orcarouter-catalog.test.ts \
  tests/orcarouter-credentials.test.ts tests/orcarouter-pkce.test.ts tests/orcarouter-live.test.ts
```

The live test is skipped unless `ORCAROUTER_API_KEY` is present; when present it
exercises the real catalog and one chat completion through the provider code
path, preferring the cyber models.
