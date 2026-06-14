<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 EMILIA Protocol, Inc. -->

# Eye Real-Time Webhook Notifier

**Status:** Experimental
**Module:** `lib/eye/webhook-notify.js`
**Wire context:** posts on `eye-advisory-v1` issuance
**Companion to:** `docs/EMILIA-EYE-ADVISORY-SPEC.md`, `docs/positioning/EYE_VS_EP.md`

A small, fail-soft notifier that pings an operator's chat channel (Slack,
Discord, or Microsoft Teams) when Eye issues a **non-`clear` advisory** — a
`caution`, `elevated`, or `review_required` posture, optionally including
shadow / observe-mode advisories.

It POSTs a chat-platform-native payload (Slack Block Kit, Discord embed, or
Teams MessageCard) to a single URL configured by environment variable.

---

## The Law (read first)

An Eye advisory **informs**. It can motivate a human to **tighten** posture. It
is **never** a gate and **never** authorizes anything.

- The notification carries **no decision** — no allow/deny, no "approved",
  no "blocked".
- It carries **no trust score, reputation index, 0–100, or ranking**. Eye does
  not score entities. The payload carries only the advisory's own status enum,
  its reason codes, a re-derivable `scope_binding_hash`, and timestamps — facts
  a recipient can independently verify, not an EMILIA-vouched opinion.
- Every payload includes a one-line disclaimer stating it is informational only
  and does not block or authorize the action; the Enforcement Point (Guard) and
  signoff decide.

This is enforced by the spec: see *"Eye Does Not"* in
`docs/positioning/EYE_VS_EP.md` ("Block actions", "Score entities", "Notify
target entities"). The webhook URL is the **operator's own** channel — Eye never
notifies a target entity that it was flagged.

---

## What this is vs. the signed webhook system

This is **not** the per-tenant signed delivery system in
`lib/cloud/webhooks.js`. That system delivers EP-style signed events to
subscriber endpoints with HMAC signatures, retries, and auto-disable.

This notifier is a deliberately simpler, fire-and-forget **operator ping** to a
chat tool's incoming webhook. No subscriber registration, no DB, no retry queue:
its single job is to put a human in the loop fast, and to get out of the way if
it can't.

If you need signed, retried, per-tenant delivery to programmatic consumers, use
`lib/cloud/webhooks.js` with an `eye.advisory_issued` event type instead.

---

## Configuration

All configuration is via environment variables. If `EYE_WEBHOOK_URL` is unset,
the notifier is a silent no-op.

| Variable | Default | Meaning |
|---|---|---|
| `EYE_WEBHOOK_URL` | _(unset → no-op)_ | Incoming-webhook URL for Slack / Discord / Teams. |
| `EYE_WEBHOOK_KIND` | inferred from URL host, else `slack` | `slack` \| `discord` \| `teams`. |
| `EYE_WEBHOOK_MIN_STATUS` | `caution` | Lowest status that fires: `caution` \| `elevated` \| `review_required`. `clear` never fires. |
| `EYE_WEBHOOK_SHADOW` | `false` | `true` to also notify on shadow / observe-mode advisories. |
| `EYE_WEBHOOK_REVEAL_REFS` | `false` | `true` to include short **hashed** ref tokens. Raw identifiers are never sent. |
| `EYE_WEBHOOK_TIMEOUT_MS` | `8000` | Delivery timeout in milliseconds. |

> **Note on env access.** This module reads `process.env` directly, mirroring the
> idiom of `lib/trust-desk/notify.js`. The project convention is to centralize
> env access in `lib/env.js`; these keys can be moved behind an
> `getEyeWebhookConfig()` accessor later with no callsite changes.

### Getting an incoming-webhook URL

- **Slack:** Create an app → *Incoming Webhooks* → *Add New Webhook to
  Workspace*. URL looks like `hooks.slack.com/services/T…/B…/…`.
- **Discord:** Channel → *Edit Channel* → *Integrations* → *Webhooks* → *New
  Webhook* → *Copy Webhook URL*. URL contains `discord.com/api/webhooks/…`.
- **Teams:** Channel → *Workflows* (or classic *Incoming Webhook* connector) →
  copy the generated URL (`…webhook.office.com…`).

The platform is auto-detected from the URL host when `EYE_WEBHOOK_KIND` is unset.

---

## Privacy & redaction (default on)

By default the payload contains **only** non-attributable, re-derivable facts:

**Sent:**
- `advisory_id`, `status`, `reason_codes`, `recommended_policy_action`
- `scope_binding_hash`, `advisory_hash` (deterministic SHA-256 — leak nothing on
  their own; a party who knows the scope can re-derive the binding hash)
- `evidence_count` (a count, **not** the evidence refs or contents)
- `issued_at`, `expires_at`, `version`
- `action_type` (a workflow label, e.g. `vendor_bank_account_change`)

**Never sent (redacted by default):**
- Raw `subject_ref`, `actor_ref`, `target_ref`, `issuer_ref`
- Raw context, evidence contents, evidence refs
- Per-entity transaction volumes or amounts, or any sensitive action parameters

With `EYE_WEBHOOK_REVEAL_REFS=true`, the payload may include a short prefix of a
ref **only when that ref already looks like a hash**; human-readable identifiers
are still dropped entirely. There is no mode that emits raw identifiers.

---

## Fail-soft guarantee

`notifyEyeAdvisory()` **never throws**. Network errors, timeouts, non-2xx
responses, invalid/private URLs, and internal bugs are all caught, logged at
`warn`, and turned into a structured return value:

```js
{ notified: false, skipped: 'no_url' }            // not configured
{ notified: false, skipped: 'below_threshold' }   // status below EYE_WEBHOOK_MIN_STATUS
{ notified: false, skipped: 'invalid_url' }        // bad / private-host URL
{ notified: false, kind: 'slack', detail: 'timeout' }
{ notified: true,  kind: 'slack', status: 200 }
```

A webhook failure **must not** break the advisory path. The caller should treat
this as fire-and-forget (do not `await`-block advisory issuance on it).

It also applies **SSRF protection**: private / reserved / internal hosts are
refused even though the URL is operator-configured.

---

## Wiring (caller responsibility)

This module is **not** wired into the advisory-emit path automatically, because
the canonical emit point (`protocolWrite()` / the `EYE_ISSUE_ADVISORY` handler in
`lib/protocol-write.js`) is a shared pipeline file owned by the integrator.

Add the following **single line** at the point where a fully-formed advisory
object is available immediately after issuance (the `EYE_ISSUE_ADVISORY` handler,
or wherever your Eye evaluator returns the advisory). It is fire-and-forget:

```js
import { notifyEyeAdvisory } from '@/lib/eye/webhook-notify.js';

// after the advisory is persisted/returned (advisory is eye-advisory-v1 shape):
notifyEyeAdvisory(advisory, { isShadow: enforcementMode === 'observe' });
```

Because the call is fail-soft and fire-and-forget, you do **not** need to
`await` it or wrap it in `try/catch`. Pass `{ isShadow: true }` for
observe/shadow-mode advisories so the `EYE_WEBHOOK_SHADOW` gate applies and the
payload is labeled accordingly.

---

## Public API

| Export | Purpose |
|---|---|
| `notifyEyeAdvisory(advisory, meta?)` | Main entrypoint. Fail-soft; returns a result object. |
| `buildWebhookPayload(view, kind, isShadow?)` | Build a platform payload from a **redacted** advisory view (for custom transports / tests). |
| `__test__` | Internal helpers exposed for unit tests only. |

---

## Example payloads

**Slack** (Block Kit + color rail):

```json
{
  "text": ":warning: Eye advisory: *Elevated* on `vendor_bank_account_change`",
  "attachments": [{
    "color": "#e8731a",
    "blocks": [
      { "type": "section", "text": { "type": "mrkdwn", "text": "…reason codes, posture, scope binding…" } },
      { "type": "context", "elements": [{ "type": "mrkdwn", "text": "Eye advisory — informational only. This does not block or authorize the action; the Enforcement Point and signoff decide. Not a trust score." }] }
    ]
  }]
}
```

**Discord** uses `embeds[].fields` with `footer.text` carrying the disclaimer.
**Teams** uses a `MessageCard` with `sections[].facts` and the disclaimer in
`sections[].text`.
