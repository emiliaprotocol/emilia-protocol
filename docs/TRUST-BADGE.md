<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Capability Badge

A small, embeddable shield that asserts **one verifiable capability** for an
entity:

> **EMILIA · authorization receipts: ON — verify →**

It is a **capability badge, not a score.** It carries no number, no ranking, and
no transaction volume. The single fact it states — *"a real, cryptographically
verifiable authorization receipt exists for this entity"* — is something the
viewer can re-derive on their own. The badge is a signpost to evidence, never a
verdict EMILIA asks you to take on faith.

---

## Endpoint

```
GET /api/badge/{entity}            → SVG shield   (default)
GET /api/badge/{entity}?format=json → JSON, same leak-free facts
```

- `{entity}` is the entity id or slug.
- No authentication. Public read.
- Cache-friendly: `Cache-Control: public, max-age=120, s-maxage=300,
  stale-while-revalidate=600`. Safe in shared/CDN caches — nothing private.
- The SVG auto-sizes to its text and carries the verification path inside its
  `<metadata>` and `aria-label`.

### States

| Rendered | Meaning |
|---|---|
| `authorization receipts: ON` (green) | A verifiable EP-RECEIPT-v1 receipt exists for this entity — go pull one and check it. |
| `authorization receipts: —` (muted) | No verifiable receipt found, or the entity is unknown. A neutral marker — **not** a negative score. |

The "ON" state is derived from the **presence** of a receipt (`receiptCount > 0`
or historical establishment), collapsed to a boolean *before* it leaves the
server. The underlying count never crosses the wire **via the badge**.

> Scope of this guarantee: it is about the *badge* surface (and the
> `?view=capability` projection it reads), which are boolean-only. Full
> `GET /api/trust/profile/{entity}` access is authenticated and self-scoped to
> the requested entity. Public callers get only the deliberately minimal
> capability view. No 0–100 reputation score is emitted on any path.

---

## Embed snippets

### Markdown

```markdown
[![EMILIA authorization receipts: ON](https://www.emiliaprotocol.ai/api/badge/YOUR_ENTITY_ID)](https://www.emiliaprotocol.ai/verify)
```

### HTML `<img>`

```html
<a href="https://www.emiliaprotocol.ai/verify">
  <img src="https://www.emiliaprotocol.ai/api/badge/YOUR_ENTITY_ID"
       alt="EMILIA authorization receipts: ON — verify" height="22">
</a>
```

### `<iframe>` (when you want the badge to stay live and self-isolating)

```html
<iframe src="https://www.emiliaprotocol.ai/api/badge/YOUR_ENTITY_ID"
        title="EMILIA authorization receipts capability"
        width="280" height="22" frameborder="0" scrolling="no"
        style="border:0;overflow:hidden"></iframe>
```

> The link target is `/verify` on purpose: that is where a human can drop a real
> receipt and watch the cryptographic checks go green, with no EMILIA server
> trusted. The badge points at the proof, not at a profile page that asks you to
> believe a rating.

### JSON (programmatic / CI)

```bash
curl https://www.emiliaprotocol.ai/api/badge/YOUR_ENTITY_ID?format=json
```

```json
{
  "entity_id": "YOUR_ENTITY_ID",
  "capability": "authorization_receipts",
  "capability_on": true,
  "claim": "A verifiable EP-RECEIPT-v1 authorization receipt exists for this entity.",
  "verify": {
    "capability_source": "https://www.emiliaprotocol.ai/api/trust/profile/YOUR_ENTITY_ID?view=capability",
    "verify_a_receipt": "https://www.emiliaprotocol.ai/verify",
    "verify_receipt_api": "https://www.emiliaprotocol.ai/api/verify/{receiptId}"
  }
}
```

---

## How to re-derive every claim yourself

The badge is only worth embedding because you do **not** have to trust it. Each
element is independently checkable:

1. **Capability presence** — call the leak-free capability projection of the
   canonical read surface: `GET /api/trust/profile/{entity}?view=capability`.
   It returns a boolean `capability_on` only — **no score, no counts, no volume**.
   (The full `GET /api/trust/profile/{entity}` surface requires entity
   authentication; the `?view=capability` projection is the public minimal one.
   No 0–100 `compat_score` is emitted on any path — the legacy score was retired
   from the wire.) If a receipt exists, the capability is `ON`. (Same trust brain
   that powers enforcement and MCP.)
2. **Pull a real receipt and check it** — receipts are verified by their
   cryptographic integrity at `GET /api/verify/{receiptId}` (hash + Merkle
   anchor), and an Ed25519 signature can be checked **entirely in your browser**
   at [`/verify`](https://www.emiliaprotocol.ai/verify) — nothing uploaded, no
   account, no EMILIA server trusted. The same verifier ships on npm
   (`npx @emilia-protocol/verify`) and is auditable on GitHub.
3. **Offline / years from now** — an EP-RECEIPT-v1 packet carries its own issuer
   public key, so the signature math holds long after any server is gone.

If the badge says `ON` and step 2 fails, the badge is wrong — by construction
you can prove it. That is the point.

---

## Design rationale — *capability, not score*

EMILIA's thesis is **"portable evidence, not another score."** The positioning
doctrine (`docs/positioning/EYE_VS_EP.md`) is explicit: EMILIA does **not**
maintain reputation scores, trust indices, or cumulative risk assessments.
This badge is built to honor that, line by line.

**What the badge deliberately does NOT do:**

- ❌ No `0–100`, no grade, no stars, no reputation index, no ranking number.
- ❌ No receipt counts, submitter counts, dollar amounts, or any per-entity
  **transaction volume** — even indirectly. The presence of a receipt is
  collapsed to a boolean *server-side*, so a count can never be reconstructed
  from the rendered output.
- ❌ No EMILIA-vouched opinion ("trusted", "A+", "97% reliable"). Those are
  judgements; we don't issue them.
- ❌ No fabricated outcomes ("SOC2 in 2 days", "insurance discount", customer or
  revenue claims). The badge states a *capability that exists*, not a *result
  achieved*.

**What it does instead:**

- ✅ Asserts a single **capability**: a verifiable authorization receipt exists.
- ✅ Makes that fact **independently re-derivable** by the viewer (profile API →
  real receipt → client-side crypto). The badge is a pointer to proof.
- ✅ Stays **advisory** — consistent with Eye's law, the badge may inform a
  human but is **never** a gate and **never** authorizes an action.
- ✅ Is **cache-friendly and self-contained**: the verification path travels
  inside the SVG `<metadata>`, so even a saved copy tells you how to check it.

**Why a boolean and not "how many receipts":** a count is a volume signal. Two
entities with the same capability should look identical on the badge regardless
of how busy they are — otherwise the badge becomes a soft leaderboard, which is
exactly the "another score" pattern the protocol rejects. Capability is binary:
either the evidence machinery works for you, or it doesn't.

---

## Distinct from "Works with EMILIA"

- **`/badge/works-with-emilia.svg`** — a *static* "we integrated EMILIA" marker.
  Self-declared; means the project gates real actions behind a human signoff.
- **`/api/badge/{entity}`** (this one) — a *live, per-entity capability*
  assertion that resolves against real receipts and is re-derivable by the
  viewer.

Use the static badge to say "we wired this in." Use the capability badge to let
anyone confirm there is actually verifiable evidence behind that claim.
