<!-- SPDX-License-Identifier: Apache-2.0 -->
# API Key Rotation Runbook

Operator procedure for precautionary / incident rotation of EP API keys, with a
**dual-accept window** so live consumers are never broken. Nothing here mass-revokes
automatically — every revoke step is explicit and operator-approved.

## 1. Why this exists

The migration-113 incident: `api_keys` was briefly readable **and writable** by the
public `anon` role (RLS policy named "service role only" was actually scoped to
PUBLIC with `USING(true)`). This runbook is the controlled response.

## 2. Exposure assessment (do this before deciding scope)

Run the inventory: `npm run keys:inventory` (read-only, prints no `key_hash`).

**Confidentiality of existing keys — LOW.** Keys are `ep_live_` + 32 random bytes
(256 bits), stored as `sha256(key)` (`lib/supabase.js`). What leaked was the
**hash**, not the token. SHA-256 preimage over 256-bit entropy is infeasible, and
`key_prefix` is display-only. **Leaked hashes are not usable to forge keys.**

**Integrity (the real risk) — audit, don't assume.** Because the policy allowed
`anon` `INSERT/UPDATE`, an attacker could in principle have *injected* a forged
key row (own hash → access to any entity) or tampered with rows. The inventory
flags this:
- entities with >1 active key
- keys for non-existent entities (orphans)
- never-used active keys created in the window

As of 2026-06-29: 164 keys (151 active, 13 revoked); **115 active keys never
used** (test/demo/seed artifacts); the only multi-key entities are obviously test
fixtures (`RaceTest_*`/`FinalTest_*`, label "Rotated key"); **0 orphans**. No
evidence of injection — but absence of evidence is not proof, so rotate the real
surface as a precaution and trust signal.

**Verdict:** precautionary rotation, not an emergency burn. Controlled, dual-accept.

## 3. Scope tiers (rotate in this order)

1. **Dormant cleanup (zero blast radius):** the ~115 active-but-never-used keys
   and the test-fixture multi-keys. `last_used_at IS NULL` ⇒ nobody is using it ⇒
   revoke directly (no dual-accept needed). Shrinks attack surface immediately.
2. **Real keys (dual-accept):** the ~36 keys with non-null `last_used_at`. These
   back live integrations — use the dual-accept flow in §4. Prioritize by org and
   by `large_payment_release` / protocol-write authority.

## 4. Dual-accept rotation (per real key)

Keys are bearer secrets — the server only stores the hash and shows plaintext
once. Two delivery models; **prefer self-service** for anything with a reachable owner:

**Model A — self-service (preferred).** Tell the owner to re-mint via the normal
key flow, confirm their new key works, then you revoke the old one (step 4.3 with
their new key id). No secret ever transits you.

**Model B — operator-minted (only when owner can't self-serve).** You generate,
deliver out-of-band over an encrypted channel, never via the page/email/Slack:
```js
// generate exactly as the app does
const key = `ep_live_${require('crypto').randomBytes(32).toString('hex')}`;
const hash = require('crypto').createHash('sha256').update(key).digest('hex');
const prefix = key.slice(0, 16); // confirm against lib/supabase.js prefix length
```

4.1 **Begin (window opens — old + new both valid):**
```sql
select admin_begin_key_rotation('<entity_uuid>', '<new_hash>', '<new_prefix>', 'Rotation 2026-06');
-- returns new_key_id
```
4.2 **Deliver** the new plaintext to the owner. **Monitor:** wait until the new
key's `last_used_at` is non-null (owner cut over). Suggested window: 7–14 days.
4.3 **Complete (window closes — revoke superseded):** only after confirming cutover:
```sql
select admin_complete_key_rotation('<entity_uuid>', '<new_key_id>');
-- revokes every OTHER active key for that entity
```

## 5. Operator checklist (per cohort)

- [ ] `npm run keys:inventory` — capture baseline counts + integrity flags
- [ ] Triage: dormant (revoke direct) vs real (dual-accept)
- [ ] **Approval gate:** get explicit sign-off before any revoke batch
- [ ] Dormant: revoke `last_used_at IS NULL` keys (small batches, re-run inventory after each)
- [ ] Real: `admin_begin_key_rotation` → notify owner → monitor `last_used_at`
- [ ] Real: `admin_complete_key_rotation` only after confirmed cutover
- [ ] `npm run schema:security` — confirm contract still satisfied
- [ ] Post: `npm run keys:inventory` — verify expected active count, 0 orphans

## 6. Rollback

If a consumer breaks mid-window, the old key is still active (dual-accept) until
4.3 — so do **not** run `admin_complete_key_rotation` until cutover is confirmed.
If you completed too early, the owner re-mints (self-service) and you re-run the
flow; revoked keys cannot be un-revoked (issue a fresh key instead).

## 7. Guardrails

- All rotation RPCs are `service_role`-only (asserted by `npm run schema:security`).
- Never deliver a plaintext key over the playground UI, email, or Slack.
- No mass `revoke` of *used* keys without an explicit approved cohort + window.
- Root-cause: rotation does not fix shared-DB tenancy — see the DB-split plan.
