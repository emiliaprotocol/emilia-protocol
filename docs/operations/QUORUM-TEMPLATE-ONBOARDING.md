<!-- SPDX-License-Identifier: Apache-2.0 -->
# Activating the org quorum-strength floor (per-tenant onboarding)

The org-pinned quorum floor (`org_quorum_policies`, migration `124`) closes the
creator-declared quorum-strength gap: a receipt's `quorum_policy` is only honored
when it **meets or exceeds** the org's template for its `(organization_id,
action_type)` — enforced at create **and** re-checked at consume by
`lib/guard-quorum-template.js`. A creator may make a quorum *stronger* than the
floor, never weaker.

## Why this is a manual, per-org step (not seeded automatically)

**The table is intentionally empty in production.** An empty table is
behaviourally identical to the prior state — no template means no floor for that
`(org, action_type)`, and enforcement activates the instant a row is inserted.

We do **not** blanket-seed, and there is deliberately no auto-run seed file, for
one concrete reason: a template row encodes a *specific* org's governance policy
(`min_required`, roster, window, `quorum_required`). Get it wrong and you either
**under-enforce** — a floor that looks like a control but isn't — or **brick the
org's legitimate creates** because their real approvers can't clear a floor that
doesn't match their actual approval structure. That value must come from each
org's confirmed policy, and inserting it changes their live enforcement. So it is
an explicit onboarding action, run once per org with signed-off values.

## Activate for one org

Run against the EP production database (service-role; RLS is service-role-only).
Fill in the org's **confirmed** policy — do not guess.

```sql
INSERT INTO org_quorum_policies
  (organization_id, action_type, min_required, max_window_sec,
   require_distinct_humans, quorum_required, allowed_approvers, allowed_modes)
VALUES
  ('<organization_id>', '<action_type>',
   2,            -- min_required: threshold floor M (receipt threshold must be >=). NULL = no floor.
   900,          -- max_window_sec: approval-window ceiling (receipt window must be <=). NULL = no ceiling.
   TRUE,         -- require_distinct_humans: separation-of-duties floor (a receipt cannot disable it).
   TRUE,         -- quorum_required: a receipt for this action_type MUST carry a quorum_policy.
   NULL,         -- allowed_approvers: [{"role":"...","approver":"..."}] roster; submitted approvers must be a subset. NULL = unrestricted.
   NULL)         -- allowed_modes: e.g. ["ordered"]. NULL = any mode.
ON CONFLICT (organization_id, action_type) DO UPDATE
  SET min_required            = EXCLUDED.min_required,
      max_window_sec          = EXCLUDED.max_window_sec,
      require_distinct_humans = EXCLUDED.require_distinct_humans,
      quorum_required         = EXCLUDED.quorum_required,
      allowed_approvers       = EXCLUDED.allowed_approvers,
      allowed_modes           = EXCLUDED.allowed_modes,
      updated_at              = now();
```

### Worked example — a caseworker override that requires a two-person rule

```sql
INSERT INTO org_quorum_policies
  (organization_id, action_type, min_required, require_distinct_humans, quorum_required)
VALUES
  ('<caseworker_org_id>', 'caseworker_override', 2, TRUE, TRUE)
ON CONFLICT (organization_id, action_type) DO UPDATE
  SET min_required = 2, require_distinct_humans = TRUE, quorum_required = TRUE, updated_at = now();
```

After this row exists, any `caseworker_override` receipt for that org that
declares fewer than two distinct human approvers (or omits a `quorum_policy`) is
refused at create with **422** and re-checked at consume.

## Verify activation

```sql
SELECT organization_id, action_type, min_required, quorum_required
FROM org_quorum_policies WHERE organization_id = '<organization_id>';
```

Then exercise the create path with a below-floor `quorum_policy` and confirm a
422, and an at-or-above-floor policy and confirm success. The invariant is
covered in `tests/quorum-org-template.test.js`.

## Rollback

Enforcement for an action reverts to "no floor" the moment its row is removed:

```sql
DELETE FROM org_quorum_policies
WHERE organization_id = '<organization_id>' AND action_type = '<action_type>';
```
