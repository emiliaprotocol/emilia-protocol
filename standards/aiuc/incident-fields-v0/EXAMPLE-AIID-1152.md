# Worked example: AIID Incident 1152

Record status: public-source coding exercise, not an AIID classification

Reporting cutoff: 2026-08-16

## Incident identity

- Namespace: AI Incident Database (`aiid`)
- Identifier: `1152`
- Canonical record: [Incident 1152](https://incidentdatabase.ai/cite/1152)
- AIID incident date: 2025-07-18
- AIID posture: the record uses "reportedly" and "alleged" language; this
  example preserves that posture.

AIID describes a Replit development assistant reportedly deleting a live
production database during an active code freeze despite repeated instructions
not to make changes. AIID currently lists five reports and classifies the event
under the MIT risk taxonomy as post-deployment, unintentional, and an AI-system
safety/failure issue. Those fields do not state the pre-attempt authorization
relationship.

## Action coding

| Field | Value | Reason |
|---|---|---|
| `action_ref` | `aiid-1152-action-1` | One material action is coded: the database-changing operation that removed live records. |
| `action_class` | `destructive` | The reported operation removed production state. Chen's taxonomy expressly uses non-reversible removal operations such as `DROP TABLE` and `TRUNCATE` as destructive examples. The exact command and runtime boundary are not public, so this class retains the limitation below. |
| `authorization.status` | `revoked` | The public record describes a previously active development workflow followed by an active code/action freeze and repeated instructions not to make changes. Under v0.1, a freeze that withdraws previously available change authority is `revoked`, not merely an absence of approval. |
| `authorization.decision_timing` | `before_attempt` | The freeze and no-change instructions are reported as already active when the database operation occurred. |
| `authorization.evidence_grade` | `E2_independently_correlated` | The affected party published the account and screenshots; Replit's CEO publicly acknowledged that an in-development agent deleted production data and called it unacceptable; AIID independently curated five reports. No public artifact binds the full instruction, exact command, execution identity, timestamps, and state diff, so E3 is not available. |
| `execution.status` | `effect_reversed` | Public reporting says the deletion occurred and rollback ultimately recovered the database. This code does not imply complete remediation or no residual harm. |
| `execution.evidence_grade` | `E2_independently_correlated` | Affected-party reporting, operator acknowledgement of deletion and backups, and independent curation correlate the event and recovery account. No public recovery log proves completeness. |

## Why the field discriminates

`destructive` answers what kind of side effect was attempted. `revoked` answers
what authority was active immediately beforehand. `E2_independently_correlated`
answers how far a reviewer can inspect the support for that coding. None of
those answers implies the others.

Without the proposed field group, two destructive incidents can look identical
even if one was specifically approved and the other followed a freeze. With the
field group, Incident 1152 is coded as a destructive action after revocation,
while preserving that the public evidence is correlated reporting rather than
an independently replayable execution artifact.

## Evidence references

- `S1`: [AIID Incident 1152](https://incidentdatabase.ai/cite/1152), independent
  incident registry and report aggregation.
- `S2`: Jason Lemkin's
  [public incident post](https://x.com/jasonlk/status/1946069562723897802),
  affected-party account with incident screenshots.
- `S3`: Amjad Masad's
  [public operator acknowledgement](https://x.com/amasad/status/1946986468586721478),
  acknowledging deletion of production data and describing immediate response.
- `S4`: Replit,
  [Inside Replit's Snapshot Engine](https://replit.com/blog/inside-replits-snapshot-engine),
  later first-party description of development/production separation,
  restricted agent access, and snapshot rollback. This is context for the
  post-incident architecture, not proof of the exact 2025 action.

## Coding limitations

1. No public typed tool schema, exact SQL, complete instruction artifact,
   execution log, state diff, or timestamp-linked approval record was located.
2. `destructive` follows the reported removal semantics. If a future primary
   artifact shows that the exact operation was semantically reversible inside
   the same Chen-style action boundary, `modify_write` may be the better action
   class. The later rollback is therefore recorded separately and the class is
   reviewable.
3. The public record does not establish the legal or organizational authority
   of every actor, liability, fault, intent, total loss, or complete recovery.
4. The example does not assert that AIID, AIUC-1, Replit, Jason Lemkin, Chen,
   Wei, or Heim accepts this coding.
5. The coding should be revised if primary execution or instruction artifacts
   become public.
