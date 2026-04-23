# EP Accountable Signoff — UX Metrics Framework

**Status:** v1 (Apr 2026).
**Scope:** What to measure in production signoff flows to know whether the human side is working. The protocol is cryptographically correct; the UX is where failure will actually come from.

---

## 1. Why this matters

Every measured rollout of human-in-the-loop controls (MFA, manager-approval workflows, step-up auth, transaction verification) has shown the same pattern: the control is adopted, the UX is friction, humans route around it, and the control becomes theater. EP Accountable Signoff has all the preconditions for that failure mode:

- 7-step ceremony (challenge → view → verify → authenticate → attest → consume → audit).
- Authenticated humans doing high-frequency attestations during their workday.
- Natural incentives to "just approve it" rather than read carefully.
- Organizational penalties for being the person whose signoff blocked the business.

The cryptography will not save you if 94% of signers are holding the enter key to batch-approve. This document defines what to measure so that you can detect that drift before it becomes structural.

---

## 2. The core metrics

### 2.1. Completion rate

**Definition**: (challenges resulting in consumed attestation) / (challenges issued).

**Target**: 80-95% for a mature workflow. Below 80% indicates systemic friction; above 95% may indicate rubber-stamping.

**Watch for**:
- Sudden drops (outage? confusing UI change?)
- Sudden spikes toward 100% (disengaged reviewers? automated approvals at the UX layer bypassing intended review?)

### 2.2. Time-to-sign (TTS)

**Definition**: timestamp(consumed) − timestamp(challenge_issued), per signoff.

**Targets** (illustrative, should be set per action class):
- Low-risk action: p50 30s, p90 2min.
- High-risk action: p50 2min, p90 15min.
- Critical action: p50 5min, p90 30min.

**Watch for**:
- **Too fast**: p50 TTS < 10s on high/critical actions indicates the reviewer did not read the action context. This is the most common failure mode. It's the one that most operators don't measure.
- **Too slow**: p90 TTS > 1 hour indicates the signer is not in the loop at the time the action needs them. This causes business pressure to lower the gate.
- **Distribution tails**: a bimodal distribution (many fast, few slow, nothing in the middle) is a reliable signal of rubber-stamping with occasional honest review. Measure the entire distribution, not just averages.

### 2.3. Abandonment

**Definition**: challenges issued, viewed, but not resolved within TTL.

**Target**: < 5% for routine workflows. Higher for truly rare-path signoffs is acceptable.

**Watch for**:
- Abandonment skewed to particular signers (training gap, role mismatch).
- Abandonment skewed to particular action types (poor UX for that action, or policy wrongly requiring signoff on an over-frequent action).
- Abandonment during specific time windows (after-hours signoffs going unanswered — consider delegation rules).

### 2.4. Denial rate

**Definition**: (explicit denials) / (consumed + denied).

**Target**: non-zero. A signoff flow with 0% denial rate across thousands of attestations is probably theater.

**Watch for**:
- Zero denials. Investigate. Either every action is legitimate (possible but unlikely at scale), or signers have not internalized that denial is an option, or the UX hides the deny button.
- Denials concentrated in specific hours / from specific signers — useful to understand who is actually reviewing.

### 2.5. Re-authentication success rate

**Definition**: (challenges where the reauth step succeeds on first attempt) / (challenges where reauth is required).

**Target**: 90%+. Below this indicates either credential issues (password fatigue, lost device) or targeted attempts at bypass.

**Watch for**:
- Drops at specific hours (possible credential stuffing).
- Concentration per signer (lost device? replace hardware).
- Gradual decline over weeks (likely password entropy drift — move to passkeys).

---

## 3. Secondary metrics

These don't need real-time alerting but should be reviewed weekly.

- **Delegation chain length**: average chain depth over the review window. Creep toward longer chains indicates decision-making moving further from accountable humans.
- **Action-class distribution**: what fraction of signoffs are `critical` vs `high` vs `medium`? Creep toward lower-risk classifications is a structural bypass indicator.
- **Policy version churn**: how often does the signoff policy change? High churn + low review latency indicates governance evolution under pressure (bad).
- **Signer workload**: signoffs per active signer per day. Above ~40/day is where research suggests attention breaks down; above ~100/day is auto-pilot territory.
- **Channel distribution**: what fraction of signoffs come from device X vs device Y? A sudden shift in channel distribution is either a rollout event (planned) or compromise (unplanned).

---

## 4. Alert-worthy anomalies

The `lib/anomaly/` module provides reference detectors for the protocol-level anomalies. These are the human-behavior anomalies that should also page:

| Pattern | Severity | Why it matters |
|---|---|---|
| Single signer's TTS p50 drops > 50% week-over-week | warning | They've started rubber-stamping. |
| Any signer produces > 10 attestations in 60 seconds | critical | Batch approval; no human review possible. |
| Denial rate for a particular action class drops to 0% over 2 weeks | warning | Review became theater. |
| Signer authenticates from a new country | warning | Either travel (fine, notify) or compromise (not fine). |
| Challenge viewed but not resolved within 2x TTL median | info | Backing up; signer may be offline. |
| Challenge resolved in < 2s post-view | warning | Too fast to be reading. |

---

## 5. Measurement infrastructure

The protocol already emits the necessary events. You need to aggregate them.

**Required events** (already emitted by EP):
- `challenge_issued`: entry into the ceremony.
- `challenge_viewed`: signer's UI loaded the challenge (record client-side; round-trip confirm).
- `attestation_submitted`: signer pressed sign.
- `consumed`: attestation used by the downstream action.
- `denied`, `expired`, `revoked`: terminal states.

**Required dimensions** per event:
- signer_id (for per-signer analysis)
- action_class (low/medium/high/critical)
- policy_id + policy_version (for policy version analysis)
- channel (device / method)

**Aggregation**:
- Weekly rollups at minimum; daily for mature deployments.
- Per-signer, per-action-class, per-policy breakdowns.
- Anomaly detectors run on the raw stream; aggregate metrics feed dashboards.

---

## 6. Reference dashboard layout

A one-page operator dashboard should show, at minimum:

```
┌─────────────────────────────────────────────────────────────────┐
│ SIGNOFF HEALTH — LAST 7 DAYS                                    │
├─────────────────────────────────────────────────────────────────┤
│ Completion:     93.2%  ▲ 1.1 pp       (target 80-95)            │
│ TTS p50 high:   2m 14s ▼ 8s           (target < 5m)             │
│ TTS p50 crit:   4m 42s ─              (target < 15m)            │
│ Abandonment:    3.8%   ▲ 0.6 pp       (target < 5%)             │
│ Denial rate:    2.1%   ─              (target > 0)              │
│                                                                 │
│ Open alerts:    2                                               │
│  - [WARN] signer_6 TTS p50 dropped 58% w/w                      │
│  - [INFO] 4 abandoned critical signoffs in last 24h             │
│                                                                 │
│ TOP SIGNERS BY VOLUME (last 7d)                                 │
│  signer_3:  84 signoffs, TTS p50 1m22s, denials 4              │
│  signer_12: 61 signoffs, TTS p50 2m09s, denials 2              │
│  signer_7:  43 signoffs, TTS p50 8s (!)   denials 0  ⚠          │
│                                                                 │
│ [View raw events]  [Policy versions in flight: 3]               │
└─────────────────────────────────────────────────────────────────┘
```

Everything in that layout maps to events the protocol already produces. Build the dashboard using whatever tooling you have — Datadog, Grafana, Superset, a custom Next.js page with tRPC. The measurement is the point; the pretty chart is not.

---

## 7. What to do when a signer has gone rubber-stamp

Some version of this happens on every mature deployment. Detection is §4. Response:

1. **Don't name-and-shame.** The signer is responding rationally to unreasonable volume or unclear UX. Fix the input, not the human.
2. **Route less.** If signer_7 is getting 84/week, look at whether their action class is actually rare enough to warrant individual review. Maybe a subset should be policy-auto-approved.
3. **Re-train on high-stakes.** Introduce randomized "integrity check" signoffs — synthetic attestations that should be denied, inserted into the real flow, to maintain review discipline. (Ethics note: disclose these in advance; don't trick your signers.)
4. **Rotate signers.** Review fatigue is real. Longer rotations with smaller steady-state loads outperform short rotations with high loads.

If §1-4 don't work, the workflow probably shouldn't be human-gated. Either eliminate it (policy auto-approve with audit) or split the class so only genuinely rare cases touch a human.

---

## 8. Integration checklist for a new operator

Before going live with signoff on a new action class:

- [ ] TTS targets set per §2.2 and documented.
- [ ] Dashboard deployed with the §6 fields populated from event stream.
- [ ] Per-signer anomaly alerts configured per §4.
- [ ] Signer training on what the action context means; review of the UI by a subject matter expert.
- [ ] Deny-button prominence confirmed: a deliberate, non-dangerous path exists to deny an action without penalty to the signer.
- [ ] Backup signer assigned for each primary signer (covers abandonment scenarios).
- [ ] Escalation path defined: what happens when N critical signoffs abandon in a row.

If any of these are empty, the action class is not ready for production signoff.
