/**
 * EP Anomaly Detection — Reference Detectors
 *
 * @license Apache-2.0
 *
 * A small set of pure anomaly detectors that operate on windows of EP events.
 * The goal is not to be a SIEM — it is to provide a reference implementation
 * of the detections most directly relevant to EP's threat model, so operators
 * can wire them into any observability pipeline (Datadog, Splunk, Sentry,
 * custom dashboards) without re-inventing the signal layer.
 *
 * Each detector is a pure function: windowed events in, findings out. No I/O.
 * No DB. No network. This keeps them trivially testable and composable.
 *
 * Threat model coverage (from docs/THREAT-MODEL.md):
 *   - T-REPLAY:    binding creation burst from single actor
 *   - T-SIGNOFF:   abandoned signoff ceremonies (auth fatigue / phishing proxies)
 *   - T-POLICY:    policy_hash churn without governance trail
 *   - T-AUTHORITY: rapid authority additions / status churn
 *   - T-DELEGATION: unusual delegation chain depth
 *
 * Consumer pattern:
 *   const findings = detectAll({
 *     binding_events:  [...],
 *     signoff_events:  [...],
 *     policy_events:   [...],
 *     authority_events: [...],
 *   }, { window_start, window_end });
 *
 *   for (const f of findings) {
 *     forwardToSIEM(f);
 *     if (f.severity === 'critical') pageOnCall(f);
 *   }
 *
 * @license Apache-2.0
 */

const DEFAULTS = Object.freeze({
  // Per-actor binding creation ceiling in a 60-second window.
  binding_burst_per_actor: 20,
  // Global binding creation ceiling per minute.
  binding_burst_global: 500,
  // Abandoned signoff TTL: challenges issued but neither consumed nor denied
  // within this many minutes → flagged for operational review.
  signoff_abandoned_minutes: 15,
  // Policy hash churn ceiling: active policies updated in a 24h window.
  policy_churn_daily: 5,
  // Authority status transitions per day.
  authority_churn_daily: 10,
  // Delegation chain depth at which we surface an operational warning.
  delegation_depth_warn: 5,
  delegation_depth_error: 8,
});

/**
 * Run every detector and concatenate findings.
 *
 * @param {object} windows
 * @param {Array} [windows.binding_events]    Events where event_type involves binding create/consume.
 * @param {Array} [windows.signoff_events]    signoff_events rows.
 * @param {Array} [windows.policy_events]     Policy change events.
 * @param {Array} [windows.authority_events]  Authority change events.
 * @param {Array} [windows.delegation_events] Delegation chain events.
 * @param {object} [opts]
 * @param {object} [opts.thresholds] Override DEFAULTS.
 * @returns {Array<Finding>}
 */
export function detectAll(windows = {}, opts = {}) {
  const thresholds = { ...DEFAULTS, ...(opts.thresholds || {}) };
  const findings = [];
  findings.push(...detectBindingBurst(windows.binding_events || [], thresholds));
  findings.push(...detectGlobalBindingBurst(windows.binding_events || [], thresholds));
  findings.push(...detectAbandonedSignoffs(windows.signoff_events || [], thresholds));
  findings.push(...detectPolicyChurn(windows.policy_events || [], thresholds));
  findings.push(...detectAuthorityChurn(windows.authority_events || [], thresholds));
  findings.push(...detectDelegationDepth(windows.delegation_events || [], thresholds));
  return findings;
}

// ── Detector 1: Binding burst per actor ────────────────────────────────────

/**
 * Flag any actor creating more than `binding_burst_per_actor` bindings in a
 * sliding 60-second window. A legitimate actor normally issues bindings at
 * human-interaction speed. A burst usually indicates automation (benign) or
 * credential compromise (not benign).
 */
export function detectBindingBurst(events, thresholds = DEFAULTS) {
  const byActor = new Map(); // actor_entity_ref → sorted timestamps (ms)
  for (const e of events) {
    if (!isBindingCreate(e)) continue;
    const actor = e.actor_entity_ref || e.actor_id || 'unknown';
    const t = toMillis(e.created_at);
    if (t === null) continue;
    if (!byActor.has(actor)) byActor.set(actor, []);
    byActor.get(actor).push(t);
  }

  const findings = [];
  for (const [actor, stamps] of byActor.entries()) {
    stamps.sort((a, b) => a - b);
    const hit = slidingWindowMax(stamps, 60_000);
    if (hit >= thresholds.binding_burst_per_actor) {
      findings.push({
        detector: 'binding_burst_per_actor',
        severity: hit >= thresholds.binding_burst_per_actor * 2 ? 'critical' : 'warning',
        actor_entity_ref: actor,
        peak_count_60s: hit,
        threshold: thresholds.binding_burst_per_actor,
        message: `Actor ${actor} created ${hit} bindings in a 60s window (threshold ${thresholds.binding_burst_per_actor}).`,
      });
    }
  }
  return findings;
}

// ── Detector 2: Global binding burst ───────────────────────────────────────

/**
 * Flag global binding creation bursts across all actors. Catches infrastructure
 * misuse that doesn't concentrate on a single actor (e.g., token leak abused
 * in parallel, automated scraping across many identities).
 */
export function detectGlobalBindingBurst(events, thresholds = DEFAULTS) {
  const stamps = events.filter(isBindingCreate).map(e => toMillis(e.created_at)).filter(t => t !== null).sort((a, b) => a - b);
  const hit = slidingWindowMax(stamps, 60_000);
  if (hit >= thresholds.binding_burst_global) {
    return [{
      detector: 'binding_burst_global',
      severity: 'warning',
      peak_count_60s: hit,
      threshold: thresholds.binding_burst_global,
      message: `Global binding creation spiked to ${hit} in a 60s window (threshold ${thresholds.binding_burst_global}).`,
    }];
  }
  return [];
}

// ── Detector 3: Abandoned signoffs ─────────────────────────────────────────

/**
 * A challenge issued but never resolved within signoff_abandoned_minutes is
 * surfaced. High abandonment rates indicate either UX friction (legitimate
 * concern) or MFA-bombing attempts (security concern). Operators triage both.
 */
export function detectAbandonedSignoffs(events, thresholds = DEFAULTS) {
  // Group by signoff_id. A signoff is abandoned if the challenge_issued event
  // exists but no terminal event (consumed / denied / expired / revoked) does.
  //
  // Audit-fix: filter out events with invalid timestamps BEFORE sorting.
  // Otherwise `toMillis(a) - toMillis(b)` can produce NaN, which makes Array.sort
  // non-deterministic and can cause us to pick the wrong event for `issued` or
  // miss a legitimate `terminal`, producing a false positive alert.
  const bySignoff = new Map();
  for (const e of events) {
    const id = e.signoff_id || e.challenge_id;
    if (!id) continue;
    if (toMillis(e.created_at) === null) continue;
    if (!bySignoff.has(id)) bySignoff.set(id, []);
    bySignoff.get(id).push(e);
  }

  const now = Date.now();
  const ttl = thresholds.signoff_abandoned_minutes * 60_000;
  const findings = [];
  for (const [id, evts] of bySignoff.entries()) {
    evts.sort((a, b) => toMillis(a.created_at) - toMillis(b.created_at));
    const issued = evts.find(e => e.event_type === 'challenge_issued' || e.event_type === 'signoff_issued');
    if (!issued) continue;
    const terminal = evts.find(e => ['consumed', 'denied', 'expired', 'revoked'].includes(e.event_type));
    if (terminal) continue;
    const age = now - toMillis(issued.created_at);
    if (age > ttl) {
      // Severity ladder (increasing with age):
      //   info     — ttl < age <= 4*ttl
      //   warning  — 4*ttl < age <= 16*ttl
      //   critical — age > 16*ttl (genuinely stuck for a very long time)
      let severity = 'info';
      if (age > ttl * 16) severity = 'critical';
      else if (age > ttl * 4) severity = 'warning';
      findings.push({
        detector: 'abandoned_signoff',
        severity,
        signoff_id: id,
        age_minutes: Math.round(age / 60_000),
        issued_at: issued.created_at,
        message: `Signoff ${id} was issued ${Math.round(age / 60_000)}m ago and has not reached a terminal state.`,
      });
    }
  }
  return findings;
}

// ── Detector 4: Policy churn ───────────────────────────────────────────────

/**
 * Flag unusual policy update rates. A compliance-frozen production policy
 * should not change 5 times a day. A legitimate rollout will produce a small
 * number of events; a misuse (bypass-by-edit) often produces many.
 */
export function detectPolicyChurn(events, thresholds = DEFAULTS) {
  const now = Date.now();
  const dayAgo = now - 86_400_000;
  const recent = events.filter(e => {
    const t = toMillis(e.created_at);
    return t !== null && t >= dayAgo;
  });
  // Distinct policy_ids that were updated
  const policies = new Map();
  for (const e of recent) {
    const id = e.policy_id;
    if (!id) continue;
    policies.set(id, (policies.get(id) || 0) + 1);
  }
  const findings = [];
  for (const [id, count] of policies.entries()) {
    if (count >= thresholds.policy_churn_daily) {
      findings.push({
        detector: 'policy_churn',
        severity: 'warning',
        policy_id: id,
        updates_24h: count,
        threshold: thresholds.policy_churn_daily,
        message: `Policy ${id} was updated ${count} times in the last 24 hours (threshold ${thresholds.policy_churn_daily}).`,
      });
    }
  }
  return findings;
}

// ── Detector 5: Authority status churn ─────────────────────────────────────

/**
 * Rapid authority status transitions suggest either a real incident (mass
 * revocation) or credential compromise attempting to rotate trust anchors.
 * Either way, on-call should know within minutes.
 */
export function detectAuthorityChurn(events, thresholds = DEFAULTS) {
  const now = Date.now();
  const dayAgo = now - 86_400_000;
  const count = events.filter(e => {
    const t = toMillis(e.created_at);
    return t !== null && t >= dayAgo;
  }).length;
  if (count >= thresholds.authority_churn_daily) {
    return [{
      detector: 'authority_churn',
      severity: 'critical',
      changes_24h: count,
      threshold: thresholds.authority_churn_daily,
      message: `Authority table had ${count} status changes in the last 24 hours (threshold ${thresholds.authority_churn_daily}).`,
    }];
  }
  return [];
}

// ── Detector 6: Delegation chain depth ─────────────────────────────────────

/**
 * Unusually deep delegation chains are a signal of either legitimate
 * multi-hop authority (rare) or attempted authority laundering (more common).
 */
export function detectDelegationDepth(events, thresholds = DEFAULTS) {
  const findings = [];
  for (const e of events) {
    const depth = Array.isArray(e.delegation_chain) ? e.delegation_chain.length : 0;
    if (depth >= thresholds.delegation_depth_error) {
      findings.push({
        detector: 'delegation_depth',
        severity: 'warning',
        delegation_chain_length: depth,
        threshold: thresholds.delegation_depth_error,
        event_id: e.event_id || null,
        message: `Delegation chain depth ${depth} is at or above error threshold ${thresholds.delegation_depth_error}.`,
      });
    } else if (depth >= thresholds.delegation_depth_warn) {
      findings.push({
        detector: 'delegation_depth',
        severity: 'info',
        delegation_chain_length: depth,
        threshold: thresholds.delegation_depth_warn,
        event_id: e.event_id || null,
        message: `Delegation chain depth ${depth} is at or above warn threshold ${thresholds.delegation_depth_warn}.`,
      });
    }
  }
  return findings;
}

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * True if the event represents a binding CREATION (not a consume).
 * The burst detectors deliberately look at creation rate, not consume rate:
 * a replay attack uses creation bursts to flood the policy ceremony; a consume
 * spike is more often legitimate ceremony completion. Consume bursts are
 * surfaced by separate detectors (future: detectConsumeBurst).
 */
function isBindingCreate(e) {
  const t = e?.event_type || '';
  return t === 'handshake_initiated' || t === 'binding_created' || t === 'handshake_created';
}

function toMillis(ts) {
  if (ts === null || ts === undefined) return null;
  const n = typeof ts === 'number' ? ts : Date.parse(ts);
  return Number.isFinite(n) ? n : null;
}

/**
 * Given a sorted array of timestamps and a window duration, return the maximum
 * count of points contained within any window of that width.
 *
 * O(n) using two pointers.
 */
function slidingWindowMax(sorted, windowMs) {
  let max = 0;
  let left = 0;
  for (let right = 0; right < sorted.length; right++) {
    while (sorted[right] - sorted[left] > windowMs) left++;
    const count = right - left + 1;
    if (count > max) max = count;
  }
  return max;
}

// Export thresholds for tests/configuration
export { DEFAULTS as ANOMALY_THRESHOLDS };
