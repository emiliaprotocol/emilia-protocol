/**
 * EP Anomaly Detectors — unit tests.
 *
 * Each detector has a negative case (quiet traffic → no findings) and at
 * least one positive case (pattern that MUST fire).
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  detectBindingBurst,
  detectGlobalBindingBurst,
  detectAbandonedSignoffs,
  detectPolicyChurn,
  detectAuthorityChurn,
  detectDelegationDepth,
  detectAll,
  ANOMALY_THRESHOLDS,
} from '@/lib/anomaly';

const now = Date.now();
const ago = (ms) => new Date(now - ms).toISOString();

// ── detectBindingBurst ─────────────────────────────────────────────────────

describe('anomaly/detectBindingBurst', () => {
  it('does not flag normal traffic', () => {
    const events = Array.from({ length: 5 }, (_, i) => ({
      event_type: 'handshake_initiated',
      actor_entity_ref: 'actor-normal',
      created_at: ago(i * 30_000),
    }));
    expect(detectBindingBurst(events)).toEqual([]);
  });

  it('flags bursts from a single actor', () => {
    // 25 bindings in 30 seconds from one actor
    const events = Array.from({ length: 25 }, (_, i) => ({
      event_type: 'handshake_initiated',
      actor_entity_ref: 'actor-bursty',
      created_at: ago(i * 1000),
    }));
    const findings = detectBindingBurst(events);
    expect(findings).toHaveLength(1);
    expect(findings[0].actor_entity_ref).toBe('actor-bursty');
    expect(findings[0].peak_count_60s).toBeGreaterThanOrEqual(25);
  });

  it('escalates severity when burst is 2x threshold', () => {
    const events = Array.from({ length: 45 }, (_, i) => ({
      event_type: 'handshake_initiated',
      actor_entity_ref: 'actor-very-bursty',
      created_at: ago(i * 500),
    }));
    const findings = detectBindingBurst(events);
    expect(findings[0].severity).toBe('critical');
  });
});

// ── detectGlobalBindingBurst ───────────────────────────────────────────────

describe('anomaly/detectGlobalBindingBurst', () => {
  it('does not flag traffic under the global threshold', () => {
    const events = Array.from({ length: 100 }, (_, i) => ({
      event_type: 'handshake_initiated',
      actor_entity_ref: `actor-${i}`,
      created_at: ago(i * 600),
    }));
    expect(detectGlobalBindingBurst(events)).toEqual([]);
  });

  it('flags a global spike', () => {
    const events = Array.from({ length: 600 }, (_, i) => ({
      event_type: 'handshake_initiated',
      actor_entity_ref: `actor-${i}`,
      created_at: ago(i * 50),
    }));
    const findings = detectGlobalBindingBurst(events);
    expect(findings.length).toBe(1);
    expect(findings[0].detector).toBe('binding_burst_global');
  });
});

// ── detectAbandonedSignoffs ────────────────────────────────────────────────

describe('anomaly/detectAbandonedSignoffs', () => {
  it('does not flag a consumed signoff', () => {
    const events = [
      { signoff_id: 's1', event_type: 'challenge_issued', created_at: ago(30 * 60_000) },
      { signoff_id: 's1', event_type: 'consumed', created_at: ago(25 * 60_000) },
    ];
    expect(detectAbandonedSignoffs(events)).toEqual([]);
  });

  it('flags an abandoned signoff at info severity just past TTL', () => {
    // ttl = 15m; this is 30m old → info (age > ttl, but <= 4*ttl)
    const events = [
      { signoff_id: 's-abandoned', event_type: 'challenge_issued', created_at: ago(30 * 60_000) },
    ];
    const findings = detectAbandonedSignoffs(events);
    expect(findings).toHaveLength(1);
    expect(findings[0].signoff_id).toBe('s-abandoned');
    expect(findings[0].severity).toBe('info');
    expect(findings[0].age_minutes).toBeGreaterThanOrEqual(ANOMALY_THRESHOLDS.signoff_abandoned_minutes);
  });

  it('escalates to warning at 4x+ TTL', () => {
    // ttl = 15m; 70m old → warning (age > 4*ttl = 60)
    const events = [
      { signoff_id: 's-old', event_type: 'challenge_issued', created_at: ago(70 * 60_000) },
    ];
    const findings = detectAbandonedSignoffs(events);
    expect(findings[0].severity).toBe('warning');
  });

  it('escalates to critical at 16x+ TTL', () => {
    // ttl = 15m; 250m old → critical (age > 16*ttl = 240)
    const events = [
      { signoff_id: 's-ancient', event_type: 'challenge_issued', created_at: ago(250 * 60_000) },
    ];
    const findings = detectAbandonedSignoffs(events);
    expect(findings[0].severity).toBe('critical');
  });

  it('does not crash on events with invalid timestamps', () => {
    // Audit regression test — NaN in sort comparator caused non-deterministic ordering.
    const events = [
      { signoff_id: 's-bad', event_type: 'challenge_issued', created_at: 'not-a-date' },
      { signoff_id: 's-bad', event_type: 'consumed', created_at: ago(10_000) },
      { signoff_id: 's-good', event_type: 'challenge_issued', created_at: ago(30 * 60_000) },
    ];
    // Should not throw; bad-timestamp events are filtered out before sorting.
    const findings = detectAbandonedSignoffs(events);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('does not flag young, still-outstanding signoffs', () => {
    const events = [
      { signoff_id: 's-fresh', event_type: 'challenge_issued', created_at: ago(60_000) },
    ];
    expect(detectAbandonedSignoffs(events)).toEqual([]);
  });
});

// ── detectPolicyChurn ──────────────────────────────────────────────────────

describe('anomaly/detectPolicyChurn', () => {
  it('does not flag a single policy update', () => {
    const events = [{ policy_id: 'p1', event_type: 'policy_updated', created_at: ago(60_000) }];
    expect(detectPolicyChurn(events)).toEqual([]);
  });

  it('flags a policy updated many times in a day', () => {
    const events = Array.from({ length: 6 }, (_, i) => ({
      policy_id: 'p-churn',
      event_type: 'policy_updated',
      created_at: ago(i * 3_600_000),
    }));
    const findings = detectPolicyChurn(events);
    expect(findings).toHaveLength(1);
    expect(findings[0].policy_id).toBe('p-churn');
  });
});

// ── detectAuthorityChurn ───────────────────────────────────────────────────

describe('anomaly/detectAuthorityChurn', () => {
  it('does not flag light authority changes', () => {
    const events = [
      { event_type: 'authority_added', created_at: ago(60_000) },
      { event_type: 'authority_revoked', created_at: ago(120_000) },
    ];
    expect(detectAuthorityChurn(events)).toEqual([]);
  });

  it('flags mass authority churn', () => {
    const events = Array.from({ length: 12 }, (_, i) => ({
      event_type: 'authority_revoked',
      created_at: ago(i * 3_600_000),
    }));
    const findings = detectAuthorityChurn(events);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });
});

// ── detectDelegationDepth ──────────────────────────────────────────────────

describe('anomaly/detectDelegationDepth', () => {
  it('does not flag normal delegation', () => {
    const events = [
      { event_id: 'e1', delegation_chain: ['a', 'b'] },
    ];
    expect(detectDelegationDepth(events)).toEqual([]);
  });

  it('warns on moderately deep delegation', () => {
    const events = [{ event_id: 'e2', delegation_chain: Array.from({ length: 5 }, (_, i) => `a${i}`) }];
    const findings = detectDelegationDepth(events);
    expect(findings[0].severity).toBe('info');
  });

  it('warns on very deep delegation', () => {
    const events = [{ event_id: 'e3', delegation_chain: Array.from({ length: 9 }, (_, i) => `a${i}`) }];
    const findings = detectDelegationDepth(events);
    expect(findings[0].severity).toBe('warning');
  });
});

// ── detectAll ──────────────────────────────────────────────────────────────

describe('anomaly/detectAll', () => {
  it('combines findings across detectors', () => {
    const windows = {
      binding_events: Array.from({ length: 25 }, (_, i) => ({
        event_type: 'handshake_initiated',
        actor_entity_ref: 'actor-bursty',
        created_at: ago(i * 1000),
      })),
      signoff_events: [
        { signoff_id: 's-abandoned', event_type: 'challenge_issued', created_at: ago(30 * 60_000) },
      ],
      policy_events: [],
      authority_events: [],
      delegation_events: [],
    };
    const findings = detectAll(windows);
    const detectors = new Set(findings.map(f => f.detector));
    expect(detectors.has('binding_burst_per_actor')).toBe(true);
    expect(detectors.has('abandoned_signoff')).toBe(true);
  });

  it('returns empty list on clean traffic', () => {
    const findings = detectAll({
      binding_events: [{ event_type: 'handshake_initiated', actor_entity_ref: 'a', created_at: ago(60_000) }],
      signoff_events: [],
      policy_events: [],
      authority_events: [],
      delegation_events: [],
    });
    expect(findings).toEqual([]);
  });

  it('is configurable via thresholds', () => {
    const windows = {
      binding_events: Array.from({ length: 8 }, (_, i) => ({
        event_type: 'handshake_initiated',
        actor_entity_ref: 'actor-sensitive',
        created_at: ago(i * 1000),
      })),
    };
    const noFindings = detectAll(windows);
    expect(noFindings).toEqual([]);
    const findings = detectAll(windows, { thresholds: { binding_burst_per_actor: 5 } });
    expect(findings.length).toBeGreaterThan(0);
  });
});
