// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
  buildSubmissionGraph,
  detectBilateralPairs,
  detectRings,
  detectConcentration,
  detectTimingAnomalies,
  scanCollusion,
} from '../lib/collusion-monitor.js';

const r = (submitted_by, entity_id, created_at = '2026-06-01T00:00:00Z') => ({
  submitted_by,
  entity_id,
  created_at,
});

describe('collusion-monitor', () => {
  it('detects a 5-entity submission ring (A->B->C->D->E->A)', () => {
    const receipts = [r('A', 'B'), r('B', 'C'), r('C', 'D'), r('D', 'E'), r('E', 'A')];
    const rings = detectRings(buildSubmissionGraph(receipts));
    expect(rings).toHaveLength(1);
    expect(rings[0].type).toBe('submission_ring');
    expect(rings[0].severity).toBe('high');
    expect(rings[0].detail.length).toBe(5);
    expect([...rings[0].members].sort()).toEqual(['A', 'B', 'C', 'D', 'E']);
  });

  it('detects a bilateral pair A<->B', () => {
    const pairs = detectBilateralPairs(buildSubmissionGraph([r('A', 'B'), r('B', 'A')]));
    expect(pairs).toHaveLength(1);
    expect(pairs[0].members).toEqual(['A', 'B']);
  });

  it('flags submitter concentration (one submitter dominates a target)', () => {
    const receipts = [
      r('X', 'T'), r('X', 'T'), r('X', 'T'), r('X', 'T'), r('X', 'T'), r('Y', 'T'),
    ];
    const found = detectConcentration(receipts);
    expect(found).toHaveLength(1);
    expect(found[0].members).toEqual(['T']);
    expect(found[0].severity).toBe('high');
    expect(found[0].detail.top_submitter_share).toBeGreaterThanOrEqual(0.6);
  });

  it('flags a machine-cadence timing burst', () => {
    const base = Date.parse('2026-06-01T00:00:00Z');
    const receipts = Array.from({ length: 5 }, (_, i) =>
      r('S', `t${i}`, new Date(base + i * 5_000).toISOString()), // 5 within 20s
    );
    const found = detectTimingAnomalies(receipts);
    expect(found).toHaveLength(1);
    expect(found[0].members).toEqual(['S']);
    expect(found[0].detail.max_in_window).toBe(5);
  });

  it('ignores an organic graph (diverse, acyclic, spread out)', () => {
    const receipts = [
      r('A', 'B', '2026-06-01T00:00:00Z'),
      r('C', 'D', '2026-06-02T00:00:00Z'),
      r('E', 'F', '2026-06-03T00:00:00Z'),
    ];
    expect(scanCollusion(receipts)).toEqual([]);
  });

  it('self-vouch edges are ignored (handled elsewhere)', () => {
    const graph = buildSubmissionGraph([r('A', 'A'), r('A', 'B'), r('B', 'A')]);
    expect(detectRings(graph)).toHaveLength(1); // only the real A<->B 2-cycle
  });
});
