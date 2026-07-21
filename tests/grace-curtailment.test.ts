// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FLEX_ENVELOPE_VERSION, CURTAILMENT_SETTLEMENT_POLICY, SETTLEMENT_CONSUMPTION_PROFILE,
  checkOrderWithinEnvelope, computeCompliance, buildRefusalStatement,
  settlementEntitlementKey, checkSettlementConsumption, runSettlementOnce,
} from '../lib/grace/curtailment.js';
import {
  verifyConsumptionProof, ReferenceConsumptionTree,
} from '../packages/verify/consumption-proof.js';
import { buildConsistencyProof, merkleRoot } from '../packages/verify/consistency.js';
import crypto from 'node:crypto';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Dimensioned bounds: power caps power, energy budgets energy, counts budget
// counts, hours budget hours. Per-event MW are never summed against an
// instantaneous ceiling.
const envelope = {
  '@version': FLEX_ENVELOPE_VERSION,
  bounds: {
    max_event_mw: 15,      // per-event instantaneous cap (MW)
    max_period_mwh: 120,   // cumulative energy budget (MWh)
    max_events: 10,        // event-count budget
    max_event_hours: 40,   // cumulative event-hours budget
    min_notice_minutes: 10,
    window: { start: '2026-06-01T00:00:00Z', end: '2026-09-30T23:59:59Z' },
  },
};
// 12 MW × 4 h = 48 MWh projected.
const order = {
  mw: '12.0', notice_minutes: 30,
  window: { start: '2026-07-15T15:00:00Z', end: '2026-07-15T19:00:00Z' },
};

describe('GRACE — Order ⊆ Envelope (fail-closed, dimensioned pre-execution check)', () => {
  it('an in-bounds order passes (12 ≤ 15 MW, 48 ≤ 120 MWh, 1 ≤ 10 events, 4 ≤ 40 h)', () => {
    expect(checkOrderWithinEnvelope(order, envelope).within).toBe(true);
  });

  it.each([
    ['MW over the per-event cap', { ...order, mw: '22.0' }, 'exceeds envelope per-event cap'],
    ['short notice', { ...order, notice_minutes: 3 }, 'below envelope floor'],
    ['outside participation window', { ...order, window: { start: '2026-11-01T15:00:00Z', end: '2026-11-01T19:00:00Z' } }, 'outside envelope participation window'],
    ['invalid window', { ...order, window: { start: '2026-07-15T19:00:00Z', end: '2026-07-15T15:00:00Z' } }, 'invalid window'],
  ])('%s is refused with a named violation', (_name, badOrder, expected) => {
    const r = checkOrderWithinEnvelope(badOrder, envelope);
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain(expected);
  });

  it('an unknown envelope version is itself a violation (fail closed)', () => {
    const r = checkOrderWithinEnvelope(order, { ...envelope, '@version': 'EP-FLEX-ENVELOPE-v1' });
    expect(r.within).toBe(false);
  });

  it('the ENERGY budget, not the MW cap, is the period ceiling: an order under max_event_mw whose projected MWh blows the remaining energy budget is refused', () => {
    // 12 MW is under the 15 MW per-event cap, but 100 of 120 MWh are already
    // settled — the projected 48 MWh exceeds the remaining 20 MWh.
    const r = checkOrderWithinEnvelope(order, envelope, { spent_mwh: 100 });
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain('remaining energy budget');
  });

  it('the same order passes when the remaining energy budget covers it', () => {
    expect(checkOrderWithinEnvelope(order, envelope, { spent_mwh: 72 }).within).toBe(true); // 48 ≤ 48 remaining
    expect(checkOrderWithinEnvelope(order, envelope, {}).within).toBe(true); // omitted spent = nothing settled yet
  });

  it('an exhausted event-count budget refuses the next order', () => {
    const r = checkOrderWithinEnvelope(order, envelope, { spent_events: 10 });
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain('event count budget exhausted');
    expect(checkOrderWithinEnvelope(order, envelope, { spent_events: 9 }).within).toBe(true);
  });

  it('an exhausted event-hours budget refuses an event that no longer fits', () => {
    const r = checkOrderWithinEnvelope(order, envelope, { spent_event_hours: 37 }); // 4 h > 3 h remaining
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain('remaining event-hours budget');
    expect(checkOrderWithinEnvelope(order, envelope, { spent_event_hours: 36 }).within).toBe(true);
  });
});

describe('GRACE — envelope budget edge cases fail closed', () => {
  it.each([
    ['max_event_mw'], ['max_period_mwh'], ['max_events'], ['max_event_hours'],
  ])('an envelope without %s cannot vouch for that dimension (missing bound → refused)', (bound) => {
    const partial = { ...envelope, bounds: { ...envelope.bounds, [bound]: undefined } };
    const r = checkOrderWithinEnvelope(order, partial);
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain(`${bound} missing or unparseable`);
  });

  it('a spent value that is PRESENT but unparseable is a violation, never coerced to zero', () => {
    for (const opts of [{ spent_mwh: 'garbage' }, { spent_events: 'garbage' }, { spent_event_hours: -1 }]) {
      const r = checkOrderWithinEnvelope(order, envelope, opts);
      expect(r.within).toBe(false);
      expect(r.violations.join(' ')).toContain('unparseable (fail closed)');
    }
  });
});

describe('GRACE — a refusal is signed evidence, not silence', () => {
  it('builds a refusal statement binding the refused order digest, the failing predicate, and the time', () => {
    const bad = checkOrderWithinEnvelope({ ...order, mw: '99.0' }, envelope);
    const refusal = buildRefusalStatement('sha256:' + 'a'.repeat(64), bad.violations, '2026-07-15T15:00:00Z');
    expect(refusal.typ).toBe('ep-curtailment-refusal');
    expect(refusal.refused_order_digest).toMatch(/^sha256:/);
    expect(refusal.failing_predicates.join(' ')).toContain('per-event cap');
    expect(refusal.refused_at).toBe('2026-07-15T15:00:00Z');
  });

  it('a non-array violation is coerced into a single-predicate list', () => {
    const refusal = buildRefusalStatement('sha256:' + 'b'.repeat(64), 'order: invalid window', '2026-07-15T15:00:00Z');
    expect(refusal.failing_predicates).toEqual(['order: invalid window']);
  });
});

describe('GRACE — compliance comes from the meter, and only the meter', () => {
  it('computes delivered vs ordered from meter intervals', () => {
    const c = computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [2.4, 2.1, 2.2, 2.3] });
    expect(c.computable).toBe(true);
    expect(c.delivered_mw).toBeCloseTo(11.95, 2);
    expect(c.compliant).toBe(true);
  });

  it('under-delivery is measurable, not hidden', () => {
    const c = computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [8.0, 8.2, 8.1, 8.0] });
    expect(c.compliant).toBe(false);
    expect(c.compliance_ratio).toBeLessThan(0.6);
  });

  it('a meter statement without baseline or intervals is not computable (never guessed)', () => {
    expect(computeCompliance({ mw: '12.0' }, { intervals_mw: [1] }).computable).toBe(false);
    expect(computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [] }).computable).toBe(false);
  });

  it('a meter statement carrying market rules (baseline_method_hash) is REFUSED — the meter is a physical witness', () => {
    const c = computeCompliance({ mw: '12.0' }, {
      baseline_mw: 14.2, intervals_mw: [2.4, 2.1, 2.2, 2.3],
      baseline_method_hash: 'sha256:' + 'c'.repeat(64),
    });
    expect(c.computable).toBe(false);
    expect(c.reason).toContain('physical witness');
    expect(c.reason).toContain('bundle level');
  });
});

describe('GRACE — one-time settlement consumption (the same event can never settle twice)', () => {
  const claim = {
    entitlement_id: 'sha256:' + 'e'.repeat(64), // the envelope being drawn against
    event_id: 'ercot-2026-07-15-0001',
    meter_window_digest: 'sha256:' + 'd'.repeat(64),
  };

  it('the first settlement consumes the entitlement; a duplicate is refused with a typed reason', () => {
    const registry = new Set();
    const first = checkSettlementConsumption(claim, registry);
    expect(first.settled).toBe(true);
    expect(first.key).toContain(SETTLEMENT_CONSUMPTION_PROFILE);
    const second = checkSettlementConsumption({ ...claim }, registry);
    expect(second.settled).toBe(false);
    expect(second.reason).toBe('settlement_already_consumed');
  });

  it('a different meter window (or event, or entitlement) is a different entitlement — not blocked', () => {
    const registry = new Set();
    expect(checkSettlementConsumption(claim, registry).settled).toBe(true);
    expect(checkSettlementConsumption({ ...claim, meter_window_digest: 'sha256:' + 'f'.repeat(64) }, registry).settled).toBe(true);
    expect(checkSettlementConsumption({ ...claim, event_id: 'ercot-2026-07-16-0002' }, registry).settled).toBe(true);
  });

  it.each([
    ['missing entitlement_id', { ...claim, entitlement_id: undefined }, 'entitlement_id_missing'],
    ['empty event_id', { ...claim, event_id: '' }, 'event_id_missing'],
    ['malformed meter_window_digest', { ...claim, meter_window_digest: 'not-a-digest' }, 'meter_window_digest_malformed'],
  ])('%s refuses fail-closed and consumes nothing', (_name, bad, reason) => {
    const registry = new Set();
    const r = checkSettlementConsumption(bad, registry);
    expect(r.settled).toBe(false);
    expect(r.reason).toBe(reason);
    expect(registry.size).toBe(0);
  });

  it('no registry, no settlement (fail closed)', () => {
    expect(checkSettlementConsumption(claim, undefined).reason).toBe('consumption_registry_missing');
    expect(checkSettlementConsumption(null, new Set()).reason).toBe('claim_missing');
  });

  it('the key is injective: parts cannot be re-split across field boundaries', () => {
    const a = settlementEntitlementKey({ entitlement_id: 'a', event_id: 'b:c', meter_window_digest: claim.meter_window_digest });
    const b = settlementEntitlementKey({ entitlement_id: 'a:b', event_id: 'c', meter_window_digest: claim.meter_window_digest });
    expect(a.key).not.toBe(b.key);
  });

  it('admits one concurrent durable settlement and refuses the duplicate', async () => {
    const states = new Map();
    const store = {
      durable: true,
      ownershipFenced: true,
      async reserve(key) {
        if (states.has(key)) return false;
        states.set(key, 'reserved');
        return true;
      },
      async commit(key) {
        if (states.get(key) !== 'reserved') return false;
        states.set(key, 'committed');
        return true;
      },
    };
    let effects = 0;
    let release;
    const first = runSettlementOnce(claim, store, async () => {
      effects += 1;
      await new Promise((resolve) => { release = resolve; });
      return { settlement_id: 'stl_1' };
    });
    while (!release) await new Promise((resolve) => setTimeout(resolve, 0));
    const second = await runSettlementOnce(claim, store, async () => { effects += 1; });
    expect(second).toMatchObject({ settled: false, reason: 'settlement_already_consumed' });
    release();
    const accepted = await first;
    expect(accepted).toMatchObject({ settled: true, result: { settlement_id: 'stl_1' } });
    expect(effects).toBe(1);
  });

  it('burns an indeterminate settlement attempt and fails closed on store outage', async () => {
    let state = null;
    const store = {
      async reserve() {
        if (state) return false;
        state = 'reserved';
        return true;
      },
      async commit() {
        if (state !== 'reserved') return false;
        state = 'committed';
        return true;
      },
    };
    await expect(runSettlementOnce(claim, store, async () => {
      throw new Error('bank response lost');
    })).rejects.toThrow('bank response lost');
    expect(await runSettlementOnce(claim, store, async () => {})).toMatchObject({
      settled: false,
      reason: 'settlement_already_consumed',
    });

    const outage = await runSettlementOnce(claim, {
      async reserve() { throw new Error('db down'); },
      async commit() { return true; },
    }, async () => {});
    expect(outage).toMatchObject({ settled: false, reason: 'consumption_registry_unavailable' });
  });

  it('the derived key IS the nonce for EP-SMT-CONSUME-v1: a real consumption proof verifies, and a second consumption of the same key cannot produce a transition', () => {
    const { key } = settlementEntitlementKey(claim);
    // Settlement authority's witnessed consumption log: key absent at h1,
    // present at h2, over an append-only dense log (same helpers as
    // packages/verify/consumption-proof.test.js).
    const denseLeaf = (content) => crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')])).digest('hex');
    const logLeaves = Array.from({ length: 6 }, (_, i) => denseLeaf(`settlement-log-${i}`));

    const before = new ReferenceConsumptionTree();
    const niProof = before.prove(key); // absent at h1
    const after = new ReferenceConsumptionTree();
    after.insert(key);
    const incProof = after.prove(key); // present at h2

    const bundle = {
      nonce: key,
      non_inclusion_proof: niProof,
      inclusion_proof: incProof,
      consistency_proof: buildConsistencyProof(3, 6, logLeaves),
      checkpoints: {
        h1: { tree_size: 3, root_hash: merkleRoot(logLeaves.slice(0, 3)) },
        h2: { tree_size: 6, root_hash: merkleRoot(logLeaves) },
      },
    };
    expect(verifyConsumptionProof(bundle).valid).toBe(true);

    // A SECOND settlement of the same key: the tree already holds it, so
    // there is no absent->present transition left to prove — the SMT root
    // does not change and the bundle is refused.
    after.insert(key);
    const again = after.prove(key);
    const replay = { ...bundle, non_inclusion_proof: { ...again, present: false }, inclusion_proof: again };
    const res = verifyConsumptionProof(replay);
    expect(res.valid).toBe(false);
  });
});

describe('GRACE — settlement policy shape', () => {
  it('requires all four legs, meter edges, and revocation on the authorization', () => {
    const p = CURTAILMENT_SETTLEMENT_POLICY;
    expect(Object.isFrozen(p)).toBe(true);
    for (const t of ['curtailment_order', 'authorization_receipt', 'execution_attestation', 'meter_statement']) {
      expect(p.requirement).toContain(t);
    }
    expect(p.required_edges).toContainEqual({ from_type: 'meter_statement', rel: 'records', to_type: 'execution_attestation' });
    expect(p.revocation_required).toContain('authorization_receipt');
  });
});

describe('GRACE — the full proof-of-curtailment vector', () => {
  it('runs end to end: envelope, challenge, presentation, admissible, signed reliance, one-time settlement, negatives enforced', () => {
    const out = execFileSync('node', [path.join(ROOT, 'examples/grace/proof-of-curtailment-vector.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    // OK line goes to stderr; execFileSync throws on nonzero exit — reaching
    // here means every assertion in the vector (positive + negatives) held.
    expect(true).toBe(true);
  });
});
