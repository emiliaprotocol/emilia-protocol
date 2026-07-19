// SPDX-License-Identifier: Apache-2.0
//
// Branch-level unit coverage for lib/guard-quorum-template.js — the org-pinned
// quorum-strength floor. The route-flow suite (quorum-org-template.test.js)
// exercises create/consume end to end; this pins the pure resolver/evaluator
// branches directly (threshold/window/distinct-humans/roster/mode floors, the
// three-way resolve outcome, and fail-closed on a store fault).

import { describe, it, expect } from 'vitest';
import {
  effectiveQuorumParams,
  normalizeQuorumTemplate,
  evaluateQuorumAgainstTemplate,
  resolveOrgQuorumTemplate,
} from '../lib/guard-quorum-template.js';

// Chainable supabase double: .from().select().eq().eq().limit() -> Promise<result>.
function mockClient(result, { throwOnFrom = false } = {}) {
  const chain = {
    from() { if (throwOnFrom) throw new Error('client boom'); return chain; },
    select() { return chain; },
    eq() { return chain; },
    limit() { return Promise.resolve(result); },
  };
  return chain;
}

describe('effectiveQuorumParams', () => {
  it('ordered mode: effective threshold is the roster size', () => {
    const p = effectiveQuorumParams({ mode: 'ordered', approvers: [{ role: 'a' }, { role: 'b' }] });
    expect(p.mode).toBe('ordered');
    expect(p.required).toBe(2);
  });
  it('threshold mode: uses a positive integer required', () => {
    expect(effectiveQuorumParams({ mode: 'threshold', required: 3 }).required).toBe(3);
  });
  it('threshold mode: non-integer/non-positive required -> NaN', () => {
    expect(Number.isNaN(effectiveQuorumParams({ required: 0 }).required)).toBe(true);
    expect(Number.isNaN(effectiveQuorumParams({ required: 'x' }).required)).toBe(true);
  });
  it('defaults: no approvers, distinct-humans true, 900s window', () => {
    const p = effectiveQuorumParams(null);
    expect(p.approvers).toEqual([]);
    expect(p.distinctHumans).toBe(true);
    expect(p.windowSec).toBe(900);
  });
  it('honors explicit distinct_humans:false and a finite window_sec', () => {
    const p = effectiveQuorumParams({ distinct_humans: false, window_sec: 120 });
    expect(p.distinctHumans).toBe(false);
    expect(p.windowSec).toBe(120);
  });
});

describe('normalizeQuorumTemplate', () => {
  it('returns null for a null/non-object row', () => {
    expect(normalizeQuorumTemplate(null)).toBeNull();
    expect(normalizeQuorumTemplate('nope')).toBeNull();
  });
  it('applies defaults and coerces non-integers to null floors', () => {
    const t = normalizeQuorumTemplate({ organization_id: 'o', action_type: 'a', min_required: 'x', max_window_sec: 1.5 });
    expect(t.min_required).toBeNull();
    expect(t.max_window_sec).toBeNull();
    expect(t.require_distinct_humans).toBe(true); // default
    expect(t.quorum_required).toBe(false);        // default
    expect(t.allowed_approvers).toBeNull();
    expect(t.allowed_modes).toBeNull();
  });
  it('keeps a non-empty roster and mode allowlist; drops empty arrays to null', () => {
    const t = normalizeQuorumTemplate({
      min_required: 2, require_distinct_humans: false, quorum_required: true,
      allowed_approvers: [{ role: 'cfo', approver: 'k1' }], allowed_modes: ['ordered'],
    });
    expect(t.min_required).toBe(2);
    expect(t.require_distinct_humans).toBe(false);
    expect(t.quorum_required).toBe(true);
    expect(t.allowed_approvers).toHaveLength(1);
    expect(t.allowed_modes).toEqual(['ordered']);
    expect(normalizeQuorumTemplate({ allowed_approvers: [], allowed_modes: [] }).allowed_approvers).toBeNull();
  });
});

describe('evaluateQuorumAgainstTemplate', () => {
  it('no template -> ok (nothing to enforce)', () => {
    expect(evaluateQuorumAgainstTemplate({ required: 1 }, null)).toEqual({ ok: true, violations: [] });
  });
  it('non-object policy against a template -> invalid_quorum_policy', () => {
    const r = evaluateQuorumAgainstTemplate(null, normalizeQuorumTemplate({ min_required: 2 }));
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('invalid_quorum_policy');
  });
  it('flags threshold_below_min', () => {
    const r = evaluateQuorumAgainstTemplate({ required: 1 }, normalizeQuorumTemplate({ min_required: 2 }));
    expect(r.violations).toContain('threshold_below_min');
  });
  it('flags window_exceeds_max', () => {
    const r = evaluateQuorumAgainstTemplate({ required: 2, window_sec: 1000 }, normalizeQuorumTemplate({ max_window_sec: 900 }));
    expect(r.violations).toContain('window_exceeds_max');
  });
  it('flags distinct_humans_disabled', () => {
    const r = evaluateQuorumAgainstTemplate({ required: 2, distinct_humans: false }, normalizeQuorumTemplate({ require_distinct_humans: true }));
    expect(r.violations).toContain('distinct_humans_disabled');
  });
  it('flags approver_out_of_roster', () => {
    const tmpl = normalizeQuorumTemplate({ allowed_approvers: [{ role: 'cfo', approver: 'k1' }] });
    const r = evaluateQuorumAgainstTemplate({ required: 1, approvers: [{ role: 'intern', approver: 'k9' }] }, tmpl);
    expect(r.violations).toContain('approver_out_of_roster');
  });
  it('flags mode_not_allowed', () => {
    const r = evaluateQuorumAgainstTemplate({ required: 1, mode: 'threshold' }, normalizeQuorumTemplate({ allowed_modes: ['ordered'] }));
    expect(r.violations).toContain('mode_not_allowed');
  });
  it('a policy at or above every floor passes', () => {
    const tmpl = normalizeQuorumTemplate({
      min_required: 2, max_window_sec: 900, require_distinct_humans: true,
      allowed_approvers: [{ role: 'cfo', approver: 'k1' }, { role: 'ctrl', approver: 'k2' }],
    });
    const r = evaluateQuorumAgainstTemplate(
      { required: 2, window_sec: 300, approvers: [{ role: 'cfo', approver: 'k1' }, { role: 'ctrl', approver: 'k2' }] },
      tmpl,
    );
    expect(r).toEqual({ ok: true, violations: [] });
  });
});

describe('resolveOrgQuorumTemplate', () => {
  it('missing org/action -> {template:null} (no hard fail)', async () => {
    expect(await resolveOrgQuorumTemplate(mockClient({ data: [], error: null }), {})).toEqual({ template: null });
  });
  it('a configured row -> normalized template', async () => {
    const row = { organization_id: 'o', action_type: 'a', min_required: 2, quorum_required: true };
    const r = await resolveOrgQuorumTemplate(mockClient({ data: [row], error: null }), { organizationId: 'o', actionType: 'a' });
    expect(r.template.min_required).toBe(2);
    expect(r.template.quorum_required).toBe(true);
  });
  it('no row -> {template:null}', async () => {
    const r = await resolveOrgQuorumTemplate(mockClient({ data: [], error: null }), { organizationId: 'o', actionType: 'a' });
    expect(r).toEqual({ template: null });
  });
  it('missing table (42P01) -> {template:null, tableMissing:true} (never bricks creation)', async () => {
    const r = await resolveOrgQuorumTemplate(mockClient({ data: null, error: { code: '42P01' } }), { organizationId: 'o', actionType: 'a' });
    expect(r).toEqual({ template: null, tableMissing: true });
  });
  it('a real store fault -> {error} (fail closed)', async () => {
    const r = await resolveOrgQuorumTemplate(mockClient({ data: null, error: { code: 'XX000', message: 'db down' } }), { organizationId: 'o', actionType: 'a' });
    expect(r.error).toBe('db down');
  });
  it('a thrown client -> {error} (fail closed)', async () => {
    const r = await resolveOrgQuorumTemplate(mockClient({}, { throwOnFrom: true }), { organizationId: 'o', actionType: 'a' });
    expect(r.error).toBeTruthy();
  });
});
