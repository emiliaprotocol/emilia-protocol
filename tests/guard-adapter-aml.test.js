/**
 * Guard adapter — AML end-to-end through runGuardPrecheck.
 *
 * Drives the real adapter (auth + policy + audit + response) with a mocked
 * Supabase + auth, and proves AML context flows through: a sanctioned
 * counterparty DENIES, a structuring pattern escalates to signoff, and a clean
 * financial action allows. Also covers the adapter's happy path (previously
 * unit-uncovered).
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';

const store = { aml_history: [], audit_events: [] };
const inserted = []; // every inserted row, in order (back-compat assertions)
const mockGetGuardedClient = vi.fn(() => ({ from: (t) => new Q(t) }));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: async () => ({ entity: { entity_id: 'ep_entity_acme', organization_id: 'ep_entity_acme' } }),
  authEntityId: (auth) => (typeof auth?.entity === 'string' ? auth.entity : auth?.entity?.entity_id || ''),
  getServiceClient: vi.fn(),
}));

// In-memory client: supports the aml_history window query chain + inserts.
class Q {
  constructor(table) { this.table = table; this.filters = []; this._limit = null; }
  select() { return this; }
  eq(c, v) { this.filters.push((r) => r[c] === v); return this; }
  gte(c, v) { this.filters.push((r) => r[c] >= v); return this; }
  order() { return this; }
  limit(n) { this._limit = n; return this; }
  async insert(row) {
    const r = { occurred_at: new Date().toISOString(), ...row };
    (store[this.table] ||= []).push(r);
    inserted.push(r);
    return { error: null };
  }
  then(resolve) {
    let rows = (store[this.table] || []).filter((r) => this.filters.every((f) => f(r)));
    rows = rows.slice().reverse(); // newest-first (insert order ascending)
    if (this._limit) rows = rows.slice(0, this._limit);
    return resolve({ data: rows, error: null });
  }
}
vi.mock('@/lib/write-guard', () => ({ getGuardedClient: (...args) => mockGetGuardedClient(...args) }));

const { runGuardPrecheck } = await import('../lib/guard-adapter.js');
const { GUARD_ACTION_TYPES, GUARD_DECISIONS } = await import('../lib/guard-policies.js');

const FIN_SPEC = {
  adapterName: 'fin.payment-release',
  actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
  policyId: 'fin.payment-release.v1',
  targetResourceField: 'payment_instruction_id',
  actorRole: 'system',
};

function precheck(body) {
  const req = new Request('https://www.emiliaprotocol.ai/api/v1/adapters/fin/payment-release/precheck', {
    method: 'POST',
    headers: { authorization: 'Bearer ep_live_test', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return runGuardPrecheck(req, FIN_SPEC);
}

function oversizedPrecheck(bytes) {
  const req = new Request('https://www.emiliaprotocol.ai/api/v1/adapters/fin/payment-release/precheck', {
    method: 'POST',
    headers: { authorization: 'Bearer ep_live_test', 'content-type': 'application/json' },
    body: JSON.stringify({ blob: 'x'.repeat(bytes) }),
  });
  return runGuardPrecheck(req, FIN_SPEC);
}

const baseBody = (extra = {}) => ({
  organization_id: 'ep_entity_acme',
  payment_instruction_id: 'pi_1',
  amount: 2000,
  currency: 'USD',
  enforcement_mode: 'enforce',
  before_state: { status: 'pending' },
  after_state: { status: 'released' },
  ...extra,
});

beforeEach(() => {
  inserted.length = 0;
  store.aml_history = [];
  store.audit_events = [];
  mockGetGuardedClient.mockClear();
});

describe('guard adapter + AML', () => {
  it('rejects oversized precheck bodies before DB work', async () => {
    const res = await oversizedPrecheck(257 * 1024);
    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
    expect(inserted).toHaveLength(0);
  });

  it('a clean financial action carries no AML signals (floored to signoff, not AML-escalated)', async () => {
    // AML intent: a clean action produces NO aml_signals. The decision is
    // allow_with_signoff because the mint-time key-class floor escalates a
    // large_payment_release that would otherwise be a bare allow — this is a
    // base-policy property, independent of AML. aml_signals is still null,
    // which is the assertion that isolates the AML behavior.
    const res = await precheck(baseBody());
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.signoff_required).toBe(true);
    expect(json.required_assurance).toBe('A');
    expect(json.aml_signals).toBeNull();
  });

  it('DENIES a payment to a sanctioned counterparty', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Blocked Person Alpha' }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.DENY);
    expect(json.receipt_status).toBe('denied');
    expect(json.aml_signals.some((s) => s.startsWith('sanctions_match'))).toBe(true);
    // The decision is recorded in the audit trail.
    expect(inserted.at(-1).after_state.aml_signals).toBeTruthy();
  });

  it('DENIES a payment to an embargoed jurisdiction', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Neutral Co', counterparty_country: 'IR' }));
    expect((await res.json()).decision).toBe(GUARD_DECISIONS.DENY);
  });

  it('escalates a structuring pattern to signoff', async () => {
    const res = await precheck(baseBody({ amount: 9500, recent_amounts: [9400, 9600] }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.signoff_required).toBe(true);
    expect(json.aml_signals.some((s) => s.startsWith('structuring'))).toBe(true);
  });

  it('observe mode never blocks even on a sanctions hit', async () => {
    const res = await precheck(baseBody({ counterparty_name: 'Blocked Person Alpha', enforcement_mode: 'observe' }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.OBSERVE);
    expect(json.observed_decision).toBe(GUARD_DECISIONS.DENY);
  });

  it('derives organization_id from the authenticated entity when the body omits it', async () => {
    const body = baseBody();
    delete body.organization_id;
    const res = await precheck(body);
    expect(res.status).toBe(201);
    expect(inserted.at(-1).after_state.organization_id).toBe('ep_entity_acme');
  });
});

describe('guard adapter + AML history (self-lookup)', () => {
  // Three near-threshold transfers to the same counterparty. None passes
  // recent_amounts; the adapter persists each and looks the window up itself.
  it('detects structuring from EP-persisted history (caller passes no recent_amounts)', async () => {
    const body = (amount) => baseBody({ counterparty_name: 'Smurf Trading', amount });

    // First near-threshold transfer, no priors: a SOFT signal (near_threshold)
    // — escalates to signoff but is not yet "structuring".
    const r1 = await (await precheck(body(9400))).json();
    expect(r1.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r1.aml_signals.some((s) => s.startsWith('structuring'))).toBe(false);
    expect(r1.aml_signals).toContain('near_threshold_amount');
    expect(store.aml_history.filter((h) => h.counterparty === 'smurf trading').length).toBe(1);

    await precheck(body(9600)); // second near-threshold, recorded
    // Third: the two priors are now in EP's own history → hard structuring,
    // detected without the caller ever supplying recent_amounts.
    const r3 = await (await precheck(body(9500))).json();
    expect(r3.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r3.aml_signals.some((s) => s.startsWith('structuring'))).toBe(true);
    expect(store.aml_history.filter((h) => h.counterparty === 'smurf trading').length).toBe(3);
  });

  it('a first-ever transfer to a counterparty (clean amount) records history and raises no AML signal', async () => {
    // History-recording intent preserved: the transfer is persisted to
    // aml_history so future prechecks can build a window from it. The decision
    // is allow_with_signoff due to the large_payment_release key-class floor
    // (not AML), and the clean counterparty contributes no aml_signals.
    const res = await precheck(baseBody({ counterparty_name: 'Acme Widgets', amount: 2000 }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.aml_signals).toBeNull();
    expect(store.aml_history.some((h) => h.counterparty === 'acme widgets' && Number(h.amount) === 2000)).toBe(true);
  });

  it('caller-supplied recent_amounts still take precedence over history', async () => {
    // History is empty, but the caller reports a structuring window directly.
    const res = await precheck(baseBody({ counterparty_name: 'Reported Co', amount: 9500, recent_amounts: [9400, 9600] }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.aml_signals.some((s) => s.startsWith('structuring'))).toBe(true);
  });
});

describe('guard adapter + PIP-007 initiator attestation', () => {
  it('carries an AML-uncertainty attestation in the response and audit row on a structuring escalation', async () => {
    const res = await precheck(baseBody({ amount: 9500, recent_amounts: [9400, 9600] }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.initiator_attestation).toBeTruthy();
    expect(json.initiator_attestation.escalation_trigger).toBe('uncertainty');
    expect(json.initiator_attestation.policy_basis).toContain('/rule:aml-screening');
    expect(json.initiator_attestation.statement.length).toBeLessThanOrEqual(280);
    // The attestation is recorded in the audit trail.
    expect(inserted.at(-1).after_state.initiator_attestation).toBeTruthy();
  });

  it('carries a magnitude attestation on a large-payment escalation', async () => {
    const res = await precheck(baseBody({ amount: 250_000 }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.initiator_attestation.escalation_trigger).toBe('magnitude');
    expect(json.initiator_attestation.policy_basis).toContain('/rule:payment-threshold-single');
  });

  it('omits the attestation (null) on a genuinely clean ALLOW', async () => {
    // The "null attestation on a clean ALLOW" invariant is preserved by routing
    // through a genuinely non-critical action (benefit_address_change with a
    // cosmetic display_name change), which the key-class floor does NOT escalate.
    // large_payment_release can no longer produce a clean ALLOW (it is floored),
    // so we exercise this invariant on an action type that still default-allows.
    const BENIGN_SPEC = {
      adapterName: 'gov.benefit-address-change',
      actionType: GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE,
      policyId: 'gov.benefit-address-change.v1',
      targetResourceField: 'benefit_case_id',
      actorRole: 'caseworker',
    };
    const req = new Request('https://www.emiliaprotocol.ai/api/v1/adapters/gov/benefit-address-change/precheck', {
      method: 'POST',
      headers: { authorization: 'Bearer ep_live_test', 'content-type': 'application/json' },
      body: JSON.stringify({
        organization_id: 'ep_entity_acme',
        benefit_case_id: 'bc_1',
        target_changed_fields: ['display_name'],
        enforcement_mode: 'enforce',
        before_state: { display_name: 'A' },
        after_state: { display_name: 'B' },
      }),
    });
    const res = await runGuardPrecheck(req, BENIGN_SPEC);
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW);
    expect(json.initiator_attestation).toBeNull();
  });

  it('mints a floor attestation on a floored large_payment_release (was a bare ALLOW)', async () => {
    // The formerly-clean sub-$50k large_payment_release is now floored to
    // signoff, so the initiator attestation is minted (no longer null). It
    // reflects the key-class floor's signoff-required escalation.
    const res = await precheck(baseBody());
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(json.initiator_attestation).not.toBeNull();
    expect(json.initiator_attestation.escalation_trigger).toBe('policy_rule');
  });

  it('observe mode still records the would-be attestation (signoffRequired preserved)', async () => {
    const res = await precheck(baseBody({ amount: 250_000, enforcement_mode: 'observe' }));
    const json = await res.json();
    expect(json.decision).toBe(GUARD_DECISIONS.OBSERVE);
    expect(json.observed_decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    // The attestation is built from the base decision, so observe mode keeps it.
    expect(json.initiator_attestation).toBeTruthy();
    expect(json.initiator_attestation.escalation_trigger).toBe('magnitude');
  });
});
