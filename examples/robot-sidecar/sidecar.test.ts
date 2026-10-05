/** EMILIA Gate robot sidecar tests — run with `node --test`. @license Apache-2.0 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EdgeActuatorGate, SimulatedArm } from './index.js';

const canon = (v) => v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
  : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
  : JSON.stringify(v);
function makeKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const nowSec = Math.floor(Date.now() / 1000);
const baseScope = () => ({ effect_class: 'actuation', target_set: ['arm-1'], allowed_actions: ['arm.move'], bounds: { max_reach_cm: 80 }, window: { not_before: nowSec - 1, not_after: nowSec + 60 } });
function envelope(privateKey, { not_after = nowSec + 60, scope = undefined as any, receipt_id = 'env_t' as any } = {}) {
  const authorization_scope = scope !== undefined ? scope : { ...baseScope(), window: { not_before: nowSec - 1, not_after } };
  const payload = {
    receipt_id, subject: 'agent:test', issuer: 'ep:org:test', created_at: new Date().toISOString(),
    claim: {
      action_type: 'physical.envelope', outcome: 'allow_with_signoff', approver: 'ep:approver:sup',
      control_mode: 'on_the_loop',
      authorization_scope,
    },
  };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
}

test('no envelope -> actuator refuses', () => {
  const { pub } = makeKey();
  const arm = new SimulatedArm(new EdgeActuatorGate({ trustedKeys: [pub] } as any));
  assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).moved, false);
});

test('valid envelope -> many in-bounds moves allowed, no consumption', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  assert.equal(gate.authorizeEnvelope(envelope(privateKey)).ok, true);
  const arm = new SimulatedArm(gate);
  assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).moved, true);
  assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 70 }).moved, true); // again — envelope not consumed
});

test('out-of-bounds reach -> refused', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  gate.authorizeEnvelope(envelope(privateKey));
  const arm = new SimulatedArm(gate);
  const r = arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 120 });
  assert.equal(r.moved, false);
  assert.equal(r.reason, 'exceeds_bounds');
});

test('action not in envelope -> refused', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  gate.authorizeEnvelope(envelope(privateKey));
  assert.equal(new SimulatedArm(gate).move({ action: 'weapon.fire', target: 'arm-1' }).reason, 'action_not_in_envelope');
});

test('revoke (halt) -> refused', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  gate.authorizeEnvelope(envelope(privateKey));
  gate.revoke();
  assert.equal(new SimulatedArm(gate).move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).reason, 'revoked');
});

test('expired envelope -> refused', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  gate.authorizeEnvelope(envelope(privateKey, { not_after: nowSec - 1 }));
  assert.equal(new SimulatedArm(gate).move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).reason, 'expired');
});

test('forged envelope (untrusted key) -> not authorized', () => {
  const { pub } = makeKey();
  const attacker = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  assert.equal(gate.authorizeEnvelope(envelope(attacker.privateKey)).ok, false);
});

// ---------------------------------------------------------------------------
// Fail-closed: malformed commands. Each must return allow:false with a specific
// reason code and must never throw.
// ---------------------------------------------------------------------------

function liveGate(scope?: any) {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  const auth = gate.authorizeEnvelope(envelope(privateKey, scope ? { scope } : {}));
  assert.equal(auth.ok, true, `envelope should load: ${auth.reason}`);
  return gate;
}
const ok = { action: 'arm.move', target: 'arm-1', reach_cm: 30 };

function refuses(gate, command, reason, field?) {
  let decision;
  assert.doesNotThrow(() => { decision = gate.permit(command); });
  assert.equal(decision.allow, false, `expected refusal ${reason}`);
  assert.equal(decision.reason, reason);
  if (field !== undefined) assert.equal(decision.field, field);
}

test('valid command still allowed, and the arm moves to the checked value', () => {
  const gate = liveGate();
  const d = gate.permit(ok);
  assert.equal(d.allow, true);
  assert.equal(d.reason, 'within_envelope');
  const arm = new SimulatedArm(gate);
  assert.deepEqual(arm.move({ ...ok, reach_cm: 80 }), { moved: true, position: 80 }); // boundary is inclusive
  assert.deepEqual(arm.move({ ...ok, reach_cm: 0 }), { moved: true, position: 0 });
});

test('non-object commands -> command_not_plain_object', () => {
  const gate = liveGate();
  for (const c of [undefined, null, 'arm.move', 42, true, [ok], new Map(), new Date()]) refuses(gate, c, 'command_not_plain_object');
});

test('missing constrained fields -> refused, not skipped', () => {
  const gate = liveGate();
  refuses(gate, {}, 'missing_action');
  refuses(gate, { target: 'arm-1', reach_cm: 30 }, 'missing_action');
  refuses(gate, { action: 'arm.move', reach_cm: 30 }, 'missing_target');
  refuses(gate, { action: 'arm.move', target: 'arm-1' }, 'missing_reach_cm');
  refuses(gate, { action: 'arm.move', target: 'arm-1', reach_cm: undefined }, 'missing_reach_cm');
});

test('reach_cm NaN / Infinity / -Infinity -> reach_cm_not_finite', () => {
  const gate = liveGate();
  for (const reach_cm of [NaN, Infinity, -Infinity]) refuses(gate, { ...ok, reach_cm }, 'reach_cm_not_finite');
  assert.equal(new SimulatedArm(gate).move({ ...ok, reach_cm: NaN }).moved, false);
});

test('reach_cm negative zero and negatives -> refused', () => {
  const gate = liveGate();
  refuses(gate, { ...ok, reach_cm: -0 }, 'reach_cm_negative_zero');
  refuses(gate, { ...ok, reach_cm: -1 }, 'reach_cm_negative');
  refuses(gate, { ...ok, reach_cm: -1e-9 }, 'reach_cm_negative');
});

test('reach_cm wrong type (string, null, boolean, array, object, bigint) -> invalid_reach_cm_type', () => {
  const gate = liveGate();
  for (const reach_cm of ['30', '120', null, true, [30], { cm: 30 }, 30n]) refuses(gate, { ...ok, reach_cm }, 'invalid_reach_cm_type');
});

test('action / target wrong type or empty -> invalid_action / invalid_target', () => {
  const gate = liveGate();
  for (const action of [null, 1, '', ['arm.move'], { name: 'arm.move' }]) refuses(gate, { ...ok, action }, 'invalid_action');
  for (const target of [null, 1, '', ['arm-1'], { id: 'arm-1' }]) refuses(gate, { ...ok, target }, 'invalid_target');
  refuses(gate, { ...ok, target: 'arm-2' }, 'out_of_target_set');
});

test('unknown / extra command fields -> unknown_command_field', () => {
  const gate = liveGate();
  refuses(gate, { ...ok, speed_cm_s: 500 }, 'unknown_command_field', 'speed_cm_s');
  refuses(gate, { ...ok, override: true }, 'unknown_command_field', 'override');
  refuses(gate, { ...ok, nested: { reach_cm: 999 } }, 'unknown_command_field', 'nested');
  refuses(gate, { ...ok, __proto__: null, extra: 1 }, 'unknown_command_field', 'extra');
});

test('extra fields allowed only when the envelope names them, and only as finite scalars', () => {
  const gate = liveGate({ ...baseScope(), allowed_command_fields: ['note', 'grip_force'] });
  assert.equal(gate.permit({ ...ok, note: 'pick bin 4', grip_force: 3 }).allow, true);
  assert.equal(gate.permit(ok).allow, true); // allowed extras may be omitted
  refuses(gate, { ...ok, grip_force: NaN }, 'invalid_extra_field_value', 'grip_force');
  refuses(gate, { ...ok, grip_force: Infinity }, 'invalid_extra_field_value', 'grip_force');
  refuses(gate, { ...ok, grip_force: -0 }, 'invalid_extra_field_value', 'grip_force');
  refuses(gate, { ...ok, note: null }, 'invalid_extra_field_value', 'note');
  refuses(gate, { ...ok, note: ['a'] }, 'invalid_extra_field_value', 'note');
  refuses(gate, { ...ok, note: { a: 1 } }, 'invalid_extra_field_value', 'note');
  refuses(gate, { ...ok, other: 1 }, 'unknown_command_field', 'other');
});

test('reach_cm is an unknown field when the envelope does not bound reach', () => {
  const scope = baseScope();
  delete (scope as any).bounds;
  const gate = liveGate(scope);
  assert.equal(gate.permit({ action: 'arm.move', target: 'arm-1' }).allow, true);
  refuses(gate, ok, 'unknown_command_field', 'reach_cm');
});

test('accessor, symbol, and throwing-proxy commands -> refused, checked value is the actuated value', () => {
  const gate = liveGate();
  let reads = 0;
  const flip = { action: 'arm.move', target: 'arm-1', get reach_cm() { reads += 1; return reads === 1 ? 30 : 500; } };
  refuses(gate, flip, 'command_accessor_field', 'reach_cm');
  refuses(gate, { ...ok, [Symbol('x')]: 1 }, 'command_symbol_field');
  const hostile = new Proxy({ ...ok }, { ownKeys() { throw new Error('boom'); } });
  refuses(gate, hostile, 'command_unreadable');
  const hostileProto = new Proxy({ ...ok }, { getPrototypeOf() { throw new Error('boom'); } });
  refuses(gate, hostileProto, 'command_unreadable');
  const arm = new SimulatedArm(gate);
  assert.deepEqual(arm.move({ ...ok, reach_cm: 42 }), { moved: true, position: 42 });
});

test('clock that is not a finite number -> clock_unavailable', () => {
  const { pub, privateKey } = makeKey();
  for (const now of [() => NaN, () => { throw new Error('rtc'); }, () => '1' as any, NaN]) {
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
    assert.equal(gate.authorizeEnvelope(envelope(privateKey)).ok, true);
    gate.now = now;
    refuses(gate, ok, 'clock_unavailable');
  }
});

// ---------------------------------------------------------------------------
// Fail-closed: malformed envelopes are refused at authorization, never loaded
// as an unlimited default.
// ---------------------------------------------------------------------------

const scopeWithout = (key: string) => { const scope: any = baseScope(); delete scope[key]; return scope; };

test('malformed or unenforceable envelope scopes -> not authorized, with a reason', () => {
  const { pub, privateKey } = makeKey();
  const cases: [any, string][] = [
    [null, 'envelope_malformed_scope'],
    [[], 'envelope_malformed_scope'],
    [scopeWithout('allowed_actions'), 'envelope_malformed_allowed_actions'],
    [{ ...baseScope(), allowed_actions: [] }, 'envelope_malformed_allowed_actions'],
    [{ ...baseScope(), allowed_actions: ['arm.move', 1] }, 'envelope_malformed_allowed_actions'],
    [{ ...baseScope(), target_set: [] }, 'envelope_malformed_target_set'],
    [{ ...baseScope(), target_set: 'arm-1' }, 'envelope_malformed_target_set'],
    [{ ...baseScope(), bounds: { max_reach_cm: '80' } }, 'envelope_malformed_bounds'],
    [{ ...baseScope(), bounds: { max_reach_cm: null } }, 'envelope_malformed_bounds'],
    [{ ...baseScope(), bounds: { max_reach_cm: -1 } }, 'envelope_malformed_bounds'],
    [{ ...baseScope(), bounds: [] }, 'envelope_malformed_bounds'],
    [{ ...baseScope(), bounds: { max_reach_cm: 80, max_speed_cm_s: 10 } }, 'envelope_unsupported_bound'],
    [{ ...baseScope(), geofence: { radius_m: 2 } }, 'envelope_unsupported_constraint'],
    [scopeWithout('window'), 'envelope_malformed_window'],
    [{ ...baseScope(), window: { not_before: nowSec - 1 } }, 'envelope_malformed_window'],
    [{ ...baseScope(), window: { not_after: String(nowSec + 60) } }, 'envelope_malformed_window'],
    [{ ...baseScope(), window: { not_before: nowSec + 120, not_after: nowSec + 60 } }, 'envelope_malformed_window'],
    [{ ...baseScope(), allowed_command_fields: ['reach_cm'] }, 'envelope_malformed_allowed_command_fields'],
    [{ ...baseScope(), allowed_command_fields: [] }, 'envelope_malformed_allowed_command_fields'],
    [{ ...baseScope(), effect_class: 7 }, 'envelope_malformed_effect_class'],
  ];
  for (const [scope, reason] of cases) {
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
    let r;
    assert.doesNotThrow(() => { r = gate.authorizeEnvelope(envelope(privateKey, { scope })); });
    assert.equal(r.ok, false, `scope should be refused: ${reason} (${JSON.stringify(scope)})`);
    assert.equal(r.reason, reason);
    refuses(gate, ok, 'no_envelope');
  }
});

test('revoke cannot be undone by re-presenting the same signed envelope', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  const signed = envelope(privateKey);
  assert.equal(gate.authorizeEnvelope(signed).ok, true);
  gate.revoke();
  const again = gate.authorizeEnvelope(signed);
  assert.equal(again.ok, false);
  assert.equal(again.reason, 'envelope_revoked');
  refuses(gate, ok, 'revoked');
  // A fresh envelope with a different receipt_id is a new human signoff and loads.
  assert.equal(gate.authorizeEnvelope(envelope(privateKey, { receipt_id: 'env_t2' })).ok, true);
  assert.equal(gate.permit(ok).allow, true);
});

test('loaded envelope is a copy: mutating the receipt afterwards does not widen it', () => {
  const { pub, privateKey } = makeKey();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  const signed = envelope(privateKey);
  assert.equal(gate.authorizeEnvelope(signed).ok, true);
  signed.payload.claim.authorization_scope.bounds.max_reach_cm = 10_000;
  signed.payload.claim.authorization_scope.allowed_actions.push('weapon.fire');
  refuses(gate, { ...ok, reach_cm: 500 }, 'exceeds_bounds');
  refuses(gate, { ...ok, action: 'weapon.fire' }, 'action_not_in_envelope');
});

// ---------------------------------------------------------------------------
// Envelope-level bypasses: every signed time bound is enforced on every
// command through one clock, and the receipt is read exactly once.
// ---------------------------------------------------------------------------

function signEnvelope(privateKey, { scope = baseScope() as any, expires_at = undefined as any, receipt_id = 'env_x' } = {}) {
  const payload: any = {
    receipt_id, subject: 'agent:test', issuer: 'ep:org:test', created_at: new Date().toISOString(),
    claim: { action_type: 'physical.envelope', outcome: 'allow_with_signoff', approver: 'ep:approver:sup', control_mode: 'on_the_loop', authorization_scope: scope },
  };
  if (expires_at !== undefined) payload.expires_at = expires_at;
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
}

test('signed expires_at is enforced by permit, not only at authorization', () => {
  const { pub, privateKey } = makeKey();
  let clock = Date.now();
  const gate = new EdgeActuatorGate({ trustedKeys: [pub], now: () => clock } as any);
  const scope = { ...baseScope(), window: { not_before: Math.floor(clock / 1000) - 1, not_after: Math.floor(clock / 1000) + 3600 } };
  const auth = gate.authorizeEnvelope(signEnvelope(privateKey, { scope, expires_at: new Date(clock + 2000).toISOString() }));
  assert.equal(auth.ok, true, `envelope should load: ${auth.reason}`);
  assert.equal(gate.permit({ action: 'arm.move', target: 'arm-1', reach_cm: 1 }).allow, true);
  clock += 2500; // past expires_at, well inside window.not_after
  refuses(gate, { action: 'arm.move', target: 'arm-1', reach_cm: 1 }, 'receipt_expired');
  assert.equal(new SimulatedArm(gate).move({ action: 'arm.move', target: 'arm-1', reach_cm: 1 }).moved, false);
});

test('authorization verifies expires_at with the gate clock, not the host clock', () => {
  const { pub, privateKey } = makeKey();
  const realNow = Date.now();
  const scope = { ...baseScope(), window: { not_before: 0, not_after: Math.floor(realNow / 1000) + 3600 } };
  // Host clock says still valid; the gate clock says expired: refused.
  const late = new EdgeActuatorGate({ trustedKeys: [pub], now: () => realNow + 10_000 } as any);
  const r = late.authorizeEnvelope(signEnvelope(privateKey, { scope, expires_at: new Date(realNow + 5000).toISOString() }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'envelope_receipt_expired');
  refuses(late, ok, 'no_envelope');
  // Host clock says expired; the gate clock says valid: loads, and permit agrees.
  const early = new EdgeActuatorGate({ trustedKeys: [pub], now: () => realNow - 10_000 } as any);
  const r2 = early.authorizeEnvelope(signEnvelope(privateKey, { scope, expires_at: new Date(realNow - 5000).toISOString() }));
  assert.equal(r2.ok, true, `envelope should load under the gate clock: ${r2.reason}`);
  assert.equal(early.permit(ok).allow, true);
  // An unusable gate clock refuses authorization rather than falling back to the host clock.
  for (const now of [() => NaN, () => { throw new Error('rtc'); }]) {
    const broken = new EdgeActuatorGate({ trustedKeys: [pub], now } as any);
    let r3;
    assert.doesNotThrow(() => { r3 = broken.authorizeEnvelope(signEnvelope(privateKey, { scope })); });
    assert.equal(r3.ok, false);
    assert.equal(r3.reason, 'envelope_clock_unavailable');
  }
});

test('receipt payload getter cannot swap a widened payload in after verification', () => {
  const { pub, privateKey } = makeKey();
  const signed = signEnvelope(privateKey);
  const widened = structuredClone(signed.payload);
  widened.claim.authorization_scope.bounds.max_reach_cm = 100000;
  widened.claim.authorization_scope.allowed_actions.push('weapon.fire');
  let reads = 0;
  const swapping = { '@version': signed['@version'], signature: signed.signature, get payload() { reads += 1; return reads <= 2 ? signed.payload : widened; } };
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  let r;
  assert.doesNotThrow(() => { r = gate.authorizeEnvelope(swapping); });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'envelope_receipt_accessor_field');
  assert.equal(reads, 0, 'the accessor is refused without being invoked');
  refuses(gate, { ...ok, action: 'weapon.fire' }, 'no_envelope');
});

test('receipt behind a Proxy cannot swap a widened payload in after verification', () => {
  const { pub, privateKey } = makeKey();
  const signed = signEnvelope(privateKey);
  const widened = structuredClone(signed.payload);
  widened.claim.authorization_scope.bounds.max_reach_cm = 100000;
  widened.claim.authorization_scope.allowed_actions.push('weapon.fire');
  let reads = 0;
  const swapping = new Proxy(signed, { get(t, k) { if (k === 'payload') { reads += 1; return reads <= 2 ? t.payload : widened; } return t[k]; } });
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  let r;
  assert.doesNotThrow(() => { r = gate.authorizeEnvelope(swapping); });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'envelope_receipt_non_plain_object');
  refuses(gate, { ...ok, action: 'weapon.fire' }, 'no_envelope');
  refuses(gate, { ...ok, reach_cm: 500 }, 'no_envelope');
  // Nested exotic values anywhere in the receipt are refused the same way.
  const nested = structuredClone(signed);
  nested.payload.claim = new Proxy(nested.payload.claim, {});
  assert.equal(gate.authorizeEnvelope(nested).reason, 'envelope_receipt_non_plain_object');
});

test('receipt shapes that are not plain data -> refused with a reason, never thrown', () => {
  const { pub, privateKey } = makeKey();
  const signed = signEnvelope(privateKey);
  const gate = new EdgeActuatorGate({ trustedKeys: [pub] } as any);
  const cases: [any, string][] = [
    [undefined, 'envelope_malformed_receipt'],
    [null, 'envelope_malformed_receipt'],
    ['receipt', 'envelope_malformed_receipt'],
    [new Proxy(signed, { get() { throw new Error('boom'); } }), 'envelope_receipt_non_plain_object'],
    [new Proxy(signed, { ownKeys() { throw new Error('boom'); } }), 'envelope_receipt_non_plain_object'],
    [{ ...signed, get payload() { throw new Error('boom'); } }, 'envelope_receipt_accessor_field'],
    [{ ...signed, [Symbol('x')]: 1 }, 'envelope_receipt_symbol_field'],
    [{ ...signed, payload: { ...signed.payload, claim: new Map() } }, 'envelope_receipt_non_plain_object'],
    [{ ...signed, payload: { ...signed.payload, extra: () => 1 } }, 'envelope_receipt_non_data_value'],
    [{ ...signed, payload: { ...signed.payload, extra: undefined } }, 'envelope_receipt_non_data_value'],
    [{ ...signed, payload: { ...signed.payload, extra: 1n } }, 'envelope_receipt_non_data_value'],
    [{ ...signed, payload: { ...signed.payload, extra: NaN } }, 'envelope_receipt_non_data_value'],
  ];
  const cyclic: any = structuredClone(signed);
  cyclic.payload.claim.self = cyclic.payload.claim;
  cases.push([cyclic, 'envelope_receipt_too_deep']);
  for (const [receipt, reason] of cases) {
    let r;
    assert.doesNotThrow(() => { r = gate.authorizeEnvelope(receipt); }, reason);
    assert.equal(r.ok, false, reason);
    assert.equal(r.reason, reason);
  }
  refuses(gate, ok, 'no_envelope');
  assert.equal(gate.authorizeEnvelope(signed).ok, true);
});

test('window bounds are compared in milliseconds: no sub-second use after not_after', () => {
  const { pub, privateKey } = makeKey();
  const S = Math.floor(Date.now() / 1000) + 100;
  let clock = (S - 50) * 1000;
  const gate = new EdgeActuatorGate({ trustedKeys: [pub], now: () => clock } as any);
  const scope = { ...baseScope(), window: { not_before: S - 50, not_after: S } };
  assert.equal(gate.authorizeEnvelope(signEnvelope(privateKey, { scope })).ok, true);
  clock = (S - 50) * 1000 - 1;
  refuses(gate, ok, 'before_window');
  clock = (S - 50) * 1000; // not_before is inclusive
  assert.equal(gate.permit(ok).allow, true);
  clock = S * 1000 - 1;
  assert.equal(gate.permit(ok).allow, true);
  clock = S * 1000; // not_after is exclusive
  refuses(gate, ok, 'expired');
  clock = S * 1000 + 500;
  refuses(gate, ok, 'expired');
  clock = S * 1000 + 999;
  refuses(gate, ok, 'expired');
});
