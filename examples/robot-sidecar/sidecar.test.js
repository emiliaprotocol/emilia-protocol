// Generated from sidecar.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
function envelope(privateKey, { not_after = nowSec + 60 } = {}) {
    const payload = {
        receipt_id: 'env_t', subject: 'agent:test', issuer: 'ep:org:test', created_at: new Date().toISOString(),
        claim: {
            action_type: 'physical.envelope', outcome: 'allow_with_signoff', approver: 'ep:approver:sup',
            control_mode: 'on_the_loop',
            authorization_scope: { effect_class: 'actuation', target_set: ['arm-1'], allowed_actions: ['arm.move'], bounds: { max_reach_cm: 80 }, window: { not_before: nowSec - 1, not_after } },
        },
    };
    return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
}
test('no envelope -> actuator refuses', () => {
    const { pub } = makeKey();
    const arm = new SimulatedArm(new EdgeActuatorGate({ trustedKeys: [pub] }));
    assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).moved, false);
});
test('valid envelope -> many in-bounds moves allowed, no consumption', () => {
    const { pub, privateKey } = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    assert.equal(gate.authorizeEnvelope(envelope(privateKey)).ok, true);
    const arm = new SimulatedArm(gate);
    assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).moved, true);
    assert.equal(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 70 }).moved, true); // again — envelope not consumed
});
test('out-of-bounds reach -> refused', () => {
    const { pub, privateKey } = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    gate.authorizeEnvelope(envelope(privateKey));
    const arm = new SimulatedArm(gate);
    const r = arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 120 });
    assert.equal(r.moved, false);
    assert.equal(r.reason, 'exceeds_bounds');
});
test('action not in envelope -> refused', () => {
    const { pub, privateKey } = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    gate.authorizeEnvelope(envelope(privateKey));
    assert.equal(new SimulatedArm(gate).move({ action: 'weapon.fire', target: 'arm-1' }).reason, 'action_not_in_envelope');
});
test('revoke (halt) -> refused', () => {
    const { pub, privateKey } = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    gate.authorizeEnvelope(envelope(privateKey));
    gate.revoke();
    assert.equal(new SimulatedArm(gate).move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).reason, 'revoked');
});
test('expired envelope -> refused', () => {
    const { pub, privateKey } = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    gate.authorizeEnvelope(envelope(privateKey, { not_after: nowSec - 1 }));
    assert.equal(new SimulatedArm(gate).move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }).reason, 'expired');
});
test('forged envelope (untrusted key) -> not authorized', () => {
    const { pub } = makeKey();
    const attacker = makeKey();
    const gate = new EdgeActuatorGate({ trustedKeys: [pub] });
    assert.equal(gate.authorizeEnvelope(envelope(attacker.privateKey)).ok, false);
});
