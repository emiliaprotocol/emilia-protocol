/**
 * EMILIA Gate robot sidecar — end-to-end demo. Run: node demo.mjs
 * One human signoff authorizes a bounded envelope; the edge verifies each motion
 * command offline, with no cloud and no per-command human. Fail-closed.
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { EdgeActuatorGate, SimulatedArm } from './index.js';

const canon = (v) => v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
  : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
  : JSON.stringify(v);
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

const nowSec = Math.floor(Date.now() / 1000);
function envelope({ not_after }) {
  const payload = {
    receipt_id: 'env_1', subject: 'agent:warehouse-planner', issuer: 'ep:org:demo',
    created_at: new Date().toISOString(),
    claim: {
      action_type: 'physical.envelope', outcome: 'allow_with_signoff', approver: 'ep:approver:floor-supervisor',
      control_mode: 'on_the_loop',
      authorization_scope: {
        effect_class: 'actuation', target_set: ['arm-1'], allowed_actions: ['arm.move', 'arm.grip'],
        bounds: { max_reach_cm: 80 }, window: { not_before: nowSec - 1, not_after },
      },
    },
  };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
}

const line = (s) => console.log(s);
const m = (r) => r.moved ? `\x1b[32mMOVED to ${r.position}cm\x1b[0m` : `\x1b[31mREFUSED\x1b[0m (${r.reason})`;

line('='.repeat(64));
line('  EMILIA Gate — robot sidecar  (arm-1, on-the-loop envelope)');
line('='.repeat(64));

// EdgeActuatorGate's constructor infers `trustedKeys` as `never[]` from its `= []`
// default (no JSDoc in index.js to widen it); the real, already-true type here is
// `string[]` (base64url-encoded Ed25519 public keys). Cast at this call boundary
// only — index.js is owned by another batch and out of scope for this file.
const gate = new EdgeActuatorGate(/** @type {any} */ ({ trustedKeys: [pub] }));
const arm = new SimulatedArm(gate);

line(`\n  command before any envelope        -> ${m(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }))}`);

const auth = gate.authorizeEnvelope(envelope({ not_after: nowSec + 60 }));
line(`\n  human signs envelope (arm-1, ≤80cm, 60s) -> ${auth.ok ? '\x1b[32mAUTHORIZED\x1b[0m' : 'REFUSED ' + auth.reason}`);

line(`\n  arm.move 30cm (in bounds)          -> ${m(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }))}`);
line(`  arm.move 70cm (in bounds, again)   -> ${m(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 70 }))}   (no consumption)`);
line(`  arm.move 120cm (exceeds reach)     -> ${m(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 120 }))}`);
line(`  weapon.fire (not in envelope)      -> ${m(arm.move({ action: 'weapon.fire', target: 'arm-1' }))}`);

gate.revoke();
line(`\n  human hits halt (revoke) ->`);
line(`  arm.move 30cm (after revoke)       -> ${m(arm.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }))}`);

// expired envelope
// Same trustedKeys type-gap as above (see comment near `gate`).
const gate2 = new EdgeActuatorGate(/** @type {any} */ ({ trustedKeys: [pub] }));
gate2.authorizeEnvelope(envelope({ not_after: nowSec - 1 }));
const arm2 = new SimulatedArm(gate2);
line(`  arm.move under EXPIRED envelope    -> ${m(arm2.move({ action: 'arm.move', target: 'arm-1', reach_cm: 30 }))}`);

line('\n  ' + '-'.repeat(60));
line('  One human signoff. Many edge-verified acts. Offline. Fail-closed.');
line('='.repeat(64));
