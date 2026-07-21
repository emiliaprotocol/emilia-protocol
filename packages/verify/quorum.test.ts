// SPDX-License-Identifier: Apache-2.0
//
// EP-QUORUM-v1 conformance test. Loads the adversarial quorum vectors (real
// multi-approver WebAuthn assertions) and asserts the verifier returns
// expect.valid for every one — proving the quorum predicate is FAIL-CLOSED:
// one bad signature, a duplicate human, an out-of-order signature, a mismatched
// action, an expired window, an under-threshold set, or an ineligible role each
// drives the whole quorum to invalid. Pure Node test (no vitest), zero-dep.
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { verifyQuorum } from './quorum.js';
import { canonicalize } from './index.js';

const suite = JSON.parse(
  readFileSync(new URL('../../conformance/vectors/quorum.v1.json', import.meta.url), 'utf8'),
);
const OPTS = { rpId: 'emiliaprotocol.ai', allowedOrigins: ['https://www.emiliaprotocol.ai', 'https://emiliaprotocol.ai'] };

test('EP-QUORUM-v1: every conformance vector matches expect.valid', () => {
  for (const v of suite.vectors) {
    const { valid } = verifyQuorum(v.quorum, OPTS);
    assert.strictEqual(valid, v.expect.valid, `${v.id}: expected valid=${v.expect.valid}, got ${valid}`);
  }
});

// Belt-and-suspenders: each negative trips the SPECIFIC predicate it targets,
// so a future refactor can't accidentally pass a reject vector for the wrong reason.
const byId = Object.fromEntries(suite.vectors.map((v) => [v.id, v]));
const predicateFor = {
  reject_under_threshold: 'threshold_met',
  reject_duplicate_human: 'distinct_humans',
  reject_out_of_order: 'order_satisfied',
  reject_action_mismatch: 'action_binding',
  reject_expired_window: 'within_window',
  reject_one_bad_signature: 'all_signatures_valid',
  reject_wrong_role: 'roles_admitted',
  reject_broken_chain: 'chain_linked',
  reject_duplicate_key: 'distinct_keys',
};
test('EP-QUORUM-v1: each negative fails on its targeted predicate', () => {
  for (const [id, predicate] of Object.entries(predicateFor)) {
    const { valid, checks } = verifyQuorum(byId[id].quorum, OPTS);
    assert.strictEqual(valid, false, `${id} should be invalid`);
    assert.strictEqual(checks[predicate], false, `${id}: expected ${predicate}=false`);
  }
});

test('EP-QUORUM-v1: a happy quorum passes every individual check', () => {
  const { valid, checks } = verifyQuorum(byId.accept_ordered_3of3.quorum, OPTS);
  assert.strictEqual(valid, true);
  for (const [k, v] of Object.entries(checks)) assert.strictEqual(v, true, `check ${k} should be true`);
});

// Fail-closed on malformed input — never throws, always returns valid:false.
test('EP-QUORUM-v1: malformed input fails closed without throwing', () => {
  for (const bad of [null, {}, { policy: {}, members: [] }, { action_hash: 'x', members: [{}], policy: { mode: 'ordered', approvers: [] } }]) {
    const r = verifyQuorum(bad, OPTS);
    assert.strictEqual(r.valid, false);
  }
});

// ── Synthetic-signer harness ────────────────────────────────────────────────
// Mints REAL P-256 WebAuthn-style signoffs (the same recipe used to bake the
// conformance vectors) so the members below genuinely COUNT toward the quorum —
// proving the initiator-exclusion and unconditional key-uniqueness predicates
// reject on real counted members, not vacuously on rejected signatures.
const RP_ID = 'emiliaprotocol.ai';
const spkiB64u = (pub) => pub.export({ type: 'spki', format: 'der' }).toString('base64url');
const ACTION_HASH = 'a'.repeat(64);

function mintSignoff(context, privateKey) {
  const challenge = crypto.createHash('sha256')
    .update(canonicalize(context), 'utf8').digest().toString('base64url');
  const clientDataJson = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${RP_ID}` }), 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(), // rpIdHash (32)
    Buffer.from([0x05, 0, 0, 0, 0]),                            // flags UP|UV + signCount
  ]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJson).digest()]);
  return {
    '@type': 'ep.signoff.webauthn',
    context,
    webauthn: {
      authenticator_data: authData.toString('base64url'),
      client_data_json: clientDataJson.toString('base64url'),
      signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
    },
  };
}
const ctx = (approver, initiator, issued_at, nonce) => ({
  ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: ACTION_HASH,
  policy: 'p', nonce, approver, initiator, issued_at, expires_at: '2026-06-11T01:00:00.000Z',
});

// (A) Initiator-as-approver => reject. The action's initiator (alice) also
// occupies an approver seat; the two-person rule requires the initiator to be
// excluded from the approver set. Every other predicate is satisfied, so this
// rejects ONLY via initiator_excluded — the exact case that slipped through
// before the fix.
test('EP-QUORUM-v1: initiator sitting in an approver seat is rejected', () => {
  const k1 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const k2 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const s1 = mintSignoff(ctx('ep:approver:alice', 'ep:approver:alice', '2026-06-11T00:01:00.000Z', 'n1'), k1.privateKey);
  const s2 = mintSignoff(ctx('ep:approver:bob', 'ep:approver:alice', '2026-06-11T00:02:00.000Z', 'n2'), k2.privateKey);
  const quorum = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH,
    policy: {
      mode: 'threshold', required: 2, distinct_humans: true, window_sec: 900,
      approvers: [
        { role: 'r1', approver: 'ep:approver:alice' },
        { role: 'r2', approver: 'ep:approver:bob' },
      ],
    },
    members: [
      { role: 'r1', approver_public_key: spkiB64u(k1.publicKey), signoff: s1 },
      { role: 'r2', approver_public_key: spkiB64u(k2.publicKey), signoff: s2 },
    ],
  };
  const { valid, checks } = verifyQuorum(quorum, OPTS);
  assert.strictEqual(valid, false, 'initiator-as-approver must reject');
  assert.strictEqual(checks.initiator_excluded, false, 'initiator_excluded must trip');
  // Prove it is the SOLE failing predicate (the pre-fix gap): everything else holds.
  for (const [k, v] of Object.entries(checks)) {
    if (k !== 'initiator_excluded') assert.strictEqual(v, true, `check ${k} should be true`);
  }
});

// (B) distinct_humans:false + one device key in two counted seats => reject.
// Key-uniqueness is a cryptographic floor, not a separation-of-duties
// preference: even with distinct_humans disabled (so distinct_humans passes),
// one signer cannot fill two seats. Rejects via distinct_keys.
test('EP-QUORUM-v1: one key in two seats is rejected even with distinct_humans:false', () => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // ONE key, two seats
  const key = spkiB64u(k.publicKey);
  const s1 = mintSignoff(ctx('ep:approver:alice', 'ent_agent_7', '2026-06-11T00:01:00.000Z', 'n1'), k.privateKey);
  const s2 = mintSignoff(ctx('ep:approver:bob', 'ent_agent_7', '2026-06-11T00:02:00.000Z', 'n2'), k.privateKey);
  const quorum = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH,
    policy: {
      mode: 'threshold', required: 2, distinct_humans: false, window_sec: 900,
      approvers: [
        { role: 'r1', approver: 'ep:approver:alice' },
        { role: 'r2', approver: 'ep:approver:bob' },
      ],
    },
    members: [
      { role: 'r1', approver_public_key: key, signoff: s1 },
      { role: 'r2', approver_public_key: key, signoff: s2 },
    ],
  };
  const { valid, checks } = verifyQuorum(quorum, OPTS);
  assert.strictEqual(valid, false, 'shared key must reject regardless of distinct_humans');
  assert.strictEqual(checks.distinct_keys, false, 'distinct_keys must trip unconditionally');
  // distinct_humans is DISABLED, so that check passes — proving key-uniqueness
  // is enforced independently, not as a side effect of separation-of-duties.
  assert.strictEqual(checks.distinct_humans, true, 'distinct_humans is off, so it passes');
});

test('EP-QUORUM-v1: a non-canonical SPKI encoding cannot fill a seat', () => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const canonicalKey = spkiB64u(k.publicKey);
  const paddedKey = `${canonicalKey}${'='.repeat((4 - canonicalKey.length % 4) % 4)}`;
  assert.notEqual(canonicalKey, paddedKey, 'fixture needs two textual encodings');
  const s1 = mintSignoff(ctx('ep:approver:alice', 'ent_agent_7', '2026-06-11T00:01:00.000Z', 'n1'), k.privateKey);
  const s2 = mintSignoff(ctx('ep:approver:bob', 'ent_agent_7', '2026-06-11T00:02:00.000Z', 'n2'), k.privateKey);
  const quorum = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH,
    policy: {
      mode: 'threshold', required: 2, distinct_humans: true, window_sec: 900,
      approvers: [
        { role: 'r1', approver: 'ep:approver:alice' },
        { role: 'r2', approver: 'ep:approver:bob' },
      ],
    },
    members: [
      { role: 'r1', approver_public_key: canonicalKey, signoff: s1 },
      { role: 'r2', approver_public_key: paddedKey, signoff: s2 },
    ],
  };
  const { valid, checks } = verifyQuorum(quorum, OPTS);
  assert.equal(valid, false);
  assert.equal(checks.all_signatures_valid, false);
});

test('EP-QUORUM-v1: roster fields containing separators cannot alias another seat', () => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signoff = mintSignoff(
    ctx('admin\u0000bob', 'ent_agent_7', '2026-06-11T00:01:00.000Z', 'n1'),
    k.privateKey,
  );
  const quorum = {
    '@type': 'ep.quorum',
    action_hash: ACTION_HASH,
    policy: {
      mode: 'threshold',
      required: 1,
      distinct_humans: true,
      window_sec: 900,
      approvers: [{ role: 'finance\u0000admin', approver: 'bob' }],
    },
    members: [{
      role: 'finance',
      approver_public_key: spkiB64u(k.publicKey),
      signoff,
    }],
  };

  const { valid, checks } = verifyQuorum(quorum, OPTS);
  assert.equal(valid, false);
  assert.equal(checks.roles_admitted, false);
});
