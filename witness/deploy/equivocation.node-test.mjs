/**
 * EP Witness: equivocation-detection test (node:test harness).
 *
 * Same mechanism as equivocation-demo.mjs (the narrated demo), asserted under
 * node's built-in test runner so it is CI-wireable the same way packages/**
 * suites are ("node --test", NOT vitest, witness/ ships no vitest config and
 * this file must stay off the vitest/proof-stats surface).
 *
 *   node --test witness/deploy/equivocation.node-test.mjs
 *
 * @license Apache-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { generateWitnessKey } from '../generate-key.mjs';
import { createServer } from '../server.mjs';
import { requireWitnessQuorum } from '../../packages/verify/witness.js';
import { detectEquivocation } from './detect-equivocation.mjs';

const LOG_KEY_ID = 'ep:log:demo-operator';
const MERKLE_ALG = 'EP-MERKLE-v2';

function makeIdentity() {
  const { privatePem, publicKeyB64u, witness_id } = generateWitnessKey();
  return { privateKey: crypto.createPrivateKey(privatePem), public_key: publicKeyB64u, witness_id };
}
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(s.address().port)));

function cosign(port, checkpoint) {
  const body = JSON.stringify({ checkpoint });
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/cosign', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (res.statusCode !== 200) return reject(new Error(`cosign ${res.statusCode}`));
          resolve(parsed.cosignature);
        });
      });
    req.on('error', reject);
    req.end(body);
  });
}

test('3 witnesses: honest head accepted, split view accepted per-verifier, gossip detects equivocation', async (t) => {
  const identities = [makeIdentity(), makeIdentity(), makeIdentity()];
  const servers = identities.map((id) => createServer(id));
  const ports = [];
  for (const s of servers) ports.push(await listen(s));
  t.after(() => servers.forEach((s) => s.close()));

  const pinned = identities.map((id) => ({ witness_id: id.witness_id, public_key: id.public_key }));
  const K = 2;

  // PHASE 1: honest single head, all 3 cosign, quorum met.
  const honest = { tree_size: 100, root_hash: 'sha256:' + 'a'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
  const honestCosigs = [];
  for (const p of ports) honestCosigs.push(await cosign(p, honest));
  const qHonest = requireWitnessQuorum(honest, honestCosigs, pinned, K);
  assert.equal(qHonest.ok, true, 'honest head meets quorum');
  assert.equal(qHonest.met, 3);

  // PHASE 2: log equivocates, two roots at the SAME tree_size.
  const headA = { tree_size: 200, root_hash: 'sha256:' + 'b'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
  const headB = { tree_size: 200, root_hash: 'sha256:' + 'c'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
  const cosigsA = [await cosign(ports[0], headA), await cosign(ports[1], headA)];
  const cosigsB = [await cosign(ports[1], headB), await cosign(ports[2], headB)];

  // Each verifier accepts its own head alone (no local detection).
  assert.equal(requireWitnessQuorum(headA, cosigsA, pinned, K).ok, true, 'verifier-A accepts head A alone');
  assert.equal(requireWitnessQuorum(headB, cosigsB, pinned, K).ok, true, 'verifier-B accepts head B alone');

  // Gossip detects the split view.
  const det = detectEquivocation(
    [{ checkpoint: headA, cosignatures: cosigsA, label: 'verifier-A' },
     { checkpoint: headB, cosignatures: cosigsB, label: 'verifier-B' }],
    pinned, K);
  assert.equal(det.equivocation, true, 'gossip detects equivocation');
  assert.equal(det.conflicts.length, 1);
  assert.equal(det.conflicts[0].tree_size, 200);
  assert.equal(det.conflicts[0].heads.length, 2);
  assert.deepEqual(det.conflicts[0].overlapping_witness_ids, [identities[1].witness_id],
    'straddling witness named as cosigning both heads');

  // CONTROL: agreeing views raise no false positive.
  const control = detectEquivocation(
    [{ checkpoint: honest, cosignatures: honestCosigs.slice(0, 2), label: 'X' },
     { checkpoint: honest, cosignatures: honestCosigs.slice(1, 3), label: 'Y' }],
    pinned, K);
  assert.equal(control.equivocation, false, 'agreeing views are clean');
});

test('detector is fail-closed: a head that misses quorum cannot convict the log', async (t) => {
  const identities = [makeIdentity(), makeIdentity(), makeIdentity()];
  const servers = identities.map((id) => createServer(id));
  const ports = [];
  for (const s of servers) ports.push(await listen(s));
  t.after(() => servers.forEach((s) => s.close()));
  const pinned = identities.map((id) => ({ witness_id: id.witness_id, public_key: id.public_key }));

  const headA = { tree_size: 5, root_hash: 'sha256:' + 'd'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
  const headB = { tree_size: 5, root_hash: 'sha256:' + 'e'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
  // Head B has only ONE cosignature, below k=2, so it is not a head anyone would
  // accept and must NOT be used to claim equivocation.
  const cosigsA = [await cosign(ports[0], headA), await cosign(ports[1], headA)];
  const cosigsB = [await cosign(ports[2], headB)];
  const det = detectEquivocation(
    [{ checkpoint: headA, cosignatures: cosigsA, label: 'A' },
     { checkpoint: headB, cosignatures: cosigsB, label: 'B' }],
    pinned, 2);
  assert.equal(det.equivocation, false, 'sub-quorum head does not trigger a false equivocation');
  assert.equal(det.quorum_backed_heads, 1);
});

test('detector preserves log ids containing control characters', async (t) => {
  const identities = [makeIdentity(), makeIdentity()];
  const servers = identities.map((id) => createServer(id));
  const ports = [];
  for (const s of servers) ports.push(await listen(s));
  t.after(() => servers.forEach((s) => s.close()));
  const pinned = identities.map((id) => ({ witness_id: id.witness_id, public_key: id.public_key }));
  const logKeyId = 'ep:log:operator\u0000shard';
  const headA = { tree_size: 7, root_hash: 'sha256:' + 'f'.repeat(64), log_key_id: logKeyId, merkle_alg: MERKLE_ALG };
  const headB = { tree_size: 7, root_hash: 'sha256:' + '0'.repeat(64), log_key_id: logKeyId, merkle_alg: MERKLE_ALG };
  const cosigsA = [await cosign(ports[0], headA), await cosign(ports[1], headA)];
  const cosigsB = [await cosign(ports[0], headB), await cosign(ports[1], headB)];

  const det = detectEquivocation(
    [{ checkpoint: headA, cosignatures: cosigsA, label: 'A' },
     { checkpoint: headB, cosignatures: cosigsB, label: 'B' }],
    pinned, 2);
  assert.equal(det.equivocation, true);
  assert.equal(det.conflicts[0].log_key_id, logKeyId);
  assert.equal(det.conflicts[0].tree_size, 7);
});
