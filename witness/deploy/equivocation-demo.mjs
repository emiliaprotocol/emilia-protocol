#!/usr/bin/env node
/**
 * EP Witness: real local equivocation-detection test.
 *
 * Stands up THREE distinct local witness instances in-process (each with its own
 * Ed25519 key, each the real witness/server.mjs over HTTP), then:
 *
 *   PHASE 1 (honest)      one head at tree_size N. All 3 witnesses /cosign it.
 *                         A verifier's requireWitnessQuorum(k=2) accepts.
 *
 *   PHASE 2 (equivocation) a MALICIOUS LOG presents TWO conflicting heads at the
 *                         SAME tree_size N (root A vs root B). Honest witnesses
 *                         each cosign whatever bytes they were shown, so valid
 *                         quorum-backed cosignatures exist for BOTH heads.
 *                         Verifier-A holds head A, verifier-B holds head B, each
 *                         passes its OWN local quorum check and detects nothing.
 *                         When A and B gossip (detectEquivocation), the conflict
 *                         is caught: one (log_key_id, tree_size), two roots, both
 *                         witness-backed, with the overlapping witnesses named.
 *
 * Everything below is executed for real against live HTTP witnesses and the real
 * @emilia-protocol/verify checks. No mocking, no stubbed crypto.
 *
 * Run: node witness/deploy/equivocation-demo.mjs
 * Exit 0 on the expected result (honest accepted AND equivocation detected),
 * non-zero if any assertion fails.
 *
 * @license Apache-2.0
 */

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
  const privateKey = crypto.createPrivateKey(privatePem);
  return { privateKey, public_key: publicKeyB64u, witness_id };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

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
          if (res.statusCode !== 200) return reject(new Error(`cosign ${res.statusCode}: ${JSON.stringify(parsed)}`));
          resolve(parsed.cosignature);
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

function assert(cond, msg) {
  if (!cond) { console.error(`ASSERT FAILED: ${msg}`); process.exitCode = 1; throw new Error(msg); }
}

async function main() {
  // --- Stand up 3 distinct local witnesses (distinct keys, distinct ports) ---
  const identities = [makeIdentity(), makeIdentity(), makeIdentity()];
  const servers = identities.map((id) => createServer(id));
  const ports = [];
  for (const s of servers) ports.push(await listen(s));

  const pinned = identities.map((id) => ({ witness_id: id.witness_id, public_key: id.public_key }));
  const K = 2; // quorum: 2 of 3 distinct witnesses

  console.log('=== 3 distinct local witness instances up ===');
  identities.forEach((id, i) => console.log(`  witness ${i + 1}: ${id.witness_id}  @127.0.0.1:${ports[i]}`));
  console.log(`  quorum threshold k=${K} of ${identities.length}\n`);

  try {
    // ================= PHASE 1: honest single head =================
    const headHonest = { tree_size: 100, root_hash: 'sha256:' + 'a'.repeat(64), log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
    const honestCosigs = [];
    for (const p of ports) honestCosigs.push(await cosign(p, headHonest));
    const qHonest = requireWitnessQuorum(headHonest, honestCosigs, pinned, K);
    console.log('=== PHASE 1  honest head ===');
    console.log(`  head: tree_size=${headHonest.tree_size} root=${headHonest.root_hash.slice(0, 14)}…`);
    console.log(`  quorum: ok=${qHonest.ok} met=${qHonest.met}/${qHonest.required} witnesses=${qHonest.witness_ids.length}`);
    assert(qHonest.ok && qHonest.met === 3, 'honest head should meet quorum with all 3 witnesses');
    console.log('  -> honest head ACCEPTED by 3 distinct pinned witnesses\n');

    // ================= PHASE 2: log equivocates =================
    // Malicious log commits TWO different roots at the SAME tree_size.
    const rootA = 'sha256:' + 'b'.repeat(64);
    const rootB = 'sha256:' + 'c'.repeat(64);
    const headA = { tree_size: 200, root_hash: rootA, log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };
    const headB = { tree_size: 200, root_hash: rootB, log_key_id: LOG_KEY_ID, merkle_alg: MERKLE_ALG };

    // Split view: the log shows head A to witnesses {1,2} and head B to {2,3}.
    // (Witness 2 is shown both, as a real split-view straddler would be.) Honest
    // witnesses sign exactly the bytes each was shown.
    const cosigsA = [await cosign(ports[0], headA), await cosign(ports[1], headA)];
    const cosigsB = [await cosign(ports[1], headB), await cosign(ports[2], headB)];

    // Verifier-A only ever saw head A; verifier-B only ever saw head B.
    const qA = requireWitnessQuorum(headA, cosigsA, pinned, K);
    const qB = requireWitnessQuorum(headB, cosigsB, pinned, K);
    console.log('=== PHASE 2  log presents two conflicting heads at tree_size=200 ===');
    console.log(`  verifier-A holds root ${rootA.slice(0, 14)}…  local quorum ok=${qA.ok} met=${qA.met}/${qA.required}`);
    console.log(`  verifier-B holds root ${rootB.slice(0, 14)}…  local quorum ok=${qB.ok} met=${qB.met}/${qB.required}`);
    assert(qA.ok, 'verifier-A should locally accept head A (it sees no conflict alone)');
    assert(qB.ok, 'verifier-B should locally accept head B (it sees no conflict alone)');
    console.log('  -> each verifier ACCEPTS its own head; NEITHER detects the split view alone\n');

    // ---- GOSSIP: verifier-A and verifier-B compare views ----
    const det = detectEquivocation(
      [
        { checkpoint: headA, cosignatures: cosigsA, label: 'verifier-A' },
        { checkpoint: headB, cosignatures: cosigsB, label: 'verifier-B' },
      ],
      pinned,
      K,
    );
    console.log('=== GOSSIP  verifier-A <-> verifier-B compare witness cosignatures ===');
    console.log(JSON.stringify(det, null, 2));
    assert(det.equivocation === true, 'gossip MUST detect equivocation');
    assert(det.conflicts.length === 1, 'exactly one conflicting (log,tree_size) position expected');
    const c = det.conflicts[0];
    assert(c.tree_size === 200 && c.heads.length === 2, 'conflict at tree_size 200 with 2 roots');
    assert(c.overlapping_witness_ids.length === 1 && c.overlapping_witness_ids[0] === identities[1].witness_id,
      'witness 2 must be named as having cosigned BOTH conflicting heads');
    console.log('\n  -> EQUIVOCATION DETECTED at tree_size=200:');
    console.log(`     two roots ${rootA.slice(0, 14)}… and ${rootB.slice(0, 14)}… under one log_key_id`);
    console.log(`     overlapping witness (signed both heads): ${c.overlapping_witness_ids.join(', ')}`);

    // ---- CONTROL: gossip over two views of the SAME honest head = no false positive ----
    const control = detectEquivocation(
      [
        { checkpoint: headHonest, cosignatures: honestCosigs.slice(0, 2), label: 'verifier-X' },
        { checkpoint: headHonest, cosignatures: honestCosigs.slice(1, 3), label: 'verifier-Y' },
      ],
      pinned,
      K,
    );
    console.log(`\n=== CONTROL  two views of the SAME honest head ===`);
    console.log(`  equivocation=${control.equivocation} (expected false)`);
    assert(control.equivocation === false, 'agreeing views MUST NOT raise a false equivocation');

    console.log('\n=== RESULT: PASS ===');
    console.log('honest head accepted; split view accepted by each verifier alone; gossip detected equivocation; agreeing views clean.');
  } finally {
    for (const s of servers) s.close();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
