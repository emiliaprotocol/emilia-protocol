// SPDX-License-Identifier: Apache-2.0
//
// Generator for the OPT-IN profile cross-language conformance vectors:
//   EP-CURRENCY-v1                (currency.v2.json; v1 is the frozen clean-room baseline)
//   EP-INITIATOR-ATTESTATION-v1   (initiator-attestation.v1.json)
//   EP-SMT-CONSUME-v1             (consumption-proof.v1.json)
//   EP-WITNESS-v1                 (witness.v1.json)
//
// Deterministic (fixed Ed25519 seeds, no randomness) so JS, Python (and any
// future Go port) verify the SAME bytes and MUST return each vector's
// expect.valid. Every vector is self-contained. The vectors agent wires the
// runner discriminators (currency / initiator_attestation / consumption_proof /
// witness_quorum).
//
// Run: node conformance/vectors/generate-optin-profiles.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { evaluateCurrency } from '../../packages/verify/currency.js';
import { validateInitiatorAttestation } from '../../packages/verify/initiator-attestation.js';
import { witnessSigningDigest, WITNESS_VERSION, requireWitnessQuorum } from '../../packages/verify/witness.js';
import {
  ReferenceConsumptionTree, verifyConsumptionProof,
} from '../../packages/verify/consumption-proof.js';
import { buildConsistencyProof, merkleRoot } from '../../packages/verify/consistency.js';

const OUT = dirname(fileURLToPath(import.meta.url));

// ── Deterministic Ed25519 from a fixed 32-byte seed ──────────────────────────
function keyFromSeed(seedHex) {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(/** @type {any} */ (priv)).export({ type: 'spki', format: 'der' }).toString('base64url');
  return { priv, pub };
}
const cp = (n) => String.fromCodePoint(n);

// =============================================================================
// EP-CURRENCY-v1 — evaluateCurrency(...).currency_at_T.status === expect_status
// =============================================================================
// Runner contract: valid iff evaluateCurrency(args).currency_at_T.status === v.currency.expect_status.
const NOW = '2026-07-05T12:00:00.000Z';
const ACTION_HASH = 'sha256:' + 'a'.repeat(64);
const OTHER_HASH = 'sha256:' + 'b'.repeat(64);
const receipt = { action_hash: ACTION_HASH };
const headAt = (sec, extra = {}) => ({ observed_at: new Date(Date.parse(NOW) - sec * 1000).toISOString(), ...extra });

const currencyVectors = [];
const addCurrency = (id, args, expect_status) => {
  const got = evaluateCurrency(args).currency_at_T.status;
  if (got !== expect_status) throw new Error(`currency ${id}: generator got ${got}, expected ${expect_status}`);
  currencyVectors.push({ id, expect: { valid: true }, currency: { args, expect_status } });
};
addCurrency('unknown_offline_no_head', { receipt, authentic_as_of_commit: true, now: NOW }, 'unknown');
addCurrency('unknown_null_head', { receipt, authentic_as_of_commit: true, now: NOW, freshHead: null }, 'unknown');
addCurrency('fresh_recent_within_window', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: headAt(60) }, 'fresh');
addCurrency('fresh_different_target_not_revoked', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: headAt(5, { revoked_target_hashes: [OTHER_HASH] }) }, 'fresh');
addCurrency('stale_head_too_old', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: headAt(600) }, 'stale');
addCurrency('stale_scalar_revoked', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: headAt(5, { revoked: true }) }, 'stale');
addCurrency('stale_status_list_revokes_this', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: headAt(5, { revoked_target_hashes: [ACTION_HASH] }) }, 'stale');
addCurrency('stale_required_but_absent', { receipt, authentic_as_of_commit: true, now: NOW, freshHeadRequired: true }, 'stale');
addCurrency('stale_no_policy_bound', { receipt, authentic_as_of_commit: true, now: NOW, freshHead: headAt(1) }, 'stale');
addCurrency('stale_negative_bound', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: -1, freshHead: headAt(1) }, 'stale');
addCurrency('unknown_bad_now', { receipt, authentic_as_of_commit: true, now: 'not-a-time', maxStalenessSeconds: 300, freshHead: headAt(1) }, 'unknown');
addCurrency('unknown_malformed_head', { receipt, authentic_as_of_commit: true, now: NOW, maxStalenessSeconds: 300, freshHead: { revoked: false } }, 'unknown');

// =============================================================================
// EP-INITIATOR-ATTESTATION-v1 — validateInitiatorAttestation(att).ok === expect
// =============================================================================
// Runner contract: valid iff validateInitiatorAttestation(v.initiator_attestation).ok === v.expect.valid.
const DIGEST = `sha256:${crypto.createHash('sha256').update('tool-context').digest('hex')}`;
const validAtt = () => ({ model_id: 'anthropic/claude-opus', model_version: '2026-01-05', tool_chain_digest: DIGEST });
const initiatorVectors = [];
const addInit = (id, expectValid, att) => {
  const got = validateInitiatorAttestation(att).ok;
  if (got !== expectValid) throw new Error(`initiator ${id}: generator ok=${got}, expected ${expectValid}`);
  initiatorVectors.push({ id, expect: { valid: expectValid }, initiator_attestation: att });
};
addInit('accept_minimal', true, validAtt());
addInit('accept_bare_uppercase_digest', true, { ...validAtt(), tool_chain_digest: crypto.createHash('sha256').update('ctx').digest('hex').toUpperCase() });
addInit('accept_hostile_statement_neutralized', true, { ...validAtt(), statement: `send ${cp(0x202e)}${cp(0x0000)}000 pay${cp(0x0085)} now` });
addInit('accept_homoglyph_statement', true, { ...validAtt(), statement: `p${cp(0x0430)}y now` });
addInit('reject_missing_model_id', false, (() => { const a = /** @type {any} */ (validAtt()); delete a.model_id; return a; })());
addInit('reject_empty_model_version', false, { ...validAtt(), model_version: '' });
addInit('reject_malformed_digest', false, { ...validAtt(), tool_chain_digest: 'sha256:' + 'a'.repeat(63) });
addInit('reject_missing_digest', false, (() => { const a = /** @type {any} */ (validAtt()); delete a.tool_chain_digest; return a; })());
addInit('reject_unknown_member', false, { ...validAtt(), evil: 'x' });
addInit('reject_wrong_version', false, { ...validAtt(), '@version': 'EP-OTHER-v9' });
addInit('reject_statement_over_cap', false, { ...validAtt(), statement: 'a'.repeat(281) });

// =============================================================================
// EP-SMT-CONSUME-v1 — verifyConsumptionProof(bundle).valid === expect
// =============================================================================
// Runner contract: valid iff verifyConsumptionProof(v.consumption_proof).valid === v.expect.valid.
const denseLeaf = (content) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')])).digest('hex');
const denseLeaves = (n) => Array.from({ length: n }, (_, i) => denseLeaf(`log-entry-${i}`));
function makeBundle({ nonce = 'nonce-A', otherNonces = ['nonce-B', 'nonce-C'], m = 3, n = 6 } = {}) {
  const tb = new ReferenceConsumptionTree(); for (const o of otherNonces) tb.insert(o);
  const ni = tb.prove(nonce);
  const ta = new ReferenceConsumptionTree(); for (const o of otherNonces) ta.insert(o); ta.insert(nonce);
  const inc = ta.prove(nonce);
  const leaves = denseLeaves(n);
  return {
    nonce, non_inclusion_proof: ni, inclusion_proof: inc,
    consistency_proof: buildConsistencyProof(m, n, leaves),
    checkpoints: { h1: { tree_size: m, root_hash: merkleRoot(leaves.slice(0, m)) }, h2: { tree_size: n, root_hash: merkleRoot(leaves) } },
    _leaves: leaves, _m: m, _n: n,
  };
}
const strip = (b) => { const c = JSON.parse(JSON.stringify(b)); delete c._leaves; delete c._m; delete c._n; return c; };
const consumptionVectors = [];
const addConsume = (id, expectValid, bundle) => {
  const got = verifyConsumptionProof(bundle).valid;
  if (got !== expectValid) throw new Error(`consume ${id}: generator valid=${got}, expected ${expectValid}`);
  consumptionVectors.push({ id, expect: { valid: expectValid }, consumption_proof: strip(bundle) });
};
addConsume('accept_genuine_transition', true, makeBundle());
addConsume('accept_larger_tree', true, makeBundle({ otherNonces: ['n1', 'n2', 'n3', 'n4', 'n5'], m: 4, n: 9 }));
{
  const b = makeBundle(); const already = new ReferenceConsumptionTree(); already.insert(b.nonce);
  b.non_inclusion_proof = already.prove(b.nonce); // present where absent required
  addConsume('reject_present_at_h1', false, b);
}
{
  const b = makeBundle(); const abs = new ReferenceConsumptionTree(); abs.insert('nonce-B'); abs.insert('nonce-C');
  b.inclusion_proof = abs.prove(b.nonce); // absent where present required
  addConsume('reject_absent_at_h2', false, b);
}
{
  const b = makeBundle(); const forked = [...b._leaves]; forked[0] = denseLeaf('rewritten-0');
  b.checkpoints.h1.root_hash = merkleRoot(forked.slice(0, b._m));
  addConsume('reject_non_append_only', false, b);
}
{
  const b = makeBundle(); b.inclusion_proof.value = crypto.createHash('sha256').update('forged').digest('hex');
  addConsume('reject_tampered_value', false, b);
}

// =============================================================================
// EP-WITNESS-v1 — requireWitnessQuorum(checkpoint, cosigs, pinned, k).ok === expect
// =============================================================================
// Seeded keypair + cosignature so JS and Python verify the SAME committed bytes.
// Runner contract: valid iff requireWitnessQuorum(v.witness_quorum.checkpoint,
//   v.witness_quorum.cosignatures, v.witness_quorum.pinned, v.witness_quorum.k).ok === v.expect.valid.
const checkpoint = { tree_size: 42, root_hash: `sha256:${'a1'.repeat(32)}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
const wA = keyFromSeed('11'.repeat(32)), wB = keyFromSeed('22'.repeat(32)), wC = keyFromSeed('33'.repeat(32));
function cosign(cpt, id, k) {
  const digest = /** @type {Buffer} */ (witnessSigningDigest(cpt));
  return { alg: WITNESS_VERSION, witness_id: id, tree_size: cpt.tree_size, root_hash: cpt.root_hash, log_key_id: cpt.log_key_id, signature: crypto.sign(null, digest, k.priv).toString('base64url') };
}
const pinned = [{ witness_id: 'a', public_key: wA.pub }, { witness_id: 'b', public_key: wB.pub }, { witness_id: 'c', public_key: wC.pub }];
const csA = cosign(checkpoint, 'a', wA), csB = cosign(checkpoint, 'b', wB), csC = cosign(checkpoint, 'c', wC);
const otherHead = { ...checkpoint, tree_size: 99 };
const csB_other = cosign(otherHead, 'b', wB);
const wStranger = keyFromSeed('44'.repeat(32));
const csStranger = cosign(checkpoint, 'stranger', wStranger);

const witnessVectors = [];
const addWitness = (id, expectValid, wq) => {
  const got = requireWitnessQuorum(wq.checkpoint, wq.cosignatures, wq.pinned, wq.k).ok;
  if (got !== expectValid) throw new Error(`witness ${id}: generator ok=${got}, expected ${expectValid}`);
  witnessVectors.push({ id, expect: { valid: expectValid }, witness_quorum: wq });
};
addWitness('accept_3_of_3_over_one_head', true, { checkpoint, cosignatures: [csA, csB, csC], pinned, k: 2 });
addWitness('accept_exactly_k', true, { checkpoint, cosignatures: [csA, csB], pinned, k: 2 });
addWitness('reject_k_minus_1', false, { checkpoint, cosignatures: [csA, csB], pinned, k: 3 });
addWitness('reject_duplicate_counts_once', false, { checkpoint, cosignatures: [csA, csA], pinned, k: 2 });
addWitness('reject_unpinned_ignored', false, { checkpoint, cosignatures: [csA, csStranger], pinned, k: 2 });
addWitness('reject_different_head_ignored', false, { checkpoint, cosignatures: [csA, csB_other], pinned, k: 2 });

// ── write suites ─────────────────────────────────────────────────────────────
const write = (file, suite, profile, vectors, vectorsVersion = '1.0.0') => {
  const doc = { suite, profile, vectors_version: vectorsVersion, count: vectors.length, vectors };
  writeFileSync(resolve(OUT, file), JSON.stringify(doc, null, 2) + '\n');
  console.log(`wrote ${file}: ${vectors.length} vectors`);
};
write('currency.v2.json', 'EP-CURRENCY-v1',
  'Two-valued currency status. valid iff evaluateCurrency(currency.args).currency_at_T.status === currency.expect_status.', currencyVectors, '2.0.0');
write('initiator-attestation.v1.json', 'EP-INITIATOR-ATTESTATION-v1',
  'Initiator attestation validation + hostile-text neutralization. valid iff validateInitiatorAttestation(initiator_attestation).ok === expect.valid.', initiatorVectors);
write('consumption-proof.v1.json', 'EP-SMT-CONSUME-v1',
  'Sparse-Merkle-over-nonce one-time consumption. valid iff verifyConsumptionProof(consumption_proof).valid === expect.valid.', consumptionVectors);
write('witness.v1.json', 'EP-WITNESS-v1',
  'Witness cosignature k-of-n quorum (seeded Ed25519; JS and Python verify the SAME committed bytes). valid iff requireWitnessQuorum(witness_quorum.checkpoint, witness_quorum.cosignatures, witness_quorum.pinned, witness_quorum.k).ok === expect.valid.', witnessVectors);
