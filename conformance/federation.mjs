// SPDX-License-Identifier: Apache-2.0
// Generated from federation.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// PIP-006 Federation — cross-operator conformance harness.
//
// Two parts:
//
//   1. SELF-CONTAINED cross-redemption proof (always runs, deterministic).
//      Generates two independent operators, has Operator A issue a genuine
//      EP-RECEIPT-v1, and proves Operator B verifies it using only A's
//      published discovery surface — plus the negative cases (tamper, wrong
//      key, revocation). This is the executable form of PIP-006 acceptance
//      gate #1, run against a self-hosted second operator.
//
//   2. LIVE primary probe (best-effort). Fetches the deployed primary
//      operator's /.well-known/ep-keys.json and asserts it is a PIP-006-
//      conformant federation surface that a relying party can consume. Proves
//      the contract is live, not just specified. Skipped cleanly if offline.
//
//   node conformance/federation.mjs [https://base.url]
//
// Exit 1 if the self-contained proof fails. The live probe is advisory — a
// network failure does not fail the harness (it is reported as SKIP).
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { resolveOperatorKeys, verifyFederatedReceiptOffline, } from '../packages/verify/federation.js';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
void root;
// ── canonicalize: must match packages/verify/index.js ────────────────────────
function canonicalize(value) {
    if (value === null || value === undefined)
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',')}}`;
    }
    return JSON.stringify(value);
}
function makeOperator(operatorId) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
        operatorId, privateKey,
        publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function issueReceipt(op, payload, signingKey) {
    const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), signingKey || op.privateKey);
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { signer: op.operatorId, key_discovery: `https://${op.operatorId}.example/.well-known/ep-keys.json`, algorithm: 'Ed25519', value: sig.toString('base64url') },
    };
}
function discoveryDoc(op, historical = []) {
    const doc = { version: '1.1', operator_id: op.operatorId, keys: { [op.operatorId]: { public_key: op.publicKeyB64u, algorithm: 'Ed25519' } } };
    if (historical.length)
        doc.historical_keys = { [op.operatorId]: historical.map((h) => ({ public_key: h.publicKeyB64u, algorithm: 'Ed25519', retired_at: '2026-01-01T00:00:00Z' })) };
    return doc;
}
let failures = 0;
function check(name, cond) {
    const ok = Boolean(cond);
    if (!ok)
        failures++;
    console.log(`  ${ok ? '✓' : '✗'} ${name}`);
    return ok;
}
// Live-surface checks are advisory: a deploy in flight, version drift, or a
// network blip must not fail the deterministic protocol proof. Reported, not
// gated.
let liveWarnings = 0;
function checkLive(name, cond) {
    const ok = Boolean(cond);
    if (!ok)
        liveWarnings++;
    console.log(`  ${ok ? '✓' : '⚠'} ${name}`);
    return ok;
}
console.log('\nPIP-006 Federation — cross-operator conformance\n');
console.log('Part 1 — self-hosted second operator (deterministic):');
// Two independent operators. B never receives A's private key.
const A = makeOperator('ep_operator_a');
const B = makeOperator('ep_operator_b');
void B;
// 1. Valid cross-redemption.
const r1 = issueReceipt(A, { receipt_id: 'fed_001', '@version': 'EP-RECEIPT-v1', amount: 82000, currency: 'USD' });
// B pins A's operator id out-of-band (PIP-006: trust comes from the relying
// party's allowlist, never from the receipt-carried signer). Without a pin a
// cryptographically-valid receipt stays accepted:false — fail closed. Offline,
// a bare-id pin suffices because the discovery doc is supplied by the relying
// party (its own trust source), not fetched from a receipt-controlled URL.
check('B accepts a valid receipt issued by A (bare-id pin, caller-supplied doc)', verifyFederatedReceiptOffline(r1, discoveryDoc(A), { trustedIssuers: ['ep_operator_a'] }).accepted === true);
// Stronger: B also pins A's KEY SOURCE (expected discovery origin + public key).
// The matched key must be the pinned key, or acceptance fails closed. This is
// the pin shape a relying party uses online, where key_discovery is receipt-
// controlled and pinning the id alone cannot authenticate the key origin.
const r1b = issueReceipt(A, { receipt_id: 'fed_001b', '@version': 'EP-RECEIPT-v1', amount: 82000, currency: 'USD' });
const pinnedA = { ep_operator_a: { key_discovery: `https://ep_operator_a.example/.well-known/ep-keys.json`, publicKey: A.publicKeyB64u } };
check('B accepts under a key-SOURCE pin (origin + pinned public key)', verifyFederatedReceiptOffline(r1b, discoveryDoc(A), { trustedIssuers: pinnedA }).accepted === true);
// And refuses when the discovery doc advertises a DIFFERENT key under A's id
// (the trust-laundering attack): a wrong key can never be the pinned key.
const laundered = discoveryDoc(makeOperator('ep_operator_a')); // same id, attacker key
check('B refuses a laundered key that is not the pinned key', verifyFederatedReceiptOffline(r1b, laundered, { trustedIssuers: pinnedA }).accepted === false);
// 2. Tamper rejection.
const r2 = issueReceipt(A, { receipt_id: 'fed_002', '@version': 'EP-RECEIPT-v1', amount: 82000, currency: 'USD' });
r2.payload.amount = 1;
check('B rejects a tampered payload', verifyFederatedReceiptOffline(r2, discoveryDoc(A)).accepted === false);
// 3. Wrong-operator key rejection.
const imposter = makeOperator('ep_operator_a');
const r3 = issueReceipt(A, { receipt_id: 'fed_003', '@version': 'EP-RECEIPT-v1', amount: 5 });
check('B rejects a receipt against the wrong key', verifyFederatedReceiptOffline(r3, discoveryDoc(imposter)).accepted === false);
// 4. Key rotation: historical key still verifies a pre-rotation receipt.
const oldPair = crypto.generateKeyPairSync('ed25519');
const oldOp = { operatorId: 'ep_operator_a', privateKey: oldPair.privateKey, publicKeyB64u: oldPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
const Anew = makeOperator('ep_operator_a');
const r4 = issueReceipt(oldOp, { receipt_id: 'fed_004', '@version': 'EP-RECEIPT-v1', amount: 7 }, oldPair.privateKey);
const v4 = verifyFederatedReceiptOffline(r4, discoveryDoc(Anew, [oldOp]), { trustedIssuers: ['ep_operator_a'] });
check('B verifies a pre-rotation receipt against an advertised historical key', v4.accepted === true && v4.keyMatched === 'historical');
// 5. Revocation: valid signature, but not accepted.
const r5 = issueReceipt(A, { receipt_id: 'fed_005', '@version': 'EP-RECEIPT-v1', amount: 9 });
const v5 = verifyFederatedReceiptOffline(r5, discoveryDoc(A), { revokedReceiptIds: new Set(['fed_005']), trustedIssuers: ['ep_operator_a'] });
check('B rejects a revoked receipt (verified but not accepted)', v5.verified === true && v5.accepted === false);
// 6. Non-federated receipt (no signer).
const r6 = issueReceipt(A, { receipt_id: 'fed_006', '@version': 'EP-RECEIPT-v1', amount: 2 });
delete r6.signature.signer;
check('B rejects a receipt with no signature.signer', verifyFederatedReceiptOffline(r6, discoveryDoc(A)).verified === false);
// ── Part 2 — live primary probe ──────────────────────────────────────────────
const base = process.argv[2] || 'https://www.emiliaprotocol.ai';
console.log(`\nPart 2 — live primary federation surface (${base}) [advisory]:`);
async function liveProbe() {
    if (typeof fetch === 'undefined') {
        console.log('  ⊘ SKIP — no fetch available');
        return;
    }
    let doc;
    try {
        const res = await fetch(`${base}/.well-known/ep-keys.json`, { signal: AbortSignal.timeout(8000) });
        if (!res.ok) {
            console.log(`  ⊘ SKIP — ep-keys.json returned HTTP ${res.status}`);
            return;
        }
        doc = await res.json();
    }
    catch (e) {
        console.log(`  ⊘ SKIP — could not reach primary (${e.message})`);
        return;
    }
    // Advisory: if the surface is reachable, it SHOULD be conformant. Drift here
    // (e.g. a deploy still rolling out) is a warning, not a harness failure.
    checkLive('ep-keys.json advertises a keys map', doc && typeof doc.keys === 'object');
    checkLive('ep-keys.json declares a verify_url_template (verifier-of-record)', typeof doc.verify_url_template === 'string' && doc.verify_url_template.includes('/api/verify/'));
    checkLive('ep-keys.json exposes historical_keys (rotation surface)', doc.historical_keys !== undefined);
    const signers = Object.keys(doc.keys || {});
    if (signers.length) {
        const resolved = resolveOperatorKeys(doc, signers[0]);
        checkLive('a relying party can resolve a live operator key', resolved.length >= 1 && resolved[0].status === 'current');
    }
    else {
        console.log('  ℹ primary advertises no signing keys yet (empty registry) — surface still conformant');
    }
}
await liveProbe();
console.log('');
if (failures > 0) {
    console.log(`✗ FAIL — ${failures} deterministic federation check(s) failed\n`);
    process.exit(1);
}
if (liveWarnings > 0) {
    console.log(`✓ PASS (cross-operator redemption verified) — ${liveWarnings} live-surface advisory warning(s); the deployed primary may be mid-rollout. Re-run after deploy.\n`);
}
else {
    console.log('✓ PASS — cross-operator redemption verified; primary publishes a conformant federation surface\n');
}
