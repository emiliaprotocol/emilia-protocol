#!/usr/bin/env node

/**
 * EP Conformance Test Suite — The Acid Test for Trust
 *
 * Tests whether an EP operator implementation conforms to EP Core v1.0.
 * Any operator that passes all required checks can interoperate with
 * any other conformant operator via self-verifying receipts.
 *
 * Usage:
 *   npx ep-conformance-test https://ep.example.com
 *   node ep-conformance-test.js https://ep.example.com
 *
 * Checks:
 *   [REQUIRED] /.well-known/ep-trust.json discovery
 *   [REQUIRED] /.well-known/ep-keys.json key publication
 *   [REQUIRED] Trust Receipt format (EP-RECEIPT-v1)
 *   [REQUIRED] Ed25519 signature on receipts
 *   [REQUIRED] Trust Profile schema compliance
 *   [REQUIRED] Trust Decision schema compliance
 *   [OPTIONAL] Handshake extension (PIP-002)
 *   [OPTIONAL] Merkle anchor proof
 *
 * Exit codes:
 *   0 = all required checks pass (CONFORMANT)
 *   1 = one or more required checks fail (NON-CONFORMANT)
 *   2 = connection error
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

const baseUrl = process.argv[2];
if (!baseUrl) {
  console.error('Usage: ep-conformance-test <base-url>');
  console.error('Example: ep-conformance-test https://ep.example.com');
  process.exit(2);
}

const results = [];
let passed = 0;
let failed = 0;
let skipped = 0;

function check(name, required, ok, detail) {
  const status = ok ? 'PASS' : (required ? 'FAIL' : 'SKIP');
  const icon = ok ? '\u2713' : (required ? '\u2717' : '-');
  results.push({ name, required, status, detail });
  if (ok) passed++;
  else if (required) failed++;
  else skipped++;
  console.log(`  ${icon} ${name}${detail ? ` — ${detail}` : ''}`);
}

async function fetchJSON(path) {
  const url = new URL(path, baseUrl).toString();
  const res = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) return { _error: `HTTP ${res.status}`, _status: res.status };
  return res.json();
}

console.log(`
  EP Conformance Test Suite v1.0
  Testing: ${baseUrl}
  ────────────────────────────────
`);

try {
  // ═══════════════════════════════════════════════════════════════
  // CHECK 1: /.well-known/ep-trust.json
  // ═══════════════════════════════════════════════════════════════
  const trust = await fetchJSON('/.well-known/ep-trust.json');
  const hasTrust = !trust._error && trust.version && trust.protocol_version;
  check('Discovery (/.well-known/ep-trust.json)', true, hasTrust,
    hasTrust ? `operator: ${trust.operator_id}, protocol: ${trust.protocol_version}` : trust._error);

  // ═══════════════════════════════════════════════════════════════
  // CHECK 2: /.well-known/ep-keys.json
  // ═══════════════════════════════════════════════════════════════
  const keys = await fetchJSON('/.well-known/ep-keys.json');
  const hasKeys = !keys._error && keys.version && keys.keys && typeof keys.keys === 'object';
  const keyCount = hasKeys ? Object.keys(keys.keys).length : 0;
  check('Key publication (/.well-known/ep-keys.json)', true, hasKeys,
    hasKeys ? `${keyCount} public key(s) published` : (keys._error || 'Invalid format'));

  // ═══════════════════════════════════════════════════════════════
  // CHECK 3: Entity registration
  // ═══════════════════════════════════════════════════════════════
  const entity = await fetchJSON('/api/entity');
  // POST to register — use the base endpoint
  let testEntity = null;
  try {
    const regRes = await fetch(new URL('/api/entity', baseUrl).toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'ep_conformance_test_entity' }),
      signal: AbortSignal.timeout(10_000),
    });
    if (regRes.ok) testEntity = await regRes.json();
  } catch { /* entity creation may not be public */ }
  check('Entity registration', true, !!testEntity?.entity_id,
    testEntity?.entity_id ? `entity: ${testEntity.entity_id}` : 'Entity creation endpoint unavailable or failed');

  // ═══════════════════════════════════════════════════════════════
  // CHECK 4: Trust Receipt format (EP-RECEIPT-v1)
  // ═══════════════════════════════════════════════════════════════
  let testReceipt = null;
  if (testEntity) {
    try {
      // Create a second entity for receipt target
      const entity2Res = await fetch(new URL('/api/entity', baseUrl).toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'ep_conformance_test_subject' }),
        signal: AbortSignal.timeout(10_000),
      });
      const entity2 = entity2Res.ok ? await entity2Res.json() : null;

      if (entity2) {
        const receiptRes = await fetch(new URL('/api/receipt', baseUrl).toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ issuer: testEntity.entity_id, subject: entity2.entity_id, outcome: 'positive', action_type: 'conformance_test' }),
          signal: AbortSignal.timeout(10_000),
        });
        if (receiptRes.ok) testReceipt = await receiptRes.json();
      }
    } catch { /* receipt creation may require auth */ }
  }

  const hasReceiptFormat = testReceipt &&
    testReceipt['@version'] === 'EP-RECEIPT-v1' &&
    testReceipt.payload?.receipt_id &&
    testReceipt.payload?.issuer &&
    testReceipt.payload?.subject &&
    testReceipt.payload?.claim &&
    testReceipt.payload?.created_at;

  check('Trust Receipt format (EP-RECEIPT-v1)', true, hasReceiptFormat,
    hasReceiptFormat ? `receipt: ${testReceipt.payload.receipt_id}` : 'Receipt format does not match EP-RECEIPT-v1 schema');

  // ═══════════════════════════════════════════════════════════════
  // CHECK 5: Ed25519 signature on receipts
  // ═══════════════════════════════════════════════════════════════
  let sigValid = false;
  if (hasReceiptFormat && testReceipt.signature?.algorithm === 'Ed25519' && testReceipt.signature?.value) {
    try {
      // Get the signer's public key
      const signerKeys = await fetchJSON('/.well-known/ep-keys.json');
      const signerKey = signerKeys?.keys?.[testReceipt.signature.signer]?.public_key;

      if (signerKey) {
        const payloadBytes = Buffer.from(JSON.stringify(testReceipt.payload, Object.keys(testReceipt.payload).sort()), 'utf8');
        const keyDer = Buffer.from(signerKey, 'base64url');
        const keyObject = crypto.createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
        const sigBytes = Buffer.from(testReceipt.signature.value, 'base64url');
        sigValid = crypto.verify(null, payloadBytes, keyObject, sigBytes);
      }
    } catch { /* sig check failed */ }
  }
  check('Ed25519 receipt signature', true, sigValid,
    sigValid ? 'Signature verified against published public key' : 'Signature verification failed or key not discoverable');

  // ═══════════════════════════════════════════════════════════════
  // CHECK 6: Trust Profile schema
  // ═══════════════════════════════════════════════════════════════
  let hasProfile = false;
  if (testEntity) {
    const profile = await fetchJSON(`/api/trust?entity_id=${testEntity.entity_id}`);
    hasProfile = !profile._error &&
      profile.entity_id &&
      typeof profile.score === 'number' &&
      typeof profile.confidence === 'string' &&
      typeof profile.evidence_depth === 'number';
    check('Trust Profile schema', true, hasProfile,
      hasProfile ? `score: ${profile.score}, confidence: ${profile.confidence}` : 'Profile schema incomplete or endpoint unavailable');
  } else {
    check('Trust Profile schema', true, false, 'Skipped — no test entity available');
  }

  // ═══════════════════════════════════════════════════════════════
  // CHECK 7: Trust Decision schema
  // ═══════════════════════════════════════════════════════════════
  // Trust Decision is typically returned by /api/trust/evaluate
  let hasDecision = false;
  try {
    const decisionRes = await fetch(new URL('/api/trust/evaluate', baseUrl).toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: testEntity?.entity_id || 'ep_entity_test', policy: 'standard' }),
      signal: AbortSignal.timeout(10_000),
    });
    if (decisionRes.ok) {
      const decision = await decisionRes.json();
      hasDecision = decision.decision && ['allow', 'review', 'deny'].includes(decision.decision);
    }
  } catch { /* evaluate may require auth */ }
  check('Trust Decision schema', true, hasDecision,
    hasDecision ? 'Returns allow/review/deny decision' : 'Decision endpoint unavailable or non-conformant');

  // ═══════════════════════════════════════════════════════════════
  // OPTIONAL: Handshake extension (PIP-002)
  // ═══════════════════════════════════════════════════════════════
  let hasHandshake = false;
  const extensions = hasTrust ? (trust.extensions || []) : [];
  if (extensions.includes('handshake')) {
    try {
      const hsRes = await fetch(new URL('/api/handshake', baseUrl).toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initiator: testEntity?.entity_id || 'test', action_type: 'conformance_test', resource_ref: 'test/resource' }),
        signal: AbortSignal.timeout(10_000),
      });
      if (hsRes.ok) {
        const hs = await hsRes.json();
        hasHandshake = hs.handshake_id && hs.binding_hash && hs.binding?.nonce;
      }
    } catch { /* handshake may require auth */ }
  }
  check('Handshake extension (PIP-002)', false, hasHandshake,
    hasHandshake ? 'Handshake ceremony functional' : (extensions.includes('handshake') ? 'Declared but failed' : 'Not declared'));

  // ═══════════════════════════════════════════════════════════════
  // OPTIONAL: Merkle anchor proof
  // ═══════════════════════════════════════════════════════════════
  const hasAnchor = testReceipt?.anchor?.merkle_root && testReceipt?.anchor?.merkle_proof;
  check('Merkle anchor proof', false, hasAnchor,
    hasAnchor ? `chain: ${testReceipt.anchor.chain}` : 'No anchor data in receipt');

} catch (err) {
  console.error(`\n  Connection error: ${err.message}`);
  process.exit(2);
}

// ═══════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════
const requiredTotal = results.filter(r => r.required).length;
const requiredPassed = results.filter(r => r.required && r.status === 'PASS').length;
const conformant = failed === 0;

console.log(`
  ────────────────────────────────
  Results: ${passed} passed, ${failed} failed, ${skipped} skipped
  Required: ${requiredPassed}/${requiredTotal} passed

  ${conformant ? 'CONFORMANT: EP Core v1.0' : 'NON-CONFORMANT: ' + failed + ' required check(s) failed'}
  ────────────────────────────────
`);

process.exit(conformant ? 0 : 1);
