/* eslint-disable no-console */
/**
 * EMILIA Protocol — CI receipt verifier.
 * @license Apache-2.0
 *
 * Offline-verifies an EP-RECEIPT-v1 Trust Receipt using @emilia-protocol/verify.
 * Reads config from env (set by action.yml): EP_RECEIPT (required),
 * EP_PUBLIC_KEY (optional), EP_KEYS_URL (fallback key source).
 *
 * Exit codes: 0 verified · 1 verification failed · 2 usage/config error.
 */

import { readFileSync } from 'node:fs';
import process from 'node:process';

const receiptPath = process.env.EP_RECEIPT;
const explicitKey = (process.env.EP_PUBLIC_KEY || '').trim();
const keysUrl = process.env.EP_KEYS_URL || 'https://www.emiliaprotocol.ai/.well-known/ep-keys.json';

function fail(code, msg) {
  console.error(`::error::${msg}`);
  process.exit(code);
}

if (!receiptPath) fail(2, 'receipt input is required (path to an EP-RECEIPT-v1 JSON file).');

const { verifyReceipt } = await import('@emilia-protocol/verify');

let receipt;
try {
  receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
} catch (e) {
  fail(2, `Cannot read receipt at ${receiptPath}: ${e.message}`);
}

// Recursively collect base64url-looking strings — schema-agnostic so the action
// keeps working if the published key-set format changes.
function collectKeys(node, out = []) {
  if (typeof node === 'string') {
    if (/^[A-Za-z0-9_-]{40,}$/.test(node)) out.push(node);
  } else if (Array.isArray(node)) {
    for (const v of node) collectKeys(v, out);
  } else if (node && typeof node === 'object') {
    for (const v of Object.values(node)) collectKeys(v, out);
  }
  return out;
}

let candidates = [];
if (explicitKey) {
  candidates = [explicitKey];
} else {
  try {
    const res = await fetch(keysUrl);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    candidates = [...new Set(collectKeys(await res.json()))];
  } catch (e) {
    fail(2, `Could not fetch keys from ${keysUrl}: ${e.message}. Pass public-key explicitly.`);
  }
}
if (candidates.length === 0) fail(2, 'No public keys available to verify against.');

let result = null;
for (const key of candidates) {
  try {
    const r = verifyReceipt(receipt, key);
    if (r && r.valid) { result = r; break; }
    if (!result) result = r;
  } catch {
    // try the next candidate key
  }
}

if (result && result.valid) {
  console.log('✅ EMILIA Trust Receipt verified.');
  console.log(JSON.stringify(result.checks ?? {}, null, 2));
  process.exit(0);
}
console.error('::error::❌ Trust Receipt verification FAILED.');
console.error(JSON.stringify(result ?? { valid: false }, null, 2));
process.exit(1);
