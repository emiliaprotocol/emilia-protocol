#!/usr/bin/env node
/**
 * ep-verify — verify one EP authorization receipt (EP-RECEIPT-v1) offline.
 * @license Apache-2.0
 *
 * Usage:
 *   ep-verify <receipt.json> [--keys keys.json]
 *
 * Prints two lines: `VERIFIED` or `REFUSED`, then one JSON line with a
 * machine-readable `reason` and the individual checks. Exit code 0 only on
 * VERIFIED; anything else — unreadable file, malformed JSON, missing keys,
 * failed check, internal error — exits 1. Fail closed by construction.
 *
 * The verifier never trusts a key that travels inside the receipt: without
 * `--keys` (the issuer public key(s) YOU pin) the answer is always REFUSED
 * with reason `no_pinned_keys`. An inline key would prove integrity (the
 * document was not altered), not trust (who signed it).
 *
 * Honest boundary: VERIFIED means the Ed25519 signature over the canonical
 * payload verifies against a pinned key, and — if an anchor is present — the
 * EP-MERKLE-v2 inclusion proof reconstructs the claimed root. It says nothing
 * about whether the authorized action was appropriate, lawful, or wise, and it
 * is not a revocation or freshness check.
 */
import { readFileSync } from 'node:fs';

// Prefer the published sibling package; fall back to the in-repo source so the
// monorepo test/build works without a node_modules link (same resolution
// pattern as packages/gate/index.js).
const { verifyReceipt } = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));

const USAGE = 'usage: ep-verify <receipt.json> [--keys keys.json]';

function emit(result, detail) {
  process.stdout.write(`${result}\n${JSON.stringify({ result, ...detail })}\n`);
  process.exitCode = result === 'VERIFIED' ? 0 : 1;
}

function refuse(reason, detail = {}) {
  emit('REFUSED', { reason, ...detail });
}

/** Normalize a pinned-keys document to an array of base64url SPKI strings. */
function normalizeKeys(k) {
  if (typeof k === 'string') return k.length > 0 ? [k] : [];
  if (Array.isArray(k)) {
    return k
      .map((e) => (typeof e === 'string' ? e : e && typeof e === 'object' ? e.public_key : null))
      .filter((s) => typeof s === 'string' && s.length > 0);
  }
  if (k && typeof k === 'object') {
    const arr = k.keys ?? k.issuer_keys ?? k.trusted_keys;
    if (arr !== undefined) return normalizeKeys(arr);
    if (typeof k.public_key === 'string') return [k.public_key];
  }
  return [];
}

function run() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`${USAGE}

Verifies one EP-RECEIPT-v1 document fully offline against issuer public
key(s) you pin. keys.json is a base64url SPKI string, an array of them,
or { "keys": [...] }. Without --keys the result is always REFUSED
(no_pinned_keys) — a key inside the receipt proves integrity, not trust.

Output: line 1 is VERIFIED or REFUSED; line 2 is machine-readable JSON
({ result, reason, checks, ... }). Exit 0 only on VERIFIED.
`);
    return;
  }

  let receiptPath = null;
  let keysPath = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--keys') {
      keysPath = args[++i];
      if (keysPath === undefined) return refuse('usage_error', { error: `--keys requires a path. ${USAGE}` });
    } else if (receiptPath === null) {
      receiptPath = args[i];
    } else {
      return refuse('usage_error', { error: `unexpected argument: ${args[i]}. ${USAGE}` });
    }
  }
  if (!receiptPath) return refuse('usage_error', { error: USAGE });

  let rawReceipt;
  try {
    rawReceipt = readFileSync(receiptPath, 'utf8');
  } catch (e) {
    return refuse('unreadable_receipt', { error: e.message });
  }
  let doc;
  try {
    doc = JSON.parse(rawReceipt);
  } catch (e) {
    return refuse('malformed_json', { error: e.message });
  }

  if (!keysPath) {
    return refuse('no_pinned_keys', {
      error: 'ep-verify never trusts a key that travels inside the receipt; pass --keys keys.json with the issuer key(s) you pin',
    });
  }
  let rawKeys;
  try {
    rawKeys = readFileSync(keysPath, 'utf8');
  } catch (e) {
    return refuse('unreadable_keys', { error: e.message });
  }
  let keysDoc;
  try {
    keysDoc = JSON.parse(rawKeys);
  } catch (e) {
    return refuse('malformed_keys', { error: e.message });
  }
  const keys = normalizeKeys(keysDoc);
  if (keys.length === 0) {
    return refuse('no_pinned_keys', { error: 'keys.json contained no usable base64url SPKI public key' });
  }

  let last = null;
  for (const key of keys) {
    let r;
    try {
      r = verifyReceipt(doc, key);
    } catch (e) {
      r = { valid: false, checks: null, error: `verifier threw: ${e.message}` };
    }
    if (r && r.valid === true) {
      return emit('VERIFIED', {
        reason: 'signature_verified_against_pinned_key',
        receipt_id: doc?.payload?.receipt_id ?? null,
        checks: r.checks ?? null,
      });
    }
    last = r;
  }

  // Map the library's failure to one machine-readable refusal reason.
  const err = String(last?.error ?? '');
  let reason = 'signature_invalid';
  if (/unsupported version/i.test(err)) reason = 'unsupported_version';
  else if (/missing payload or signature/i.test(err)) reason = 'not_a_receipt';
  else if (/canonicalization profile/i.test(err)) reason = 'outside_canonicalization_profile';
  else if (last?.checks?.signature === true && last?.checks?.anchor === false) reason = 'anchor_invalid';
  return refuse(reason, {
    receipt_id: doc?.payload?.receipt_id ?? null,
    error: last?.error ?? null,
    checks: last?.checks ?? null,
  });
}

try {
  run();
} catch (e) {
  // Fail closed on ANY unexpected error: never exit 0 without a VERIFIED line.
  refuse('internal_error', { error: String(e?.message ?? e) });
}
