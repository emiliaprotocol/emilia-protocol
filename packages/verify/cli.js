#!/usr/bin/env node
/**
 * @emilia-protocol/verify — CLI.
 * @license Apache-2.0
 *
 * `npx @emilia-protocol/verify receipt.json [more.json…]`
 *
 * Auto-detects the document kind (EP-RECEIPT-v1, EP-BUNDLE-v1, EP-PROOF-v1, or
 * a Class-A WebAuthn device signoff), runs the matching verifier from index.js,
 * prints every check, and exits 0 only if every document verifies. Fully
 * offline — the same guarantee as the library.
 */
import { readFileSync } from 'node:fs';
import {
  verifyReceipt,
  verifyReceiptBundle,
  verifyCommitmentProof,
  verifyWebAuthnSignoff,
} from './index.js';

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`@emilia-protocol/verify — offline verification, no EP server required.

Usage:
  npx @emilia-protocol/verify <file.json> [more.json…]

Accepts: EP-RECEIPT-v1 receipts, EP-BUNDLE-v1 bundles, EP-PROOF-v1 commitment
proofs, and Class-A WebAuthn device signoffs ({ context, webauthn, … }).
Self-contained evidence packets embed their public key; otherwise pass
--key <base64url-spki> to supply it.

Exit code 0 = every document verified; 1 = any failure.`);
  process.exit(args.length === 0 ? 1 : 0);
}

let suppliedKey = null;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--key') suppliedKey = args[++i];
  else files.push(args[i]);
}

function findKey(doc, names) {
  for (const n of names) {
    if (typeof doc?.[n] === 'string') return doc[n];
    if (typeof doc?.context?.[n] === 'string') return doc.context[n];
    if (typeof doc?.signer?.[n] === 'string') return doc.signer[n];
  }
  return suppliedKey;
}

function printChecks(checks) {
  for (const [k, v] of Object.entries(checks || {})) {
    if (v === null || v === undefined) continue;
    console.log(`  ${v === true ? '✓' : '✕'} ${k}`);
  }
}

let allValid = true;

for (const file of files) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`✕ ${file}: not readable JSON (${err.message})`);
    allValid = false;
    continue;
  }

  let kind = null;
  let result = null;

  if (doc?.['@version'] === 'EP-BUNDLE-v1') {
    kind = 'bundle';
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    result = key
      ? verifyReceiptBundle(doc, key)
      : { valid: false, error: 'no embedded public key — pass --key' };
  } else if (doc?.['@version'] === 'EP-RECEIPT-v1') {
    kind = 'receipt';
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    result = key
      ? verifyReceipt(doc, key)
      : { valid: false, error: 'no embedded public key — pass --key' };
  } else if (doc?.['@version'] === 'EP-PROOF-v1') {
    kind = 'commitment proof';
    result = verifyCommitmentProof(doc, findKey(doc, ['public_key', 'publicKey', 'entity_public_key']));
  } else if (doc?.context && doc?.webauthn) {
    kind = 'Class-A device signoff';
    const key = findKey(doc, ['approver_public_key', 'public_key', 'publicKey']);
    const rpId = doc.rp_id || doc.context?.rp_id || undefined;
    result = key
      ? verifyWebAuthnSignoff(doc, key, rpId ? { rpId } : {})
      : { valid: false, error: 'no embedded approver public key — pass --key' };
  } else {
    console.error(`✕ ${file}: unrecognized document (expected EP receipt, bundle, proof, or device signoff)`);
    allValid = false;
    continue;
  }

  const ok = result.valid === true;
  allValid = allValid && ok;
  console.log(`${ok ? '✅ VERIFIED' : '⛔ NOT VERIFIED'} — ${kind} — ${file}`);
  printChecks(result.checks);
  if (!ok && result.error) console.log(`  reason: ${result.error}`);
  if (kind === 'bundle' && typeof result.verified === 'number') {
    console.log(`  ${result.verified}/${result.total} documents verified`);
  }
}

process.exit(allValid ? 0 : 1);
