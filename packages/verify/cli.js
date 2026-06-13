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
  verifyTrustReceipt,
} from './index.js';

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`@emilia-protocol/verify — offline verification, no EP server required.

Usage:
  npx @emilia-protocol/verify <file.json> [more.json…]

Accepts: EP-RECEIPT-v1 receipts, EP-BUNDLE-v1 bundles, EP-PROOF-v1 commitment
proofs, Class-A WebAuthn device signoffs ({ context, webauthn, … }), and I-D
§6.2 authorization receipts ({ contexts, signoffs, log_proof, … }).
Self-contained evidence packets embed their public key; otherwise pass
--key <base64url-spki> to supply it. For §6.2 receipts, pass the issuer's
public material with --verification <verification.json>.

For a §6.2 receipt carrying a PIP-007 initiator escalation attestation, the
advisory report (present / consistent across contexts / any §1 issues) is
printed beneath the cryptographic checks. It never affects whether the receipt
verifies.

Exit code 0 = every document verified; 1 = any failure.`);
  process.exit(args.length === 0 ? 1 : 0);
}

let suppliedKey = null;
let verificationPath = null;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--key') suppliedKey = args[++i];
  else if (args[i] === '--verification') verificationPath = args[++i];
  else files.push(args[i]);
}

// PIP-007 §2 advisory: print the attestation report when a result carries one.
function printAttestationAdvisory(attestation) {
  if (!attestation || !attestation.present) return;
  console.log(`  attestation: present, ${attestation.consistent ? 'consistent across contexts' : 'INCONSISTENT across contexts'}`);
  for (const issue of attestation.issues || []) {
    console.log(`    advisory: ${issue}`);
  }
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
  } else if (Array.isArray(doc?.contexts) && Array.isArray(doc?.signoffs)) {
    // I-D §6.2 authorization receipt (the shape @emilia-protocol/issue emits).
    kind = 'authorization receipt (§6.2)';
    let verification = null;
    if (verificationPath) {
      try {
        verification = JSON.parse(readFileSync(verificationPath, 'utf8'));
      } catch (err) {
        result = { valid: false, error: `--verification not readable JSON (${err.message})` };
      }
    }
    if (!result) {
      if (verification?.approver_keys && verification?.log_public_key) {
        result = verifyTrustReceipt(doc, {
          approverKeys: verification.approver_keys,
          logPublicKey: verification.log_public_key,
        });
      } else {
        result = { valid: false, error: 'a §6.2 receipt needs --verification <verification.json> (approver_keys + log_public_key)' };
      }
    }
  } else {
    console.error(`✕ ${file}: unrecognized document (expected EP receipt, bundle, proof, device signoff, or §6.2 authorization receipt)`);
    allValid = false;
    continue;
  }

  const ok = result.valid === true;
  allValid = allValid && ok;
  console.log(`${ok ? '✅ VERIFIED' : '⛔ NOT VERIFIED'} — ${kind} — ${file}`);
  printChecks(result.checks);
  printAttestationAdvisory(result.attestation);
  if (!ok && result.error) console.log(`  reason: ${result.error}`);
  if (kind === 'bundle' && typeof result.verified === 'number') {
    console.log(`  ${result.verified}/${result.total} documents verified`);
  }
}

process.exit(allValid ? 0 : 1);
