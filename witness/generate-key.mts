#!/usr/bin/env node
/**
 * EP Witness — key generation.
 *
 * Generates one Ed25519 keypair for a witness cosigner and writes:
 *   - witness-private.pem   PKCS8 PEM (the SECRET; keep it off the checkpoint path)
 *   - witness-public.json   { witness_id, public_key, alg } for relying parties to PIN
 *
 * The public key is base64url-encoded SPKI DER, byte-identical to the encoding
 * @emilia-protocol/verify expects (crypto.verify(null, ...) over an SPKI key).
 * The witness_id is a stable, self-certifying id derived from the public key:
 *   "witness:sha256:<first 16 hex of SHA-256(SPKI DER)>"
 * so anyone holding the public key can recompute and confirm the id.
 *
 * Usage:
 *   node generate-key.mjs [outDir]        # defaults to ./keys
 *
 * The server never hardcodes a key: it loads the private key from
 * WITNESS_PRIVATE_KEY (PEM literal) or WITNESS_PRIVATE_KEY_FILE (path), and the
 * public/id from WITNESS_PUBLIC_FILE (defaults to <keydir>/witness-public.json).
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function deriveWitnessId(publicKeySpkiB64u) {
  const der = Buffer.from(publicKeySpkiB64u, 'base64url');
  const h = crypto.createHash('sha256').update(der).digest('hex');
  return `witness:sha256:${h.slice(0, 16)}`;
}

export function generateWitnessKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const witness_id = deriveWitnessId(publicKeyB64u);
  return { privatePem, publicKeyB64u, witness_id };
}

function main() {
  const outDir = process.argv[2] || path.join(process.cwd(), 'keys');
  fs.mkdirSync(outDir, { recursive: true });

  const privPath = path.join(outDir, 'witness-private.pem');
  const pubPath = path.join(outDir, 'witness-public.json');
  if (fs.existsSync(privPath)) {
    console.error(`Refusing to overwrite existing private key at ${privPath}.`);
    console.error('Remove it deliberately if you really mean to rotate the witness identity.');
    process.exit(1);
  }

  const { privatePem, publicKeyB64u, witness_id } = generateWitnessKey();

  fs.writeFileSync(privPath, privatePem, { mode: 0o600 });
  const publicRecord = { alg: 'EP-WITNESS-v1', witness_id, public_key: publicKeyB64u };
  fs.writeFileSync(pubPath, JSON.stringify(publicRecord, null, 2) + '\n');

  console.log('Witness keypair generated.');
  console.log(`  private key : ${privPath}   (mode 0600, KEEP SECRET)`);
  console.log(`  public info : ${pubPath}`);
  console.log(`  witness_id  : ${witness_id}`);
  console.log('');
  console.log('Pin this witness at relying parties with witness-public.json.');
}

// Run only when invoked directly (not when imported by the server).
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
