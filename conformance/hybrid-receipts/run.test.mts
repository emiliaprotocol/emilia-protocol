// SPDX-License-Identifier: Apache-2.0
//
// Executes conformance/hybrid-receipts/vectors.json end to end:
//   - every vector is run through verifyHybridReceipt and must produce the
//     EXACT recorded verdict, reason, and attributed algorithm;
//   - the recorded EP-RECEIPT-v1 verifier behaviour is re-derived by running
//     packages/verify's verifyReceipt, so the documented refusal is a captured
//     result and not a claim about one;
//   - the whole file is regenerated in a subprocess and compared byte for
//     byte, so "deterministic vectors" is executed rather than asserted.
//
// The suite FAILS LOUDLY if the ML-DSA backend is missing. A skipped
// post-quantum suite would prove nothing about a post-quantum profile.

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  HYBRID_RECEIPT_PROFILE,
  HYBRID_RECEIPT_REASONS,
  hybridSignedBytes,
  loadAgilityModule,
  verifyHybridReceipt,
} from '../../packages/issue/dist/hybrid-issuance.js';
import { verifyReceipt } from '../../packages/verify/index.js';

const here: string = path.dirname(fileURLToPath(import.meta.url));
const root: string = path.resolve(here, '..', '..');
const vectors: any = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));

const verificationKeys = {
  ed25519PublicKey: vectors.keys.Ed25519.public_key,
  ed25519KeyId: vectors.keys.Ed25519.key_id,
  mldsaPublicKey: vectors.keys['ML-DSA-65'].public_key,
  mldsaKeyId: vectors.keys['ML-DSA-65'].key_id,
};

describe('EP-RECEIPT-HYBRID-v1 conformance vectors', () => {
  it('runs against a real ML-DSA-65 backend', async () => {
    const agility = await loadAgilityModule();
    expect(agility, 'EP-SIG-AGILITY-v1 must resolve').toBeTruthy();
    const backend = await import('@noble/post-quantum/ml-dsa.js');
    expect(typeof backend.ml_dsa65.verify).toBe('function');
  });

  it('pins the profile marker and the committed algorithm set', () => {
    expect(vectors.profile).toBe(HYBRID_RECEIPT_PROFILE);
    expect(vectors.required_algorithms).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(vectors.vectors.length).toBeGreaterThan(0);
  });

  it('signs bytes that commit to the profile and the full algorithm set', () => {
    const bytes = hybridSignedBytes(vectors.payload);
    expect(JSON.parse(bytes.toString('utf8'))).toEqual(vectors.signed_material);
    expect(crypto.createHash('sha256').update(bytes).digest('hex')).toBe(vectors.signed_bytes_sha256);
  });

  for (const vector of vectors.vectors as Array<any>) {
    it(`${vector.id}: ${vector.description}`, async () => {
      const result = await verifyHybridReceipt(vector.receipt, verificationKeys);
      expect(result.verified, vector.id).toBe(vector.expect.verified);
      expect(result.reason, vector.id).toBe(vector.expect.reason);
      expect(result.failed_algorithm, vector.id).toBe(vector.expect.failed_algorithm);
    });
  }

  it('names every refusal from the published vocabulary', () => {
    const known = new Set<string>(Object.values(HYBRID_RECEIPT_REASONS));
    for (const vector of vectors.vectors as Array<any>) {
      if (vector.expect.reason === null) continue;
      expect(known.has(vector.expect.reason), `${vector.id} -> ${vector.expect.reason}`).toBe(true);
    }
  });
});

describe('EP-RECEIPT-v1 verifier behaviour on a hybrid receipt', () => {
  const valid = (vectors.vectors as Array<any>).find((v) => v.id === 'hybrid-valid');

  it('refuses the hybrid receipt on the version check, with the recorded reason', () => {
    const result = verifyReceipt(valid.receipt, verificationKeys.ed25519PublicKey);
    expect(result).toEqual(vectors.v1_verifier_behaviour['hybrid-receipt-under-v1-verifier'].result);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(`Unsupported version: ${HYBRID_RECEIPT_PROFILE}`);
    // The clean part: it refused, it did not throw, and it never inspected a
    // signature it could only half check.
    expect(result.checks.signature).toBe(false);
  });

  it('refuses the classical leg repackaged as an EP-RECEIPT-v1 receipt', () => {
    const repackaged = {
      '@version': 'EP-RECEIPT-v1',
      payload: vectors.payload,
      signature: {
        algorithm: 'Ed25519',
        value: valid.receipt.signatures.find((s: any) => s.alg === 'Ed25519').sig,
        key_id: verificationKeys.ed25519KeyId,
      },
    };
    const result = verifyReceipt(repackaged, verificationKeys.ed25519PublicKey);
    expect(result).toEqual(vectors.v1_verifier_behaviour['classical-leg-repackaged-as-v1'].result);
    // Version accepted, signature rejected: the leg committed to the hybrid
    // profile and the full algorithm set, so it cannot be replayed as a
    // classical single-signature receipt.
    expect(result.checks.version).toBe(true);
    expect(result.checks.signature).toBe(false);
  });
});

describe('determinism', () => {
  it('regenerates byte for byte', () => {
    // Executed, not asserted: run the generator in --check mode and let it
    // compare the checked-in file against a fresh build from the seed labels.
    const output = execFileSync(
      process.execPath,
      ['conformance/hybrid-receipts/generate.mjs', '--check'],
      { cwd: root, encoding: 'utf8' },
    );
    expect(output).toContain('reproducible');
  });
});
