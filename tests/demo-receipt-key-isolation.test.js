// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  canonicalize,
  getDemoPublicKeyBase64url,
  getDemoReceipt,
  getDemoRuntimePublicKeyBase64url,
  signDemoPayload,
} from '../lib/demo-receipt.js';

const ROOT = path.resolve(import.meta.dirname, '..');

function verify(payload, signature, publicKeyB64u) {
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64u, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(
    null,
    Buffer.from(canonicalize(payload), 'utf8'),
    publicKey,
    Buffer.from(signature, 'base64url'),
  );
}

describe('public demo signing boundary', () => {
  it('contains no source-controlled demo private key', () => {
    const source = fs.readFileSync(path.join(ROOT, 'lib/demo-receipt.js'), 'utf8');
    const forbiddenName = ['DEMO', 'PRIVATE', 'JWK'].join('_');
    expect(source).not.toContain(forbiddenName);
    expect(source).not.toMatch(/createPrivateKey\(\s*\{\s*key:\s*DEMO/);
  });

  it('keeps the public /r/example fixture cryptographically verifiable', () => {
    const receipt = getDemoReceipt();
    expect(receipt.public_key).toBe(getDemoPublicKeyBase64url());
    expect(verify(
      receipt.document.payload,
      receipt.document.signature.value,
      receipt.public_key,
    )).toBe(true);
  });

  it('returns a public key matching dynamic demo signatures', () => {
    const payload = { demo: true, action: 'synthetic-crash-test', nonce: 'test-only' };
    const signature = signDemoPayload(payload);
    expect(verify(payload, signature, getDemoRuntimePublicKeyBase64url())).toBe(true);
  });
});
