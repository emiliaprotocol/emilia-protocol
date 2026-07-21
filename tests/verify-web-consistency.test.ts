/**
 * Guard: the app's vendored browser verifier (lib/verify-web.js) must stay
 * byte-identical to the published source of truth — now the COMPILED output
 * of packages/verify/src/web.ts (packages/verify/dist/web.js), since verify
 * moved from hand-written JS to TypeScript. packages/verify/dist is itself
 * regenerated from src by `npm run build` and is not hand-edited.
 *
 * The /verify page imports the vendored copy so Next can bundle it client-side;
 * the package is what ships on npm. If they drift, a buyer could see a green
 * check in the browser that the audited, published verifier wouldn't give. This
 * test fails the build the moment they diverge.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('browser verifier — published source vs app copy', () => {
  it('lib/verify-web.js is byte-identical to packages/verify/dist/web.js', () => {
    const published = readFileSync(resolve(root, 'packages/verify/dist/web.js'), 'utf8');
    const vendored = readFileSync(resolve(root, 'lib/verify-web.js'), 'utf8');
    expect(vendored).toBe(published);
  });

  it('the strict nested-JSON gate is byte-identical in both browser bundles', () => {
    const published = readFileSync(resolve(root, 'packages/verify/dist/strict-json.js'), 'utf8');
    const vendored = readFileSync(resolve(root, 'lib/strict-json.js'), 'utf8');
    expect(vendored).toBe(published);
  });

  it('the vendored verifier actually verifies a signed receipt (smoke)', async () => {
    const crypto = await import('crypto');
    const { verifyReceipt } = await import('../lib/verify-web.js');
    const canon = (v: any): string => v === null || v === undefined ? JSON.stringify(v)
      : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
        : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
          : JSON.stringify(v);
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const payload = { receipt_id: 'tr_smoke', issuer: 'demo' };
    const doc = {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload)), privateKey).toString('base64url') },
    };
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const r = await verifyReceipt(doc, spki);
    expect(r.valid).toBe(true);
    // and rejects a tamper
    const bad = await verifyReceipt({ ...doc, payload: { ...payload, receipt_id: 'HACKED' } }, spki);
    expect(bad.valid).toBe(false);
  });
});
