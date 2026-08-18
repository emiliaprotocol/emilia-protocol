// SPDX-License-Identifier: Apache-2.0
//
// The browser verifier twins and EP-RECEIPT-HYBRID-v1.
//
// WHY THERE IS NO BROWSER HYBRID VERIFIER, STATED AS A TEST RATHER THAN AS A
// COMMENT. packages/verify/src/web.ts and its vendored copy lib/verify-web.js
// are built on W3C Web Crypto (globalThis.crypto.subtle) and are zero-dependency
// by design, because the /verify page bundles the vendored copy client-side.
// Web Crypto has no ML-DSA-65. A "hybrid verifier" in that runtime could only
// ever return a permanent pq_backend_unavailable, or — far worse — pass on the
// Ed25519 leg alone. Neither is worth shipping.
//
// So the browser twins do the one correct thing instead: they refuse a hybrid
// receipt on the VERSION MARKER, before inspecting any signature, without
// throwing. That is exactly the v1-refuses-v2 property the hybrid program
// requires of a deployed v1 verifier, and it is what this suite pins — in BOTH
// twins, so neither can drift into accepting a document the other refuses.
//
// A relying party that needs the post-quantum leg checked runs the Node
// verifier's verifyHybridReceipt (packages/verify/src/receipt-hybrid.ts).

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import * as webSource from '../packages/verify/src/web.js';
// The app's vendored copy, byte-identical to packages/verify/dist/web.js (that
// byte identity is itself pinned by tests/verify-web-consistency.test.ts).
import * as webVendored from '../lib/verify-web.js';
import {
  HYBRID_RECEIPT_PROFILE,
  hybridReceiptSignedBytes,
  LOG_CHECKPOINT_HYBRID_PROFILE,
} from '../packages/verify/receipt-hybrid.js';
import { canonicalize } from '../packages/verify/index.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edSpkiB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(new Uint8Array(crypto.createHash('sha256').update('web-twins/seed').digest()));

const PAYLOAD = {
  receipt_id: 'ep:receipt:web-twin-test',
  claim: { action_type: 'payment.send', outcome: 'authorized' },
  issued_at: '2026-08-17T12:00:00Z',
};

const hybridBytes = hybridReceiptSignedBytes(PAYLOAD);
const HYBRID_DOC = {
  '@version': HYBRID_RECEIPT_PROFILE,
  profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: ['Ed25519', 'ML-DSA-65'] },
  payload: PAYLOAD,
  signatures: [
    { alg: 'Ed25519', sig: crypto.sign(null, hybridBytes, ed.privateKey).toString('base64url') },
    {
      alg: 'ML-DSA-65',
      sig: Buffer.from(ml_dsa65.sign(new Uint8Array(hybridBytes), pq.secretKey)).toString('base64url'),
    },
  ],
};

const V1_DOC = {
  '@version': 'EP-RECEIPT-v1',
  payload: PAYLOAD,
  signature: {
    algorithm: 'Ed25519',
    value: crypto.sign(null, Buffer.from(canonicalize(PAYLOAD), 'utf8'), ed.privateKey).toString('base64url'),
  },
};

const twins: Array<[string, typeof webSource]> = [
  ['packages/verify/src/web.ts', webSource],
  ['lib/verify-web.js (vendored)', webVendored as any],
];

describe.each(twins)('browser verifier twin: %s', (_name, web) => {
  it('still verifies an ordinary EP-RECEIPT-v1 receipt (control)', async () => {
    const result = await web.verifyReceipt(V1_DOC, edSpkiB64u);
    expect(result.valid).toBe(true);
    expect(result.checks).toEqual({ version: true, signature: true, anchor: null });
  });

  it('REFUSES a hybrid receipt on the version marker, before inspecting any signature', async () => {
    const result = await web.verifyReceipt(HYBRID_DOC as any, edSpkiB64u);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(`Unsupported version: ${HYBRID_RECEIPT_PROFILE}`);
    expect(result.checks.version).toBe(false);
    expect(result.checks.signature).toBe(false);
    expect(result.checks.anchor).toBe(null);
  });

  it('does not throw on a hybrid receipt, a checkpoint proof, or hostile input', async () => {
    const hostile = [
      HYBRID_DOC,
      { '@version': LOG_CHECKPOINT_HYBRID_PROFILE, profile: {}, checkpoint: {}, signatures: [] },
      { '@version': HYBRID_RECEIPT_PROFILE },
      null, undefined, 0, '', [], { '@version': 1 },
    ];
    for (const doc of hostile) {
      const result = await web.verifyReceipt(doc as any, edSpkiB64u);
      expect(result.valid).toBe(false);
      expect(typeof result.error).toBe('string');
    }
  });

  it('LEG LIFTING: a hybrid receipt\'s Ed25519 leg does not verify inside a v1 envelope in the browser either', async () => {
    const lifted = {
      '@version': 'EP-RECEIPT-v1',
      payload: PAYLOAD,
      signature: { algorithm: 'Ed25519', value: HYBRID_DOC.signatures[0].sig },
    };
    const result = await web.verifyReceipt(lifted, edSpkiB64u);
    expect(result.valid).toBe(false);
    expect(result.checks.version).toBe(true);
    expect(result.checks.signature).toBe(false);
  });

  it('a bundle containing a hybrid receipt fails the bundle, and names which document', async () => {
    const result = await web.verifyReceiptBundle(
      { '@version': 'EP-BUNDLE-v1', documents: [V1_DOC, HYBRID_DOC] }, edSpkiB64u,
    );
    expect(result.valid).toBe(false);
    expect(result.verified).toBe(1);
    expect(result.failed).toEqual([`doc[1]: Unsupported version: ${HYBRID_RECEIPT_PROFILE}`]);
  });
});

describe('the two browser twins agree', () => {
  it('return identical verdicts for the same documents', async () => {
    for (const doc of [V1_DOC, HYBRID_DOC, { '@version': 'EP-RECEIPT-v9' }, null]) {
      const a = await webSource.verifyReceipt(doc as any, edSpkiB64u);
      const b = await (webVendored as any).verifyReceipt(doc as any, edSpkiB64u);
      expect(JSON.parse(JSON.stringify(b))).toEqual(JSON.parse(JSON.stringify(a)));
    }
  });
});
