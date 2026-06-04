// Generate a cross-language test fixture: sign an EP-RECEIPT-v1 on the JS side,
// confirm @emilia-protocol/verify accepts it, then write it for the Python
// verifier (packages/python-verify) to independently verify. Proves the two
// implementations agree byte-for-byte.
//
//   node scripts/gen-python-fixture.mjs

import crypto from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyReceipt } from '../packages/verify/index.js';

// Same recursive canonicalization the verifier uses.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',')}}`;
  }
  return JSON.stringify(value);
}
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hashPair = (a, b) => { const [lo, hi] = [a, b].sort(); return sha256hex(lo + hi); };

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubB64url = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

const payload = {
  receipt_id: 'ep_demo_8c1f2a',
  issued_at: '2026-06-04T00:00:00Z',
  claim: {
    action: 'payment.release',
    outcome: 'allow_with_signoff',
    approver: 'operator:iman.schrock',
    context: { amount: 50000, destination: 'acct_9f12', currency: 'USD' },
  },
};
const sigValue = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');

// A small, real Merkle anchor (2-leaf tree) to exercise the anchor path too.
const leaf = sha256hex(payload.receipt_id);
const sibling = sha256hex('sibling-leaf');
const merkleRoot = hashPair(leaf, sibling);

const doc = {
  '@version': 'EP-RECEIPT-v1',
  payload,
  signature: { algorithm: 'ed25519', value: sigValue },
  anchor: { leaf_hash: leaf, merkle_proof: [{ hash: sibling, position: 'right' }], merkle_root: merkleRoot },
};

// Confirm the JS verifier accepts it before we hand it to Python.
const jsResult = verifyReceipt(doc, pubB64url);
if (!jsResult.valid) {
  console.error('JS verifyReceipt rejected the fixture:', jsResult);
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', 'packages', 'python-verify', 'tests', 'fixtures');
mkdirSync(fixtures, { recursive: true });
writeFileSync(join(fixtures, 'receipt.json'), JSON.stringify(doc, null, 2) + '\n');
writeFileSync(join(fixtures, 'pubkey.txt'), pubB64url + '\n');

console.log('JS verify: valid =', jsResult.valid, '| checks =', JSON.stringify(jsResult.checks));
console.log('wrote fixtures →', fixtures);
