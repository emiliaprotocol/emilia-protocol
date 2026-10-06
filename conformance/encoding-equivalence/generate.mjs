// SPDX-License-Identifier: Apache-2.0
// Deterministically regenerate the EP-COSE-ENCODING-v0.1 signed artifacts.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../packages/verify/dist/index.js';
import {
  buildReceiptCoseSign1,
  receiptActionCaid,
  receiptToCborBytes,
} from '../../packages/verify/dist/receipt-cose-encoding.js';

const vectorPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vectors.json');
const suite = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');

function privateKeyFromSeedHex(seedHex) {
  return crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

const issuerKey = privateKeyFromSeedHex(suite.keys.issuer.seed_hex);
const envelopeKey = privateKeyFromSeedHex(suite.keys.envelope.seed_hex);
suite.receipt.signature.value = crypto.sign(
  null,
  Buffer.from(canonicalize(suite.receipt.payload), 'utf8'),
  issuerKey,
).toString('base64url');

const canonicalReceipt = canonicalize(suite.receipt);
const canonicalDigest = crypto.createHash('sha256').update(canonicalReceipt, 'utf8').digest('hex');
const actionCaid = receiptActionCaid(suite.receipt.payload.action);
if (!actionCaid.ok) throw new Error(`CAID derivation failed: ${actionCaid.reason}`);
const cbor = receiptToCborBytes(suite.receipt);
if (!cbor.ok) throw new Error(`CBOR encoding failed: ${cbor.reason}`);
const cose = buildReceiptCoseSign1(suite.receipt, {
  envelopePrivateKey: envelopeKey,
  kid: suite.expected.cose_kid,
});
if (!cose.ok) throw new Error(`COSE construction failed: ${cose.reason}`);

Object.assign(suite.expected, {
  receipt_canonical_json: canonicalReceipt,
  receipt_canonical_sha256_hex: canonicalDigest,
  caid: actionCaid.value.caid,
  caid_action_digest: actionCaid.value.digest,
  receipt_cbor_hex: hex(cbor.value),
  cose_sign1_hex: hex(cose.value.cose),
  cose_payload_sha256_hex: crypto.createHash('sha256').update(cose.value.payload).digest('hex'),
  cose_protected_header_hex: hex(cose.value.protectedHeaderBytes),
});

const invariance = suite.vectors.find(({ id }) => id === 'caid-encoding-invariance');
invariance.expect.caid = actionCaid.value.caid;

const hostile = suite.vectors.find(({ id }) => id === 'hostile-tampered-payload-intact-headers');
const from = Buffer.from('40000.00', 'utf8').toString('hex');
const to = Buffer.from('40000.01', 'utf8').toString('hex');
if (!suite.expected.cose_sign1_hex.includes(from)) throw new Error('amount bytes not found in COSE payload');
hostile.input_cose_hex = suite.expected.cose_sign1_hex.replace(from, to);

fs.writeFileSync(vectorPath, `${JSON.stringify(suite, null, 2)}\n`);
