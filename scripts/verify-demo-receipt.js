#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end proof of the /r/example demo receipt's signature chain.
//
// Builds the demo receipt (lib/demo-receipt.js) — same code path the
// production /r/example page and /api/demo/trust-receipts/.../evidence
// endpoint use — and feeds it through the published @emilia-protocol/
// verify@1.0.1 verifier. Both signer and verifier use the recursive
// canonical-JSON algorithm; the signature must validate.
//
// Also exercises the regression case the v1.0.0 shallow bug allowed:
// tamper a deeply-nested field (claim.context.change.after_bank_hash)
// and confirm the verifier rejects it.
//
// Run:
//   node scripts/verify-demo-receipt.js

import { getDemoReceipt } from '../lib/demo-receipt.js';
import { verifyReceipt } from '../packages/verify/index.js';

const r = getDemoReceipt();

console.log('═'.repeat(72));
console.log('Demo receipt round-trip — sign with lib/demo-receipt.js,');
console.log('verify with @emilia-protocol/verify@1.0.1');
console.log('═'.repeat(72));

console.log('\n1. Honest verify (untampered document):');
const honest = verifyReceipt(r.document, r.public_key);
console.log('   →', honest);
if (!honest.valid) {
  console.error('\nFAIL: honest verify rejected. Canonicalization out of sync.');
  process.exit(1);
}

console.log('\n2. Tampered verify (modify deeply-nested after_bank_hash):');
const tampered = JSON.parse(JSON.stringify(r.document));
tampered.payload.claim.context.change.after_bank_hash = 'sha256:EVIL_DESTINATION';
const tamperedResult = verifyReceipt(tampered, r.public_key);
console.log('   →', tamperedResult);
if (tamperedResult.valid) {
  console.error('\nFAIL: tampered verify accepted. Recursive canonicalize is not active.');
  process.exit(1);
}

console.log('\n3. Tampered verify (modify nested risk_signals array):');
const riskTamper = JSON.parse(JSON.stringify(r.document));
riskTamper.payload.claim.context.risk_signals = ['BENIGN'];
const riskResult = verifyReceipt(riskTamper, r.public_key);
console.log('   →', riskResult);
if (riskResult.valid) {
  console.error('\nFAIL: tampered risk_signals accepted.');
  process.exit(1);
}

console.log('\n' + '═'.repeat(72));
console.log('All three checks pass. Verification chain is sound.');
console.log('Demo public key:', r.public_key.slice(0, 48) + '…');
console.log('═'.repeat(72));
