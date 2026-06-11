// SPDX-License-Identifier: Apache-2.0
// Class-A signoff conformance: runs the published EP-SIGNOFF-v1 vectors through
// BOTH JS reference verifiers — Node (packages/verify) and Web Crypto
// (packages/verify/web.js) — and asserts they agree with each other and the
// expected outcome. Prints a matrix grouped by failure class. Exit 1 on any
// divergence.  node conformance/run-signoffs.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { verifyWebAuthnSignoff as nodeVerify } from '../packages/verify/index.js';
import { verifyWebAuthnSignoff as webVerify } from '../packages/verify/web.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const suite = JSON.parse(readFileSync(resolve(root, 'conformance/vectors/signoffs.v1.json'), 'utf8'));

console.log(`\nEP-SIGNOFF-v1 conformance — vectors v${suite.vectors_version} (${suite.vectors.length} vectors)\n`);
const pad = (s, n) => String(s).padEnd(n);
console.log(`  ${pad('vector', 34)}${pad('failure class', 20)}${pad('expect', 8)}${pad('Node', 8)}${pad('Web', 8)}`);
console.log('  ' + '─'.repeat(76));

let failures = 0;
for (const v of suite.vectors) {
  const opts = { rpId: v.rp_id };
  const n = nodeVerify(v.signoff, v.approver_public_key, opts).valid;
  const w = (await webVerify(v.signoff, v.approver_public_key, opts)).valid;
  const exp = v.expect.valid;
  const ok = n === exp && w === exp;
  if (!ok) failures++;
  console.log(`  ${pad(v.id, 34)}${pad(v.failure_class, 20)}${pad(exp ? 'valid' : 'reject', 8)}${pad(n === exp ? '✓' : `✗(${n})`, 8)}${pad(w === exp ? '✓' : `✗(${w})`, 8)}`);
}
console.log('  ' + '─'.repeat(76));
if (failures === 0) {
  console.log(`\n  ✅ ${suite.vectors.length} signoff vectors · Node + Web Crypto verifiers agree\n`);
  process.exit(0);
} else {
  console.log(`\n  ❌ ${failures} vector(s) diverged\n`);
  process.exit(1);
}
