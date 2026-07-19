#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Secure development scaffold for the EMILIA issuer -> relying-party verifier
// boundary. It deliberately uses the published issuer and verifier packages;
// generated applications do not contain a second cryptographic implementation.

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';

const projectName = process.argv[2];
if (!projectName) {
  console.error('Usage: npx @emilia-protocol/create-ep-app <project-name>');
  process.exit(1);
}
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(projectName) || projectName === '.' || projectName === '..') {
  console.error('Project name must be 1-64 safe filename characters and may not be a path.');
  process.exit(1);
}

const cwd = resolve(process.cwd());
const root = resolve(cwd, projectName);
const rel = relative(cwd, root);
if (!rel || rel.startsWith('..') || rel.includes('/') || rel.includes('\\')) {
  console.error('Resolved project path escapes the current directory.');
  process.exit(1);
}
if (existsSync(root)) {
  console.error(`Refusing to overwrite existing path: ${projectName}`);
  process.exit(1);
}
mkdirSync(root, { recursive: false, mode: 0o700 });

function write(name, body) {
  writeFileSync(resolve(root, name), body, { flag: 'wx', mode: 0o600 });
}

write('package.json', `${JSON.stringify({
  name: projectName,
  version: '0.1.0',
  private: true,
  type: 'module',
  scripts: {
    demo: 'node demo.mjs',
    verify: 'node verify-receipt.mjs receipt.json relying-party-trust.json',
  },
  dependencies: {
    '@emilia-protocol/issue': '0.6.1',
    '@emilia-protocol/verify': '3.10.0',
  },
}, null, 2)}\n`);

write('demo.mjs', `import { writeFileSync } from 'node:fs';
import { generateIssuerKeyBundle, issueFromKeyBundle } from '@emilia-protocol/issue';
import { verifyTrustReceipt } from '@emilia-protocol/verify';

const action = {
  ep_version: '1.0',
  action_type: 'payment.release',
  target: { system: 'development.example', resource: 'invoice/8841' },
  parameters: { amount: '250000.00', currency: 'USD', destination: 'vendor-42' },
  initiator: 'ep:entity:development-agent',
  policy_id: 'ep:policy:development-only@v1',
  requested_at: new Date().toISOString(),
};

// Development only: the relying party pins these keys before evaluating the
// receipt. A production profile must come from independent enrollment and
// governance, not from receipt contents or this issuer process.
const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:development-only' });
const { receipt, verification } = await issueFromKeyBundle({ keys, action });
const trust = {
  '@version': 'EP-DEVELOPMENT-TRUST-PROFILE-v1',
  approver_keys: verification.approver_keys,
  log_public_key: verification.log_public_key,
};

writeFileSync('receipt.json', JSON.stringify(receipt, null, 2) + '\\n', { flag: 'wx', mode: 0o600 });
writeFileSync('relying-party-trust.json', JSON.stringify(trust, null, 2) + '\\n', { flag: 'wx', mode: 0o600 });

const result = verifyTrustReceipt(receipt, {
  approverKeys: trust.approver_keys,
  logPublicKey: trust.log_public_key,
});
if (!result.valid) throw new Error('issued receipt did not verify: ' + result.errors.join('; '));

const tampered = structuredClone(receipt);
tampered.action.parameters.amount = '2500000.00';
const attack = verifyTrustReceipt(tampered, {
  approverKeys: trust.approver_keys,
  logPublicKey: trust.log_public_key,
});
if (attack.valid) throw new Error('tampered receipt was accepted');

console.log('VERIFIED under the separately loaded development trust profile.');
console.log('REFUSED after exact-action mutation.');
console.log('This demonstrates cryptographic binding, not identity, authority, perception, execution, or legal reliance.');
`);

write('verify-receipt.mjs', `import { readFileSync } from 'node:fs';
import { verifyTrustReceipt } from '@emilia-protocol/verify';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';

const MAX_BYTES = 8 * 1024 * 1024;
function readStrict(path) {
  const raw = readFileSync(path);
  if (raw.length > MAX_BYTES) throw new Error(path + ' exceeds ' + MAX_BYTES + ' bytes');
  const text = raw.toString('utf8');
  const gate = strictJsonGate(text);
  if (!gate.ok) throw new Error(path + ' refused: ' + gate.reason);
  return JSON.parse(text);
}

const [receiptPath, trustPath] = process.argv.slice(2);
if (!receiptPath || !trustPath) {
  console.error('Usage: node verify-receipt.mjs <receipt.json> <relying-party-trust.json>');
  process.exit(2);
}
const receipt = readStrict(receiptPath);
const trust = readStrict(trustPath);
if (trust['@version'] !== 'EP-DEVELOPMENT-TRUST-PROFILE-v1') {
  throw new Error('unrecognized relying-party trust profile');
}
const result = verifyTrustReceipt(receipt, {
  approverKeys: trust.approver_keys,
  logPublicKey: trust.log_public_key,
});
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.valid ? 0 : 1;
`);

write('README.md', `# ${projectName}

This is a local development demonstration of the EMILIA issuer-to-verifier
boundary. It uses the published issuer and verifier packages and requires a
separately loaded relying-party trust profile; it never trusts keys carried by
the receipt itself.

\`\`\`bash
npm install
npm run demo
npm run verify
\`\`\`

The demo proves that enrolled keys signed an exact action and that mutation is
refused under the pinned development profile. It does **not** prove real-world
identity, legal authority, what a person perceived, policy correctness,
execution, effects, safety, or legal reliance. Replace the generated profile
with independently enrolled and governed production trust roots before use.
`);

console.log(`Created ${projectName}. Run: cd ${projectName} && npm install && npm run demo`);
