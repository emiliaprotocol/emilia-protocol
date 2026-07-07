// SPDX-License-Identifier: Apache-2.0
//
// Keep public conformance-count claims tied to the live vector suites. This
// catches the easy-to-miss drift where conformance/run.mjs grows a negative
// vector but README.md / CONFORMANCE.md keep advertising the old count.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const runText = readFileSync(resolve(root, 'conformance/run.mjs'), 'utf8');
const suitesMatch = runText.match(/const\s+SUITES\s*=\s*\[([\s\S]*?)\];/);
if (!suitesMatch) {
  throw new Error('could not locate SUITES in conformance/run.mjs');
}

const suiteFiles = [...suitesMatch[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
if (suiteFiles.length === 0) {
  throw new Error('conformance/run.mjs SUITES list is empty');
}

const tableLabels = new Map([
  ['receipts.v1.json', 'EP-RECEIPT-v1'],
  ['signoffs.v1.json', 'EP-SIGNOFF-v1'],
  ['quorum.v1.json', 'EP-QUORUM-v1'],
  ['revocation.exec.v1.json', 'EP-REVOCATION-v1'],
  ['time-attestation.v1.json', 'EP-TIME-ATTESTATION-v1'],
  ['trust-receipt.exec.v1.json', 'EP-TRUST-RECEIPT-v1 (§6.2)'],
  ['trust-receipt.timestamp-forms.v1.json', 'EP-TRUST-RECEIPT-v1 ts-profile'],
  ['provenance.exec.v1.json', 'EP-PROVENANCE-CHAIN-v1'],
  ['evidence-record.v1.json', 'EP-EVIDENCE-RECORD-v1'],
  ['canonicalization.v1.json', 'EP-CANONICALIZATION-v1'],
  ['boundary.v1.json', 'EP-BOUNDARY-v1'],
  ['currency.v1.json', 'EP-CURRENCY-v1'],
  ['initiator-attestation.v1.json', 'EP-INITIATOR-ATTESTATION-v1'],
  ['consumption-proof.v1.json', 'EP-SMT-CONSUME-v1'],
  ['witness.v1.json', 'EP-WITNESS-v1'],
  ['timestamp-proof.v1.json', 'EP-TIMESTAMP-PROOF-v1'],
]);

const counts = [];
for (const suiteFile of suiteFiles) {
  const suitePath = resolve(root, 'conformance/vectors', suiteFile);
  const suite = JSON.parse(readFileSync(suitePath, 'utf8'));
  if (!Array.isArray(suite.vectors)) {
    throw new Error(`${suiteFile} has no vectors array`);
  }
  counts.push({ suiteFile, count: suite.vectors.length });
}

const total = counts.reduce((sum, s) => sum + s.count, 0);
const summary = `${total} vectors · ${suiteFiles.length} suites`;
const failures = [];

const readDoc = (path) => readFileSync(resolve(root, path), 'utf8');
const docs = {
  'README.md': readDoc('README.md'),
  'CONFORMANCE.md': readDoc('CONFORMANCE.md'),
};

for (const [doc, text] of Object.entries(docs)) {
  if (!text.includes(summary)) {
    failures.push(`${doc} must contain "${summary}"`);
  }
}

const conformance = docs['CONFORMANCE.md'];
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
for (const { suiteFile, count } of counts) {
  const label = tableLabels.get(suiteFile);
  if (!label) {
    failures.push(`no CONFORMANCE.md table label registered for ${suiteFile}`);
    continue;
  }
  const re = new RegExp(`${esc(label)}\\s+—\\s+${String(count).padStart(1)}\\s+vectors`);
  if (!re.test(conformance)) {
    failures.push(`CONFORMANCE.md must list "${label} — ${count} vectors"`);
  }
}

if (failures.length > 0) {
  console.error('CONFORMANCE DOC COUNTS: FAIL');
  for (const f of failures) console.error(`- ${f}`);
  process.exit(1);
}

console.log(`CONFORMANCE DOC COUNTS: OK (${summary})`);
