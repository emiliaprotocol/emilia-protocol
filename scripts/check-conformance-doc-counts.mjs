// SPDX-License-Identifier: Apache-2.0
//
// Keep public conformance-count claims tied to the live vector suites. This
// catches the easy-to-miss drift where conformance/run.mjs grows a negative
// vector but README.md / CONFORMANCE.md keep advertising the old count.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { LIVE_SUITE_FILES } from '../conformance/suites.mjs';

const root = resolve(import.meta.dirname, '..');
const suiteFiles = [...LIVE_SUITE_FILES];
if (suiteFiles.length === 0) {
  throw new Error('conformance/suites.mjs LIVE_SUITE_FILES is empty');
}

const tableLabels = new Map([
  ['receipts.v1.json', 'EP-RECEIPT-v1'],
  ['signoffs.v1.json', 'EP-SIGNOFF-v1'],
  ['resolution.v1.json', 'EP-RESOLUTION-v1'],
  ['quorum.v1.json', 'EP-QUORUM-v1'],
  ['revocation.exec.v2.json', 'EP-REVOCATION-v1'],
  ['outcome-binding.v1.json', 'EP-OUTCOME-BINDING-v1 semantic'],
  ['outcome-binding.exec.v1.json', 'EP-OUTCOME-BINDING-v1 real-crypto'],
  ['authority-document-proof-join.v1.json', 'EP-AUTHORITY-DOC-PROOF-JOIN-v1'],
  ['time-attestation.v2.json', 'EP-TIME-ATTESTATION-v1'],
  ['trust-receipt.exec.v1.json', 'EP-TRUST-RECEIPT-v1 (§6.2)'],
  ['trust-receipt.timestamp-forms.v2.json', 'EP-TRUST-RECEIPT-v1 ts-profile'],
  ['provenance.exec.v1.json', 'EP-PROVENANCE-CHAIN-v1'],
  ['evidence-record.v1.json', 'EP-EVIDENCE-RECORD-v1'],
  ['canonicalization.v1.json', 'EP-CANONICALIZATION-v1'],
  ['boundary.v1.json', 'EP-BOUNDARY-v1'],
  ['aec-role.v1.json', 'EP-AEC-ROLE-v1'],
  ['currency.v2.json', 'EP-CURRENCY-v1'],
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
