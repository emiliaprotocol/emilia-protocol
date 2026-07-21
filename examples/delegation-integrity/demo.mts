// SPDX-License-Identifier: Apache-2.0
/**
 * EP-DELEGATION-INTEGRITY-v1 — offline demo.
 *
 * Runs every conformance vector through the real delegation-chain verifier
 * (packages/verify/provenance.js) and prints, in plain terms, why the valid
 * chain is ACCEPTED and why each classic delegation attack is REFUSED.
 *
 * Fully offline. No dependencies beyond node:fs and the repo verifier.
 * Run:  node examples/delegation-integrity/demo.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { verifyProvenanceOffline } from '../../packages/verify/provenance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(
  readFileSync(path.join(__dirname, '..', '..', 'conformance', 'vectors', 'delegation-integrity.v1.json'), 'utf8'),
);

// ── plain, editorial styling. Falls back to no-color when not a TTY. ──────────
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = (s) => c('1;32', s);
const red = (s) => c('1;31', s);
const dim = (s) => c('2', s);
const bold = (s) => c('1', s);

const KIND_LABEL = {
  positive: 'CONTROL',
  authority_laundering: 'AUTHORITY LAUNDERING',
  chain_poisoning: 'DELEGATION CHAIN POISONING',
  root_authority: 'ROOT AUTHORITY',
};

console.log('');
console.log(bold('  EMILIA PROTOCOL — DELEGATION INTEGRITY'));
console.log(dim('  A signed delegation may only NARROW what its parent conferred.'));
console.log(dim('  Broaden the scope, poison a link, or root it in nothing — the verifier refuses.'));
console.log('');

let mismatches = 0;
let lastKind = null;

for (const v of SUITE.vectors) {
  if (v.kind !== lastKind) {
    console.log('  ' + bold(KIND_LABEL[v.kind] || v.kind.toUpperCase()));
    lastKind = v.kind;
  }

  const res = verifyProvenanceOffline(v.input.provenance_chain, {
    delegationKeys: v.input.delegation_keys,
    rootVerification: v.input.root_verification,
    actionVerification: v.input.action_verification,
    now: v.input.now_ms,
  });

  const asExpected = res.valid === v.expect.valid;
  if (!asExpected) mismatches++;

  const verdict = res.valid ? green('ACCEPT') : red('REFUSE');
  const flag = asExpected ? '' : red('  <-- UNEXPECTED VERDICT');
  console.log(`    ${verdict}  ${v.id}${flag}`);
  console.log(dim(`           ${v.description}`));

  if (!res.valid) {
    const reason = (res.errors && res.errors[0]) || '(no reason emitted)';
    console.log(dim(`           reason: ${reason}`));
  }
  console.log('');
}

const total = SUITE.vectors.length;
const accepts = SUITE.vectors.filter((v) => v.expect.valid).length;
const refusals = total - accepts;

console.log('  ' + bold('SUMMARY'));
console.log(`    ${total} vectors  ·  ${green(`${accepts} accepted`)}  ·  ${red(`${refusals} refused`)}`);
if (mismatches === 0) {
  console.log('    ' + green('Every attack was refused fail-closed, and every valid chain was accepted.'));
  console.log('');
  process.exit(0);
} else {
  console.log('    ' + red(`${mismatches} vector(s) did NOT match the expected verdict — the verifier failed to refuse an attack.`));
  console.log('');
  process.exit(1);
}
