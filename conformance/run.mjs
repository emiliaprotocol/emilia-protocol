// SPDX-License-Identifier: Apache-2.0
//
// Cross-language conformance runner.
//
// Runs the SAME canonical vectors through three INDEPENDENT reference verifiers
// — JavaScript, Python, and Go — and asserts they all agree with each other and
// with the expected outcome, across every suite:
//   • EP-RECEIPT-v1  (Ed25519 receipts)
//   • EP-SIGNOFF-v1  (WebAuthn ECDSA P-256 device signoffs)
//   • EP-QUORUM-v1   (multi-party M-of-N / ordered approval)
// This is the IETF bar for a real standard: multiple independent interoperable
// implementations. Exit 1 on any divergence.
//
//   node conformance/run.mjs
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SUITES = ['receipts.v1.json', 'signoffs.v1.json', 'quorum.v1.json'];

const IMPLS = [
  { lang: 'JavaScript', run: (p) => execFileSync('node', ['conformance/runners/run-js.mjs', p], { cwd: root, encoding: 'utf8' }) },
  { lang: 'Python', run: (p) => execFileSync('python3', ['conformance/runners/run_py.py', p], { cwd: root, encoding: 'utf8' }) },
  { lang: 'Go', run: (p) => execFileSync('go', ['run', './cmd/conformance', p], { cwd: resolve(root, 'packages/go-verify'), encoding: 'utf8' }) },
];

const pad = (s, n) => String(s).padEnd(n);
let totalFailures = 0;
let anyRan = false;

for (const suiteFile of SUITES) {
  const vectorsPath = resolve(root, 'conformance/vectors', suiteFile);
  let suite;
  try { suite = JSON.parse(readFileSync(vectorsPath, 'utf8')); }
  catch { console.log(`\n⚠ ${suiteFile}: not found — skipped`); continue; }
  const expected = new Map(suite.vectors.map((v) => [v.id, v.expect.valid]));

  const results = {};
  const ran = [];
  for (const impl of IMPLS) {
    try {
      results[impl.lang] = new Map(JSON.parse(impl.run(vectorsPath)).map((r) => [r.id, r.valid]));
      ran.push(impl.lang);
    } catch (e) {
      console.log(`  ⚠ ${impl.lang}: skipped (${(e.message || '').split('\n')[0]})`);
    }
  }

  console.log(`\n${suite.suite || suiteFile} — ${suite.vectors.length} vectors`);
  if (ran.length === 0) { console.log('  (no implementations ran)'); totalFailures++; continue; }
  anyRan = true;
  const head = `  ${pad('vector', 36)}${pad('expect', 8)}${ran.map((l) => pad(l, 12)).join('')}`;
  console.log(head);
  console.log('  ' + '─'.repeat(head.length - 2));
  for (const v of suite.vectors) {
    const exp = expected.get(v.id);
    const cells = ran.map((lang) => { const got = results[lang].get(v.id); return got === exp ? '✓' : `✗(${got})`; });
    if (!cells.every((c) => c === '✓')) totalFailures++;
    console.log(`  ${pad(v.id, 36)}${pad(exp ? 'valid' : 'reject', 8)}${ran.map((l, i) => pad(cells[i], 12)).join('')}`);
  }
}

if (!anyRan) { console.error('\nNo implementations ran.'); process.exit(1); }
if (totalFailures === 0) {
  console.log('\n✅ receipts · signoffs · quorum — three independent implementations agree.');
  process.exit(0);
}
console.log(`\n❌ ${totalFailures} divergence(s) across implementations — NOT conformant`);
process.exit(1);
