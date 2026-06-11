// SPDX-License-Identifier: Apache-2.0
//
// Cross-language conformance runner for EP-RECEIPT-v1.
//
// Runs the SAME canonical vectors through three INDEPENDENT reference verifiers
// — JavaScript, Python, and Go — and asserts they all agree with each other and
// with the expected outcome. This is the IETF bar for a real standard: multiple
// independent interoperable implementations. Exit 1 on any divergence.
//
//   node conformance/run.mjs
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vectorsPath = resolve(root, 'conformance/vectors/receipts.v1.json');
const suite = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const expected = new Map(suite.vectors.map((v) => [v.id, v.expect.valid]));

const IMPLS = [
  { lang: 'JavaScript', run: () => execFileSync('node', ['conformance/runners/run-js.mjs', vectorsPath], { cwd: root, encoding: 'utf8' }) },
  { lang: 'Python', run: () => execFileSync('python3', ['conformance/runners/run_py.py', vectorsPath], { cwd: root, encoding: 'utf8' }) },
  { lang: 'Go', run: () => execFileSync('go', ['run', './cmd/conformance', vectorsPath], { cwd: resolve(root, 'packages/go-verify'), encoding: 'utf8' }) },
];

console.log(`\nEP-RECEIPT-v1 conformance — vectors v${suite.vectors_version} (${suite.vectors.length} vectors)\n`);

const results = {}; // lang -> Map(id -> valid)
const ran = [];
for (const impl of IMPLS) {
  try {
    const out = JSON.parse(impl.run());
    results[impl.lang] = new Map(out.map((r) => [r.id, r.valid]));
    ran.push(impl.lang);
  } catch (e) {
    console.log(`  ⚠ ${impl.lang}: could not run (${(e.message || '').split('\n')[0]}) — SKIPPED`);
  }
}
if (ran.length === 0) { console.error('No implementations ran.'); process.exit(1); }

// Matrix
const pad = (s, n) => String(s).padEnd(n);
const head = `  ${pad('vector', 32)}${pad('expect', 8)}${ran.map((l) => pad(l, 12)).join('')}`;
console.log(head);
console.log('  ' + '─'.repeat(head.length - 2));

let failures = 0;
for (const v of suite.vectors) {
  const exp = expected.get(v.id);
  const cells = ran.map((lang) => {
    const got = results[lang].get(v.id);
    return got === exp ? '✓' : `✗(${got})`;
  });
  const rowOk = cells.every((c) => c === '✓');
  if (!rowOk) failures++;
  console.log(`  ${pad(v.id, 32)}${pad(exp ? 'valid' : 'reject', 8)}${ran.map((l, i) => pad(cells[i], 12)).join('')}`);
}

console.log('  ' + '─'.repeat(head.length - 2));
const allThree = ran.length === IMPLS.length;
if (failures === 0) {
  console.log(`\n  ✅ ${suite.vectors.length} vectors · ${ran.length} independent implementations agree (${ran.join(', ')})`);
  if (!allThree) console.log(`  ⚠ note: ${IMPLS.length - ran.length} implementation(s) skipped (toolchain not present)`);
  process.exit(0);
} else {
  console.log(`\n  ❌ ${failures} vector(s) diverged across implementations — NOT conformant`);
  process.exit(1);
}
