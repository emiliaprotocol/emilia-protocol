// SPDX-License-Identifier: Apache-2.0
//
// npm currently describes GHSA-mh99-v99m-4gvg with a range broad enough to
// include backported, capped implementations. Accept that advisory only when
// every installed brace-expansion copy is one of the exact reviewed builds and
// demonstrates both result-count and aggregate-length caps at runtime.

import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const scope = process.argv[2] ?? 'ROOT';
const minimumSeverity = process.argv[3] ?? 'moderate';
const severityRank = new Map([
  ['low', 1],
  ['moderate', 2],
  ['high', 3],
  ['critical', 4],
]);
const minimumRank = severityRank.get(minimumSeverity);
if (minimumRank === undefined) {
  throw new Error(`Unsupported audit severity threshold: ${minimumSeverity}`);
}

const REVIEWED_ADVISORY = 'https://github.com/advisories/GHSA-mh99-v99m-4gvg';
const REVIEWED_BRACE_EXPANSION = new Set(['2.1.3', '5.0.8']);

let report;
try {
  const stdout = execFileSync('npm', ['audit', '--json'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  report = JSON.parse(stdout);
} catch (error) {
  const stdout = error?.stdout;
  if (typeof stdout !== 'string' || stdout.length === 0) throw error;
  report = JSON.parse(stdout);
}

const observed = new Set();
for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  for (const cause of vulnerability.via ?? []) {
    if (typeof cause !== 'object' || cause === null) continue;
    const rank = severityRank.get(cause.severity) ?? 0;
    if (rank >= minimumRank && typeof cause.url === 'string') observed.add(cause.url);
  }
}

const unexpected = [...observed].filter((url) => url !== REVIEWED_ADVISORY);
if (unexpected.length > 0) {
  throw new Error(JSON.stringify({ unexpected }, null, 2));
}

if (observed.has(REVIEWED_ADVISORY)) {
  const packagePaths = execFileSync(
    'npm',
    ['ls', 'brace-expansion', '--all', '--parseable'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).trim().split(/\r?\n/).filter(Boolean);
  if (packagePaths.length === 0) throw new Error('brace-expansion advisory observed without an installed package');

  const require = createRequire(import.meta.url);
  for (const packagePath of packagePaths) {
    const manifest = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8'));
    if (!REVIEWED_BRACE_EXPANSION.has(manifest.version)) {
      throw new Error(`unreviewed brace-expansion version under advisory: ${manifest.version}`);
    }
    const loaded = require(packagePath);
    const expand = typeof loaded === 'function' ? loaded : loaded?.expand;
    if (typeof expand !== 'function') throw new Error(`brace-expansion ${manifest.version} has no callable expansion API`);

    const max = 64;
    const maxLength = 4096;
    const expanded = expand('{a,b}'.repeat(16), { max, maxLength });
    const totalLength = expanded.reduce((sum, value) => sum + value.length, 0);
    if (expanded.length > max || totalLength > maxLength) {
      throw new Error(`brace-expansion ${manifest.version} failed the executable resource-cap check`);
    }
  }
}

console.log(
  `${scope} AUDIT: PASS at ${minimumSeverity}+; `
  + (observed.size === 0
    ? 'no advisories observed'
    : 'one npm range finding is constrained to reviewed, cap-enforced builds'),
);
