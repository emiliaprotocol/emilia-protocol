// SPDX-License-Identifier: Apache-2.0
//
// Bounded, fixed-seed fuzz batch for the per-push CI job (audit GAP 7).
//
// Deterministic and time-bounded: the same seeds and iteration counts run on
// every push, so a regression that breaks a concurrency invariant fails CI at a
// named seed the author can replay locally with:
//
//   node fuzz/harness.mjs <target> --seed <SEED> --iterations <ITER>
//
// This batch is intentionally sized to finish well under a minute on a GitHub
// runner. The deeper, longer nightly sweep is documented in fuzz/README.md.

import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const harness = join(HERE, 'harness.mjs');
const raceTeethSelftest = join(HERE, 'race-teeth.selftest.mjs');

// [target, seedsSpec, iterationsPerSeed]
/** @type {Array<[string, string, number]>} */
const BATCH = [
  ['capability-race', '1..24', 250],
  ['concurrent-race', '1..24', 250],
  ['handshake-consume', '1..24', 250],
];

const startedAt = process.hrtime.bigint();
let failed = false;

// Prove the concurrency driver can actually detect the check-then-act bug
// class before trusting a green run against the hardened implementation.
const teeth = spawnSync(
  process.execPath,
  ['--test', raceTeethSelftest],
  { stdio: 'inherit' },
);
if (teeth.status !== 0) failed = true;

for (const [target, seeds, iterations] of BATCH) {
  if (failed) break;
  const args: readonly string[] = [harness, target as string, '--seeds', seeds as string, '--iterations', String(iterations)];
  const result = spawnSync(
    process.execPath,
    args,
    { stdio: 'inherit' },
  );
  if (result.status !== 0) {
    failed = true;
    break;
  }
}

const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
process.stdout.write(`\nfuzz CI batch ${failed ? 'FAILED' : 'passed'} in ${elapsedMs.toFixed(0)} ms\n`);
process.exit(failed ? 1 : 0);
