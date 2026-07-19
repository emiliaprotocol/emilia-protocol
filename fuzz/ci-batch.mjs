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

// [target, seedsSpec, iterationsPerSeed]
const BATCH = [
  ['capability-race', '1..24', 250],
  ['handshake-consume', '1..24', 250],
];

const startedAt = process.hrtime.bigint();
let failed = false;

for (const [target, seeds, iterations] of BATCH) {
  const result = spawnSync(
    process.execPath,
    [harness, target, '--seeds', seeds, '--iterations', String(iterations)],
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
