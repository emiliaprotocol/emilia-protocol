// SPDX-License-Identifier: Apache-2.0
//
// EP continuous adversarial fuzzing harness (audit GAP 7).
//
// A seeded, deterministic, CI-runnable property fuzzer for the concurrency-
// sensitive surfaces of the protocol. The async-guard bypass that motivated
// this harness was a parallel-consumption race: a check-then-act window between
// a budget/consumption read and its mutation. A fuzzer that drives many
// concurrent reserve/commit attempts, interleaved at operation-step boundaries,
// and asserts the safety invariants after every scenario would have flagged it.
//
// Design goals:
//   1. REPRODUCIBLE. The RNG is seeded (mulberry32); the interleaving scheduler
//      draws every scheduling decision from that same RNG. Same seed => same
//      logical operation sequence and the same PASS/FAIL verdict. (Reservation
//      tokens / capability ids are node crypto UUIDs and therefore differ run to
//      run; they are opaque to every invariant, so the verdict stays stable.)
//   2. NO wall-clock / Math.random nondeterminism in the harness itself.
//   3. Targets import and exercise the ACTUAL shipped modules — never a reimpl.
//
// Usage:
//   node fuzz/harness.mjs <target> [--seed N] [--seeds A..B] [--iterations K]
//
// Exit code is non-zero on the first invariant violation, and the failing seed
// + iteration are printed so the exact scenario can be replayed with --seed.

import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Thrown by a target when a safety invariant is violated by real code. */
export class InvariantViolation extends Error {
  constructor(invariant, detail) {
    super(`invariant violated: ${invariant} — ${detail}`);
    this.name = 'InvariantViolation';
    this.invariant = invariant;
    this.detail = detail;
  }
}

/** Assert helper that raises a typed InvariantViolation (not a bare Error). */
export function invariant(condition, name, detail) {
  if (!condition) throw new InvariantViolation(name, detail);
}

/**
 * mulberry32 — a small, fast, fully deterministic 32-bit PRNG. Seeded once;
 * produces the identical stream for the identical seed on every platform.
 */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A seeded RNG facade with the small vocabulary the targets need. */
export function createRng(seed) {
  const next = mulberry32(seed);
  return {
    seed,
    next,
    /** integer in [min, max] inclusive */
    int(min, max) {
      if (max < min) return min;
      return min + Math.floor(next() * (max - min + 1));
    },
    /** true with probability p */
    bool(p = 0.5) {
      return next() < p;
    },
    pick(arr) {
      return arr[this.int(0, arr.length - 1)];
    },
  };
}

/**
 * Cooperative interleaving scheduler.
 *
 * `ops` is an array of operations; each operation is an array of async step
 * thunks. The scheduler repeatedly picks a still-running operation at random
 * (from the seeded RNG) and advances it exactly one step, awaiting that step to
 * completion before choosing the next. Interleaving therefore happens at step
 * boundaries: modelling, for example, reserve() as one step and a later
 * commit() as another, with other operations' steps interleaved in between —
 * precisely the check-then-act window a parallel-consumption race exploits.
 *
 * Because the choice is drawn from the seeded RNG and each step is awaited
 * fully, the whole interleaving is deterministic for a given seed.
 */
export async function interleave(ops, rng) {
  const cursors = ops
    .map((steps, id) => ({ id, steps, pos: 0 }))
    .filter((c) => c.steps.length > 0);
  let stepCount = 0;
  while (cursors.length > 0) {
    const idx = rng.int(0, cursors.length - 1);
    const cursor = cursors[idx];
    await cursor.steps[cursor.pos]();
    cursor.pos += 1;
    stepCount += 1;
    if (cursor.pos >= cursor.steps.length) cursors.splice(idx, 1);
  }
  return stepCount;
}

/**
 * TRUE-concurrency driver. Unlike interleave() (which advances one op-step at a
 * time and awaits each, so a store method runs atomically to completion),
 * concurrent() fires every op-sequence at once via Promise.all. If any store
 * method has an internal check-then-act `await` (the async-guard bug class),
 * concurrent calls interleave INSIDE that method and can violate an invariant.
 * Against a correctly-atomic store this simply passes; its value is as a
 * regression guard — a reintroduced non-atomic reserve/commit would be caught.
 * fuzz/race-teeth.selftest.mjs proves this driver DOES catch a non-atomic store.
 *
 * `opSequences` is an array of arrays of async step thunks; each sequence runs
 * its steps in order, all sequences run concurrently.
 */
export async function concurrent(opSequences) {
  await Promise.all(opSequences.map(async (steps) => {
    for (const step of steps) await step();
  }));
}

const TARGETS = {
  'capability-race': './targets/capability-race.mjs',
  'concurrent-race': './targets/concurrent-race.mjs',
  'handshake-consume': './targets/handshake-consume.mjs',
};

function parseArgs(argv) {
  const args = { target: null, seed: 1, seeds: null, iterations: 200 };
  const rest = argv.slice(2);
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (token === '--seed') args.seed = Number(rest[(i += 1)]);
    else if (token === '--seeds') args.seeds = rest[(i += 1)];
    else if (token === '--iterations') args.iterations = Number(rest[(i += 1)]);
    else if (!args.target) args.target = token;
  }
  return args;
}

function seedRange(spec, fallbackSeed) {
  if (!spec) return [fallbackSeed];
  const match = /^(-?\d+)\.\.(-?\d+)$/.exec(spec.trim());
  if (!match) throw new Error(`--seeds must look like A..B, got ${spec}`);
  const start = Number(match[1]);
  const end = Number(match[2]);
  const seeds = [];
  for (let s = start; s <= end; s += 1) seeds.push(s);
  return seeds;
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.target || !TARGETS[args.target]) {
    process.stderr.write(
      `usage: node fuzz/harness.mjs <${Object.keys(TARGETS).join('|')}> `
        + '[--seed N] [--seeds A..B] [--iterations K]\n',
    );
    process.exit(2);
    return;
  }

  const targetModule = await import(pathToFileURL(join(HERE, TARGETS[args.target])).href);
  const target = targetModule.default;
  const seeds = seedRange(args.seeds, args.seed);
  const iterations = Number.isSafeInteger(args.iterations) && args.iterations > 0 ? args.iterations : 200;

  const startedAt = process.hrtime.bigint();
  let totalIterations = 0;
  let totalOps = 0;

  process.stdout.write(
    `fuzz target=${target.name} seeds=${seeds[0]}..${seeds[seeds.length - 1]} `
      + `iterations/seed=${iterations}\n`,
  );
  process.stdout.write(`invariants: ${target.invariants.join(', ')}\n`);

  for (const seed of seeds) {
    const rng = createRng(seed);
    for (let iteration = 0; iteration < iterations; iteration += 1) {
      try {
        const result = await target.iterate({ rng, iteration, seed });
        totalIterations += 1;
        totalOps += result?.ops ?? 0;
      } catch (error) {
        if (error instanceof InvariantViolation) {
          process.stdout.write('\n');
          process.stdout.write('!!! FUZZ FOUND AN INVARIANT VIOLATION !!!\n');
          process.stdout.write(`  target:     ${target.name}\n`);
          process.stdout.write(`  seed:       ${seed}\n`);
          process.stdout.write(`  iteration:  ${iteration}\n`);
          process.stdout.write(`  invariant:  ${error.invariant}\n`);
          process.stdout.write(`  detail:     ${error.detail}\n`);
          process.stdout.write(`  replay:     node fuzz/harness.mjs ${target.name} --seed ${seed} --iterations ${iteration + 1}\n`);
          process.exit(1);
          return;
        }
        throw error;
      }
    }
  }

  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  process.stdout.write(
    `OK  ${totalIterations} iterations across ${seeds.length} seed(s), `
      + `${totalOps} concurrent operations driven, all invariants held `
      + `(${elapsedMs.toFixed(0)} ms)\n`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch((error) => {
    process.stderr.write(`fuzz harness crashed: ${error?.stack || error}\n`);
    process.exit(3);
  });
}
