/**
 * EMILIA Protocol — Stryker Mutation Testing Configuration
 * @license Apache-2.0
 *
 * Mutation testing finds test gaps that line-coverage misses: it inserts
 * small code mutations (flipped operators, removed conditionals, swapped
 * constants) and verifies that at least one test fails for each mutation.
 * A surviving mutant means the test suite accepts wrong code — a real gap.
 *
 * Scope: core protocol logic only (lib/handshake/, lib/signoff/, lib/commit.js,
 * lib/protocol-write.js, lib/scoring*.js). App routes and cloud modules are
 * excluded — they are integration-tested through the API, not unit-tested
 * in isolation.
 *
 * Run locally:
 *   npm run test:mutation
 *
 * Expected runtime: ~5-10 minutes (parallelised across available CPUs).
 * Results are written to reports/mutation/mutation.html.
 *
 * Not in the default CI push/PR pipeline (cost: ~10 min per run).
 * Runs on manual dispatch and on the weekly Sunday performance/quality slot.
 *
 * Mutation score targets (see GOVERNANCE.md):
 *   Core protocol logic:   ≥ 80% killed
 *   Scoring functions:     ≥ 75% killed
 *   Signing / crypto:      ≥ 85% killed
 */

/** @type {import('@stryker-mutator/core').PartialStrykerOptions} */
export default {
  testRunner: 'vitest',
  vitest: {
    configFile: 'vitest.config.js',
  },

  // ── Mutation targets ────────────────────────────────────────────────────────
  // Focus on the invariant-bearing protocol core. Exclude:
  //   - app/ routes (thin adapters — integration-tested, not worth mutating)
  //   - lib/logger.js (I/O infrastructure, not protocol logic)
  //   - lib/supabase.js, lib/env.js (config/connection boilerplate)
  //   - lib/cloud/ (cloud control plane — tested via integration suite)
  mutate: [
    'lib/handshake/*.js',
    'lib/signoff/*.js',
    'lib/commit.js',
    'lib/create-receipt.js',
    'lib/canonical-writer.js',
    'lib/protocol-write.js',
    'lib/scoring.js',
    'lib/scoring-v2.js',
    'lib/write-guard.js',
    '!lib/**/*.test.js',
  ],

  // ── Test file pattern ──────────────────────────────────────────────────────
  // Only run the unit test files that directly cover the mutated modules.
  // Keeps the mutation run fast (~5 min vs ~30 min for the full suite).
  testFiles: [
    'tests/handshake*.test.js',
    'tests/signoff*.test.js',
    'tests/commit*.test.js',
    'tests/receipt*.test.js',
    'tests/scoring*.test.js',
    'tests/write-guard*.test.js',
    'tests/protocol-write*.test.js',
    'tests/property-based.test.js',
    'tests/adversarial*.test.js',
  ],

  // ── Thresholds ─────────────────────────────────────────────────────────────
  thresholds: {
    high:   80,   // ≥80% killed → green
    low:    65,   // 65–79%      → yellow (warning)
    break:  50,   // <50%        → CI failure
  },

  // ── Reporters ──────────────────────────────────────────────────────────────
  reporters: ['html', 'clear-text', 'progress'],
  htmlReporter: {
    fileName: 'reports/mutation/mutation.html',
  },

  // ── Performance ────────────────────────────────────────────────────────────
  concurrency: 4,        // parallel test runners
  timeoutMS: 30_000,     // per-mutant timeout

  // ── Ignored mutants ────────────────────────────────────────────────────────
  // Suppress known-equivalent or low-value mutations that would require
  // extremely specific test oracles to kill.
  ignoredMutations: [
    // String literal mutations in error codes — hundreds of variants, low signal
    'StringLiteral',
  ],

  // ── Output ─────────────────────────────────────────────────────────────────
  tempDirName: '.stryker-tmp',
  cleanTempDir: true,
};
