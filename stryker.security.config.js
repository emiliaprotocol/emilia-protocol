// SPDX-License-Identifier: Apache-2.0
// High-assurance mutation gate for the acceptance and replay kernels.
/** @type {import('@stryker-mutator/core').PartialStrykerOptions} */
export default {
  testRunner: 'vitest',
  vitest: { configFile: 'vitest.config.js', related: false },
  mutate: [
    // Include every helper that can change a security verdict or the bytes it
    // binds. Constants, exports, and the legacy in-memory demo store remain out
    // of scope; signed-material extraction and strict time parsing do not.
    'packages/gate/store.js:57-142',
    'packages/verify/reliance.js:69-572',
    'lib/authority/resolver.js:57-378',
  ],
  testFiles: [
    'tests/mutation-security-kernel.test.js',
    'tests/reliance-kernel.test.js',
    'tests/authority-registry.test.js',
    'tests/audit-regression.test.js',
  ],
  thresholds: {
    // Ratcheted over the full ranges above: 81.55% total / 82.19% covered.
    // CI may improve it, but may never silently fall below the 80% floor.
    high: 85,
    low: 80,
    break: 80,
  },
  reporters: ['clear-text', 'progress', 'json'],
  jsonReporter: { fileName: 'reports/mutation/security-kernel.json' },
  concurrency: 4,
  timeoutMS: 30000,
  tempDirName: '.stryker-security-tmp',
  cleanTempDir: true,
  coverageAnalysis: 'perTest',
  mutator: {
    // Reason-message wording is not a security oracle; closed verdict values
    // are already asserted exactly by conformance vectors.
    excludedMutations: ['StringLiteral'],
  },
};
