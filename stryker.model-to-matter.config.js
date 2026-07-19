// SPDX-License-Identifier: Apache-2.0
// Full decision-surface mutation campaign for Model-to-Matter.
/** @type {import('@stryker-mutator/core').PartialStrykerOptions} */
export default {
  testRunner: 'vitest',
  vitest: { configFile: 'vitest.config.js', related: false },
  ignorePatterns: [
    'sdks/swift-mobile/.build/**',
    'sdks/kotlin-mobile/.gradle/**',
    'sdks/kotlin-mobile/build/**',
    'sdks/kotlin-mobile/sample/build/**',
    '.next/**',
    'reports/**',
  ],
  // Every executable function from sha256hex through effect verification.
  // Module-scope frozen protocol tables and export aggregation are exact-tested
  // separately; Vitest loads those ESM initializers before mutant activation.
  mutate: ['lib/frontier/model-to-matter.js:107-1127'],
  testFiles: [
    'tests/model-to-matter.test.js',
    'tests/model-to-matter-security-branches.test.js',
    'tests/model-to-matter-mutation-oracles.test.js',
  ],
  thresholds: {
    // See the status file for the score produced by the current source and
    // test corpus. The floor is never lowered to make a campaign pass.
    high: 90,
    low: 80,
    break: 80,
  },
  reporters: ['clear-text', 'progress', 'json'],
  jsonReporter: { fileName: 'reports/mutation/model-to-matter.json' },
  concurrency: 4,
  timeoutMS: 30000,
  tempDirName: '.stryker-model-to-matter-tmp',
  cleanTempDir: true,
  coverageAnalysis: 'all',
  mutator: { excludedMutations: ['StringLiteral'] },
};
