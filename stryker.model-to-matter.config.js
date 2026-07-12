// SPDX-License-Identifier: Apache-2.0
// Full decision-surface mutation campaign for Model-to-Matter.
/** @type {import('@stryker-mutator/core').PartialStrykerOptions} */
export default {
  testRunner: 'vitest',
  vitest: { configFile: 'vitest.config.js', related: false },
  mutate: ['lib/frontier/model-to-matter.js:83-1006'],
  testFiles: [
    'tests/model-to-matter.test.js',
    'tests/model-to-matter-security-branches.test.js',
    'tests/model-to-matter-mutation-oracles.test.js',
  ],
  thresholds: {
    // Ratcheted over the complete Model-to-Matter decision surface:
    // 80.27% total / 82.35% covered.
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
