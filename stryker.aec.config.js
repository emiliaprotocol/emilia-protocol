// SPDX-License-Identifier: Apache-2.0
// Focused mutation campaign for AEC acceptance, execution, and fleet logging.
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
  mutate: [
    'packages/verify/evidence-chain.js:55-532',
    'packages/gate/aec-execution.js:20-287',
    'packages/gate/evidence.js:27-40',
    'packages/gate/evidence.js:99-307',
  ],
  testFiles: [
    'tests/aec-safety-critical.test.js',
    'tests/aec-role-conformance.test.js',
    'tests/aec-mutation-oracles.test.js',
    'tests/aec-isolated-refusals.test.js',
    'tests/aec-execution-gate.test.js',
    'tests/role-non-substitution.test.js',
    'tests/atomic-evidence-log.test.js',
  ],
  thresholds: {
    // Ratcheted over the complete public AEC verifier boundary, execution gate,
    // and fleet-safe evidence log: 80.15% total / 81.68% covered.
    high: 90,
    low: 80,
    break: 80,
  },
  reporters: ['clear-text', 'progress', 'json'],
  jsonReporter: { fileName: 'reports/mutation/aec-kernel.json' },
  concurrency: 4,
  timeoutMS: 30000,
  tempDirName: '.stryker-aec-tmp',
  cleanTempDir: true,
  coverageAnalysis: 'all',
  mutator: { excludedMutations: ['StringLiteral'] },
};
