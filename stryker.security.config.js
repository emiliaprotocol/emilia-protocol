// SPDX-License-Identifier: Apache-2.0
// High-assurance mutation gate for the acceptance and replay kernels.
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
    // Include every helper that can change a security verdict or the bytes it
    // binds. Constants, exports, and the legacy in-memory demo store remain out
    // of scope; signed-material extraction and strict time parsing do not.
    'packages/gate/store.js:58-66',
    'packages/gate/store.js:67-152',
    'packages/gate/index.js:353-371',
    'packages/gate/breakglass.js:193-195',
    'packages/gate/breakglass.js:205-216',
    'packages/gate/breakglass.js:288-288',
    'packages/gate/breakglass.js:294-295',
    'packages/gate/breakglass.js:299-299',
    'packages/gate/breakglass.js:304-304',
    'packages/gate/breakglass.js:308-317',
    'packages/gate/breakglass.js:327-329',
    'packages/gate/breakglass.js:509-510',
    'packages/gate/breakglass.js:512-512',
    'packages/gate/breakglass.js:521-521',
    'packages/gate/breakglass.js:533-535',
    'packages/gate/breakglass.js:545-550',
    'packages/gate/breakglass.js:560-560',
    'packages/gate/key-registry.js:40-46',
    'packages/gate/key-registry.js:62-69',
    'packages/gate/key-registry.js:75-88',
    'packages/gate/execution-binding.js:54-61',
    'packages/gate/execution-binding.js:112-123',
    'packages/gate/execution-binding.js:159-174',
    'packages/gate/execution-binding.js:179-202',
    'packages/verify/reliance.js:69-572',
    'lib/authority/resolver.js:57-378',
  ],
  testFiles: [
    'tests/gate-security-remediation.test.js',
    'tests/gate-execution-binding-failclosed.test.js',
    'tests/mutation-security-kernel.test.js',
    'tests/reliance-kernel.test.js',
    'tests/authority-registry.test.js',
    'tests/audit-regression.test.js',
  ],
  thresholds: {
    // Ratcheted over the full ranges above: 90.34% total / 91.03% covered.
    // CI may improve it, but may never silently fall below the 90% floor.
    high: 95,
    low: 90,
    break: 90,
  },
  reporters: ['clear-text', 'progress', 'json'],
  jsonReporter: { fileName: 'reports/mutation/security-kernel.json' },
  concurrency: 4,
  timeoutMS: 30000,
  tempDirName: '.stryker-security-tmp',
  cleanTempDir: true,
  // Run the complete security suite against every mutant. Table-driven and
  // dynamically assembled protocol vectors cross helper boundaries that
  // per-test instrumentation can under-attribute.
  coverageAnalysis: 'all',
  mutator: {
    // Reason-message wording is not a security oracle; closed verdict values
    // are already asserted exactly by conformance vectors.
    excludedMutations: ['StringLiteral'],
  },
};
