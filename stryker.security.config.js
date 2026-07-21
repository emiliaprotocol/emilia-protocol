// SPDX-License-Identifier: Apache-2.0
// High-assurance mutation gate for the acceptance and replay kernels.
import { readFileSync } from 'node:fs';

function mutationRange(file, startMarker, endMarker) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const startIndex = lines.findIndex((line) => line.includes(startMarker));
  const endIndex = lines.findIndex(
    (line, index) => index >= startIndex && line.includes(endMarker),
  );
  if (startIndex < 0 || endIndex < startIndex) {
    throw new Error(
      `Mutation range markers not found in ${file}: ${startMarker} -> ${endMarker}`,
    );
  }
  return `${file}:${startIndex + 1}-${endIndex + 1}`;
}

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
    //
    // These packages/gate and packages/verify files were converted from
    // hand-written .js to compiled TypeScript (src/*.ts -> dist/*.js, with a
    // re-export shim left at the old .js path for existing consumers). The
    // ranges below were re-derived line-for-line against packages/gate/src/*.ts
    // and packages/verify/src/reliance.ts so the tested surface is unchanged.
    'packages/gate/src/store.ts:64-72',
    'packages/gate/src/store.ts:73-164',
    // Resolve this range from semantic anchors. A fixed line range drifted into
    // an unrelated helper when Gate composition code was inserted above
    // createGate, producing untested mutants while the intended admission
    // kernel escaped mutation.
    mutationRange(
      'packages/gate/src/index.ts',
      'if (capabilityStore &&',
      'const businessExpected = businessAuthorizationRequirement(requirement);',
    ),
    'packages/gate/src/breakglass.ts:223-225',
    'packages/gate/src/breakglass.ts:237-248',
    'packages/gate/src/breakglass.ts:327-327',
    'packages/gate/src/breakglass.ts:333-334',
    'packages/gate/src/breakglass.ts:338-338',
    'packages/gate/src/breakglass.ts:343-343',
    'packages/gate/src/breakglass.ts:347-356',
    'packages/gate/src/breakglass.ts:366-368',
    'packages/gate/src/breakglass.ts:548-549',
    'packages/gate/src/breakglass.ts:551-551',
    'packages/gate/src/breakglass.ts:568-568',
    'packages/gate/src/breakglass.ts:580-582',
    'packages/gate/src/breakglass.ts:592-599',
    'packages/gate/src/breakglass.ts:609-609',
    'packages/gate/src/key-registry.ts:55-61',
    'packages/gate/src/key-registry.ts:77-84',
    'packages/gate/src/key-registry.ts:90-103',
    'packages/gate/src/execution-binding.ts:54-61',
    'packages/gate/src/execution-binding.ts:112-123',
    'packages/gate/src/execution-binding.ts:161-176',
    'packages/gate/src/execution-binding.ts:181-204',
    'packages/verify/src/reliance.ts:69-575',
    'lib/authority/resolver.js:57-378',
  ],
  testFiles: [
    'tests/gate-security-remediation.test.{js,ts}',
    'tests/gate-execution-binding-failclosed.test.{js,ts}',
    'tests/mutation-security-kernel.test.{js,ts}',
    'tests/reliance-kernel.test.{js,ts}',
    'tests/authority-registry.test.{js,ts}',
    'tests/audit-regression.test.{js,ts}',
  ],
  thresholds: {
    // CI may improve this score, but may never silently fall below the 90% floor.
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
