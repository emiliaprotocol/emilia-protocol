// SPDX-License-Identifier: Apache-2.0
// Stryker 9.6.1 records Vitest test IDs as "suite test", while Vitest 5
// filters on "suite > test". Without this adapter, covered mutants run zero
// tests and silently survive. Normalize only the test-name filter at execution;
// leave Stryker's dry-run IDs and per-test coverage IDs unchanged. Since those
// IDs lose suite boundaries, this may select extra tests within a covering
// file; it must never omit a covering test. Mutation thresholds remain intact.
// Remove this shim once upstream matches Vitest 5 names and the focused
// non-static mutant regression passes without it.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { declareFactoryPlugin, PluginKind } from '@stryker-mutator/api/plugin';
import {
  strykerPlugins as upstreamPlugins,
  strykerValidationSchema,
} from '@stryker-mutator/vitest-runner';

const require = createRequire(import.meta.url);
const packagePath = require.resolve('@stryker-mutator/vitest-runner/package.json');
const { version } = require(packagePath);
const helperSource = readFileSync(
  path.join(path.dirname(packagePath), 'dist/src/test-helpers.js'), 'utf8',
);
if (version !== '9.6.1' || !helperSource.includes("return nameParts.join(' ').trim();")) {
  throw new Error('Review Stryker Vitest name-filter shim before changing the upstream runner');
}

// Stryker's published plugin type includes factory variants without `.inject`;
// the installed Vitest 9.6.1 factory is checked at runtime below.
const upstreamFactory = /** @type {any} */ (upstreamPlugins.find(
  (plugin) => plugin.kind === PluginKind.TestRunner && plugin.name === 'vitest',
)?.factory);

if (typeof upstreamFactory !== 'function' || !Array.isArray(upstreamFactory.inject)) {
  throw new Error('Stryker Vitest runner factory or inject tokens are unavailable');
}

// Stryker escapes regex metacharacters but not spaces. Every original space
// can be inside a title (still a space) or between suite/title in Vitest 5
// (" > "). Matching both keeps the covering test and may run an extra test,
// which is safe for mutation testing. Stryker escapes title metacharacters;
// this adapter inserts only the fixed non-capturing alternative.
export function vitest5NamePattern(pattern) {
  return new RegExp(pattern.source.replaceAll(' ', '(?: | > )'), pattern.flags);
}

export function wrapVitest5Runner(runner) {
  const init = runner.init.bind(runner);
  const mutantRun = runner.mutantRun.bind(runner);

  runner.init = async () => {
    await init();
    if (!runner.ctx || !Array.isArray(runner.ctx.projects)) {
      throw new Error('Stryker Vitest context is unavailable');
    }
    const start = runner.ctx.start.bind(runner.ctx);
    runner.ctx.start = (...args) => {
      for (const project of runner.ctx.projects) {
        const pattern = project.config.testNamePattern;
        if (pattern instanceof RegExp) {
          project.config.testNamePattern = vitest5NamePattern(pattern);
        }
      }
      return start(...args);
    };
  };

  runner.mutantRun = async (options) => {
    const result = await mutantRun(options);
    if (options.testFilter?.some((id) => id.includes('#')) && result.nrOfTests === 0) {
      throw new Error('Covered mutant executed zero Vitest tests');
    }
    return result;
  };

  return runner;
}

function createVitest5Runner(injector) {
  return wrapVitest5Runner(upstreamFactory(injector));
}
createVitest5Runner.inject = upstreamFactory.inject;

export const strykerPlugins = [
  declareFactoryPlugin(PluginKind.TestRunner, 'vitest-5', createVitest5Runner),
];
export { strykerValidationSchema };
