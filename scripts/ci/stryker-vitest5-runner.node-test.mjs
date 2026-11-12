// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { vitest5NamePattern, wrapVitest5Runner } from './stryker-vitest5-runner.mjs';

test('keeps nested suites and regex metacharacters selectable in Vitest 5', () => {
  const pattern = vitest5NamePattern(/Outer \[x\] Inner \(y\) test \$value/);
  assert.match('Outer [x] > Inner (y) > test $value', pattern);
  assert.match('Outer [x] Inner (y) test $value', pattern);
  assert.doesNotMatch('Outer x > Inner (y) > test $value', pattern);
  const literalArrow = vitest5NamePattern(/Outer > \[x\] Inner \(y\) test \$value/);
  assert.match('Outer > [x] > Inner (y) > test $value', literalArrow);
});

test('adapts each worker before its mutant run without changing dry-run IDs', async () => {
  let patternAtExecution;
  const runner = wrapVitest5Runner({
    ctx: null,
    async init() {
      this.ctx = {
        projects: [{ config: {} }],
        start: async () => {
          patternAtExecution = this.ctx.projects[0].config.testNamePattern;
        },
      };
    },
    async mutantRun() {
      this.ctx.projects[0].config.testNamePattern = /Outer \[x\] Inner \(y\) test \$value/;
      await this.ctx.start();
      return { status: 'killed', nrOfTests: 1 };
    },
  });

  await runner.init();
  await runner.mutantRun({ testFilter: ['tests/example.test.ts#Outer [x] Inner (y) test $value'] });
  assert.match('Outer [x] > Inner (y) > test $value', patternAtExecution);
});

test('refuses to silently survive when a covered mutant runs zero tests', async () => {
  const runner = wrapVitest5Runner({
    ctx: null,
    async init() {
      this.ctx = { projects: [], start: async () => {} };
    },
    async mutantRun() {
      return { status: 'survived', nrOfTests: 0 };
    },
  });

  await runner.init();
  await assert.rejects(
    runner.mutantRun({ testFilter: ['tests/example.test.ts#covered test'] }),
    /Covered mutant executed zero Vitest tests/,
  );
});
