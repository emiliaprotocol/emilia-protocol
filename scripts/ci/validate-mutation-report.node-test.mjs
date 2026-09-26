// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertMutationReport, mutationGateExitCode } from './validate-mutation-report.mjs';

const reportWith = (mutants) => ({
  framework: { name: 'StrykerJS' },
  files: { 'source.ts': { mutants } },
});

test('accepts a covered mutant that actually ran and survived', () => {
  assert.equal(assertMutationReport(reportWith([
    { id: '1', status: 'Survived', coveredBy: ['test-1'], testsCompleted: 1 },
  ])), 1);
});

test('keeps NoCoverage distinct from a zero-test survivor', () => {
  assert.equal(assertMutationReport(reportWith([
    { id: 'uncovered', status: 'NoCoverage', testsCompleted: 0 },
  ])), 1);
});

test('rejects a covered survivor whose Vitest filter ran zero tests', () => {
  assert.throws(() => assertMutationReport(reportWith([
    { id: '1', status: 'Survived', coveredBy: ['test-1'], testsCompleted: 0 },
  ])), /Surviving mutant ran zero tests/);
});

test('rejects a static survivor that ran zero tests even without coveredBy', () => {
  assert.throws(() => assertMutationReport(reportWith([
    { id: 'static', status: 'Survived', testsCompleted: 0 },
  ])), /Surviving mutant ran zero tests/);
});

test('rejects runtime errors excluded from the mutation-score denominator', () => {
  assert.throws(() => assertMutationReport(reportWith([
    { id: '2', status: 'RuntimeError', coveredBy: ['test-1'] },
  ])), /Mutation runner error/);
});

test('rejects missing and empty reports', () => {
  assert.throws(() => assertMutationReport({}), /Missing or invalid/);
  assert.throws(() => assertMutationReport(reportWith([])), /Empty Stryker/);
  assert.throws(() => assertMutationReport(reportWith([
    { id: '3', status: 'Ignored' },
  ])), /Empty Stryker/);
  assert.throws(() => assertMutationReport(reportWith([
    { id: '4', status: 'CompileError' },
  ])), /Mutation runner error/);
});

test('cannot pass a signaled mutation run even with a valid report', () => {
  assert.equal(mutationGateExitCode({ code: null, signal: 'SIGTERM' }, false), 1);
  assert.equal(mutationGateExitCode({ code: 7, signal: null }, false), 7);
  assert.equal(mutationGateExitCode({ code: 0, signal: null }, true), 1);
  assert.equal(mutationGateExitCode({ code: 0, signal: null }, false), 0);
});
