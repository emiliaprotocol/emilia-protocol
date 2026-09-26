// SPDX-License-Identifier: Apache-2.0
// Mutation score alone is not sufficient: Stryker can report a covered mutant
// as survived after its Vitest filter accidentally executes zero tests.
import { readFileSync } from 'node:fs';

export function assertMutationReport(report) {
  if (report?.framework?.name !== 'StrykerJS' || !report.files || typeof report.files !== 'object') {
    throw new Error('Missing or invalid Stryker mutation report');
  }

  let total = 0;
  let scored = 0;
  for (const [file, entry] of Object.entries(report.files)) {
    if (!Array.isArray(entry.mutants)) throw new Error(`Missing mutants for ${file}`);
    for (const mutant of entry.mutants) {
      total += 1;
      if (mutant.status === 'RuntimeError' || mutant.status === 'CompileError') {
        throw new Error(`Mutation runner error: ${file} mutant ${mutant.id}`);
      }
      if (mutant.status === 'Survived' && !(mutant.testsCompleted > 0)) {
        throw new Error(`Surviving mutant ran zero tests: ${file} mutant ${mutant.id}`);
      }
      if (['Killed', 'Timeout', 'Survived', 'NoCoverage'].includes(mutant.status)) scored += 1;
      else if (mutant.status !== 'Ignored') throw new Error(`Unknown mutation status: ${file} mutant ${mutant.id}`);
    }
  }
  if (total === 0 || scored === 0) throw new Error('Empty Stryker mutation score denominator');
  return total;
}

export function mutationGateExitCode({ code, signal }, validationFailed) {
  if (code !== null && code !== 0) return code;
  return signal || code === null || validationFailed ? 1 : 0;
}

export function validateMutationReportFile(file) {
  const report = JSON.parse(readFileSync(file, 'utf8'));
  return assertMutationReport(report);
}
