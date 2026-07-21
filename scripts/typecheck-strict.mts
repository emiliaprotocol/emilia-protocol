#!/usr/bin/env node

/**
 * Run the migration probe against a clean compiler program.
 *
 * The normal typecheck gates intentionally remain compatible with the current
 * JavaScript codebase. This opt-in probe turns on noImplicitAny and disables
 * incremental state so migration progress cannot be confused with a cached
 * zero-error result.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root: string = process.cwd();
const tsc: string = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
if (!existsSync(tsc)) {
  console.error(`TypeScript compiler not found at ${tsc}. Run npm ci first.`);
  process.exit(2);
}

const tiers: readonly string[] = ['core', 'lib', 'rest', 'app'];
const failures: Array<{ tier: string; errors: number; status: number | null }> = [];

for (const tier of tiers) {
  const result = spawnSync(process.execPath, [
    tsc,
    '-p', `tsconfig.${tier}.json`,
    '--noEmit',
    '--incremental', 'false',
    '--noImplicitAny', 'true',
    '--pretty', 'false',
  ], { cwd: root, encoding: 'utf8' });

  const output: string = `${result.stdout || ''}${result.stderr || ''}`;
  const errors: number = output.match(/error TS\d+/g)?.length || 0;
  console.log(`[typecheck:strict:${tier}] ${errors} error${errors === 1 ? '' : 's'}`);
  if (output) process.stdout.write(output);
  if (result.status !== 0) failures.push({ tier, errors, status: result.status });
}

if (failures.length) {
  console.error('\nStrict migration probe is not yet clean.');
  process.exit(1);
}

console.log('\nStrict migration probe is clean.');
