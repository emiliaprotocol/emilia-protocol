// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES = [
  { name: '@emilia-protocol/verify', directory: 'packages/verify' },
  { name: '@emilia-protocol/gate', directory: 'packages/gate' },
] as const;

function run(command: string, args: string[], cwd = ROOT): string {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
      FORCE_COLOR: '0',
    },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed (${String(result.status)}):\n`
      + `${result.stdout || ''}${result.stderr || ''}`,
    );
  }
  return result.stdout;
}

function packageTargets(name: string, packageJson: Record<string, any>): string[] {
  const exportsMap = packageJson.exports;
  if (!exportsMap || typeof exportsMap !== 'object' || Array.isArray(exportsMap)) {
    throw new Error(`${name} has no closed package exports map`);
  }
  return Object.keys(exportsMap)
    .filter((subpath) => subpath !== './package.json')
    .sort()
    .map((subpath) => (subpath === '.' ? name : `${name}/${subpath.slice(2)}`));
}

export function checkPackedPackageExports(): { packages: number; imports: number } {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-packed-exports-'));
  try {
    const tarballs: string[] = [];
    const imports: string[] = [];
    for (const item of PACKAGES) {
      const packageJson = JSON.parse(fs.readFileSync(
        path.join(ROOT, item.directory, 'package.json'),
        'utf8',
      ));
      imports.push(...packageTargets(item.name, packageJson));
      const report = JSON.parse(run('npm', [
        'pack',
        path.join(ROOT, item.directory),
        '--json',
        '--pack-destination',
        temporary,
      ]));
      if (!Array.isArray(report) || report.length !== 1
          || typeof report[0]?.filename !== 'string') {
        throw new Error(`npm pack returned an invalid report for ${item.name}`);
      }
      tarballs.push(path.join(temporary, report[0].filename));
    }

    fs.writeFileSync(
      path.join(temporary, 'package.json'),
      JSON.stringify({ private: true, type: 'module' }),
      { encoding: 'utf8', mode: 0o600 },
    );
    run('npm', [
      'install',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      ...tarballs,
    ], temporary);

    const program = `
      const targets = ${JSON.stringify(imports)};
      for (const target of targets) {
        await import(target);
      }
      process.stdout.write(JSON.stringify({imports: targets.length}));
    `;
    const output = run(process.execPath, [
      '--input-type=module',
      '--eval',
      program,
    ], temporary);
    const result = JSON.parse(output);
    if (result.imports !== imports.length) {
      throw new Error('packed export smoke returned an incomplete import count');
    }
    return { packages: PACKAGES.length, imports: imports.length };
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = checkPackedPackageExports();
  process.stdout.write(
    `Packed package exports: ${result.packages} packages, ${result.imports} imports passed.\n`,
  );
}

