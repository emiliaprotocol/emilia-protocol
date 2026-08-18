// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES = [
  { name: '@emilia-protocol/verify', directory: 'packages/verify' },
  // Gate pins this package exactly. Install the candidate tarball in the blank
  // consumer so an unpublished patch never falls back to an older npm build.
  { name: '@emilia-protocol/require-receipt', directory: 'packages/require-receipt' },
  { name: '@emilia-protocol/gate', directory: 'packages/gate' },
  { name: '@emilia-protocol/scan', directory: 'packages/scan' },
  // Every publishable package with a closed exports map belongs behind the
  // blank-consumer check. This catches dependencies or relative imports that
  // happen to work only inside the monorepo or a flat node_modules layout.
  { name: '@emilia-protocol/mcp-guard', directory: 'packages/mcp-guard' },
  { name: '@emilia-protocol/attest', directory: 'packages/attest' },
  { name: '@emilia-protocol/issue', directory: 'packages/issue' },
  { name: '@emilia-protocol/langchain', directory: 'packages/langchain' },
  { name: '@emilia-protocol/langgraph', directory: 'packages/langgraph' },
  { name: '@emilia-protocol/openai-agents', directory: 'packages/openai-agents' },
  { name: '@emilia-protocol/openai-guard', directory: 'packages/openai-guard' },
  { name: '@emilia-protocol/fire-drill', directory: 'packages/fire-drill' },
  { name: '@emilia-protocol/fire-drill-mcp', directory: 'packages/fire-drill-mcp' },
  // crash-test and mobile are deliberately absent: neither declares a closed
  // exports map. Add them here when they expose an importable package surface.
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

type PackageTarget = {
  specifier: string;
  kind: 'module' | 'asset';
};

const MODULE_EXTENSIONS = new Set(['.cjs', '.js', '.mjs']);
const ASSET_EXTENSIONS = new Set(['.json', '.sql', '.wasm']);
// Declaration/runtime parity is release-gated for new subpaths as they are
// introduced. Expanding this set requires fixing any older wrapper debt first.
const DEFAULT_EXPORT_PARITY_SPECIFIERS = new Set([
  '@emilia-protocol/gate/recovery-admission',
  '@emilia-protocol/gate/recovery-admission-postgres',
  '@emilia-protocol/gate/recovery-admission-remedy',
]);

export function packageTargets(
  name: string,
  packageJson: Record<string, any>,
): PackageTarget[] {
  const exportsMap = packageJson.exports;
  if (!exportsMap || typeof exportsMap !== 'object' || Array.isArray(exportsMap)) {
    throw new Error(`${name} has no closed package exports map`);
  }
  return Object.entries(exportsMap)
    .filter(([subpath]) => subpath !== './package.json')
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([subpath, exportValue]) => {
      const importPath = typeof exportValue === 'string'
        ? exportValue
        : exportValue && typeof exportValue === 'object' && !Array.isArray(exportValue)
          ? (exportValue as Record<string, unknown>).import
          : undefined;
      if (typeof importPath !== 'string') {
        throw new Error(`${name} export ${subpath} has no closed import target`);
      }
      const extension = path.posix.extname(importPath);
      const kind = MODULE_EXTENSIONS.has(extension)
        ? 'module'
        : ASSET_EXTENSIONS.has(extension)
          ? 'asset'
          : undefined;
      if (!kind) {
        throw new Error(`${name} export ${subpath} has unsupported target ${importPath}`);
      }
      return {
        specifier: subpath === '.' ? name : `${name}/${subpath.slice(2)}`,
        kind,
      };
    });
}

export function typedPackageSpecifiers(
  name: string,
  packageJson: Record<string, any>,
): string[] {
  const exportsMap = packageJson.exports;
  if (!exportsMap || typeof exportsMap !== 'object' || Array.isArray(exportsMap)) {
    throw new Error(`${name} has no closed package exports map`);
  }
  return Object.entries(exportsMap)
    .filter(([subpath]) => subpath !== './package.json')
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([subpath, exportValue]) => {
      const typesPath = exportValue && typeof exportValue === 'object'
        && !Array.isArray(exportValue)
        ? (exportValue as Record<string, unknown>).types
        : undefined;
      if (typeof typesPath !== 'string') return [];
      return [subpath === '.' ? name : `${name}/${subpath.slice(2)}`];
    });
}

function defaultTypedPackageSpecifiers(
  name: string,
  directory: string,
  packageJson: Record<string, any>,
): string[] {
  const exportsMap = packageJson.exports;
  if (!exportsMap || typeof exportsMap !== 'object' || Array.isArray(exportsMap)) {
    throw new Error(`${name} has no closed package exports map`);
  }
  return Object.entries(exportsMap)
    .filter(([subpath]) => subpath !== './package.json')
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([subpath, exportValue]) => {
      const typesPath = exportValue && typeof exportValue === 'object'
        && !Array.isArray(exportValue)
        ? (exportValue as Record<string, unknown>).types
        : undefined;
      if (typeof typesPath !== 'string') return [];
      const declaration = fs.readFileSync(path.join(ROOT, directory, typesPath), 'utf8');
      const specifier = subpath === '.' ? name : `${name}/${subpath.slice(2)}`;
      if (!DEFAULT_EXPORT_PARITY_SPECIFIERS.has(specifier)) return [];
      if (!/\bexport\s+(?:default\b|\{[^}]*\bdefault\b[^}]*\}\s+from\b)/s.test(declaration)) {
        return [];
      }
      return [specifier];
    });
}

export function checkPackedPackageExports(): {
  packages: number;
  imports: number;
  assets: number;
  declarations: number;
} {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-packed-exports-'));
  try {
    const tarballs: string[] = [];
    const targets: PackageTarget[] = [];
    const typedSpecifiers: string[] = [];
    const defaultTypedSpecifiers: string[] = [];
    for (const item of PACKAGES) {
      const packageJson = JSON.parse(fs.readFileSync(
        path.join(ROOT, item.directory, 'package.json'),
        'utf8',
      ));
      targets.push(...packageTargets(item.name, packageJson));
      typedSpecifiers.push(...typedPackageSpecifiers(item.name, packageJson));
      defaultTypedSpecifiers.push(...defaultTypedPackageSpecifiers(
        item.name,
        item.directory,
        packageJson,
      ));
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

    const installedScan = fs.realpathSync(path.join(
      temporary,
      'node_modules',
      '@emilia-protocol',
      'scan',
    ));
    const installedRoot = fs.realpathSync(path.join(temporary, 'node_modules'));
    if (!installedScan.startsWith(`${installedRoot}${path.sep}`)) {
      throw new Error(`packed scan resolved outside the blank consumer: ${installedScan}`);
    }

    // Importability is necessary but insufficient for CLI packages. Exercise
    // the real packed binaries and the generated artifact from a blank
    // consumer so workspace-relative imports or unpublished package fallbacks
    // cannot make the release appear healthy.
    const protectedOutput = path.join(temporary, 'emilia');
    run(path.join(temporary, 'node_modules', '.bin', 'scan'), [
      'protect',
      '--sample',
      '--apply',
      '--out', 'emilia',
    ], temporary);
    const setupOutput = run(process.execPath, [
      path.join(protectedOutput, 'verify-setup.mjs'),
    ], temporary);
    if (!setupOutput.includes('EMILIA RR-1 CHECK: PASS — 4/4 cases matched the protected-action contract.')
      || !setupOutput.includes('The synthetic local handler ran exactly once.')) {
      throw new Error('packed scan RR-1 setup check did not prove its four-case action contract');
    }

    const imports = targets.filter((target) => target.kind === 'module');
    const assets = targets.filter((target) => target.kind === 'asset');
    const program = `
      import { readFile } from 'node:fs/promises';
      import { fileURLToPath } from 'node:url';
      const imports = ${JSON.stringify(imports.map(({ specifier }) => specifier))};
      const assets = ${JSON.stringify(assets.map(({ specifier }) => specifier))};
      const defaults = ${JSON.stringify(defaultTypedSpecifiers)};
      for (const target of imports) {
        const loaded = await import(target);
        if (defaults.includes(target) && !Object.hasOwn(loaded, 'default')) {
          throw new Error(target + ' declares a default export but its packed runtime omits it');
        }
      }
      for (const target of assets) {
        const resolved = import.meta.resolve(target);
        const bytes = await readFile(fileURLToPath(resolved));
        if (bytes.length === 0) {
          throw new Error(target + ' resolved to an empty packaged asset');
        }
      }
      process.stdout.write(JSON.stringify({
        imports: imports.length,
        assets: assets.length,
        defaults: defaults.length,
      }));
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
    if (result.assets !== assets.length) {
      throw new Error('packed export smoke returned an incomplete asset count');
    }
    if (result.defaults !== defaultTypedSpecifiers.length) {
      throw new Error('packed export smoke returned an incomplete default-export count');
    }
    const typeConsumer = typedSpecifiers
      .map((specifier, index) => `import * as package${index} from ${JSON.stringify(specifier)};\nvoid package${index};`)
      .concat(defaultTypedSpecifiers.map((specifier, index) =>
        `import defaultPackage${index} from ${JSON.stringify(specifier)};\nvoid defaultPackage${index};`))
      .join('\n');
    fs.writeFileSync(path.join(temporary, 'consumer.ts'), `${typeConsumer}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    run(path.join(ROOT, 'node_modules', '.bin', 'tsc'), [
      '--noEmit',
      '--strict',
      '--skipLibCheck', 'false',
      '--module', 'NodeNext',
      '--moduleResolution', 'NodeNext',
      '--target', 'ES2022',
      '--types', 'node',
      '--typeRoots', path.join(ROOT, 'node_modules', '@types'),
      'consumer.ts',
    ], temporary);
    return {
      packages: PACKAGES.length,
      imports: imports.length,
      assets: assets.length,
      declarations: typedSpecifiers.length,
    };
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = checkPackedPackageExports();
  process.stdout.write(
    `Packed package exports: ${result.packages} packages, ${result.imports} imports, ${result.assets} assets and ${result.declarations} typed entries passed.\n`,
  );
}
