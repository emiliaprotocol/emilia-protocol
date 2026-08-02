// SPDX-License-Identifier: Apache-2.0
// Generated from check-packed-package-exports.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
];
function run(command, args, cwd = ROOT) {
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
        throw new Error(`${command} ${args.join(' ')} failed (${String(result.status)}):\n`
            + `${result.stdout || ''}${result.stderr || ''}`);
    }
    return result.stdout;
}
const MODULE_EXTENSIONS = new Set(['.cjs', '.js', '.mjs']);
const ASSET_EXTENSIONS = new Set(['.json', '.sql', '.wasm']);
export function packageTargets(name, packageJson) {
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
                ? exportValue.import
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
export function typedPackageSpecifiers(name, packageJson) {
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
            ? exportValue.types
            : undefined;
        if (typeof typesPath !== 'string')
            return [];
        return [subpath === '.' ? name : `${name}/${subpath.slice(2)}`];
    });
}
export function checkPackedPackageExports() {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-packed-exports-'));
    try {
        const tarballs = [];
        const targets = [];
        const typedSpecifiers = [];
        for (const item of PACKAGES) {
            const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, item.directory, 'package.json'), 'utf8'));
            targets.push(...packageTargets(item.name, packageJson));
            typedSpecifiers.push(...typedPackageSpecifiers(item.name, packageJson));
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
        fs.writeFileSync(path.join(temporary, 'package.json'), JSON.stringify({ private: true, type: 'module' }), { encoding: 'utf8', mode: 0o600 });
        run('npm', [
            'install',
            '--ignore-scripts',
            '--no-audit',
            '--no-fund',
            ...tarballs,
        ], temporary);
        const imports = targets.filter((target) => target.kind === 'module');
        const assets = targets.filter((target) => target.kind === 'asset');
        const program = `
      import { readFile } from 'node:fs/promises';
      import { fileURLToPath } from 'node:url';
      const imports = ${JSON.stringify(imports.map(({ specifier }) => specifier))};
      const assets = ${JSON.stringify(assets.map(({ specifier }) => specifier))};
      for (const target of imports) {
        await import(target);
      }
      for (const target of assets) {
        const resolved = import.meta.resolve(target);
        const bytes = await readFile(fileURLToPath(resolved));
        if (bytes.length === 0) {
          throw new Error(target + ' resolved to an empty packaged asset');
        }
      }
      process.stdout.write(JSON.stringify({imports: imports.length, assets: assets.length}));
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
        const typeConsumer = typedSpecifiers
            .map((specifier, index) => `import * as package${index} from ${JSON.stringify(specifier)};\nvoid package${index};`)
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
    }
    finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const result = checkPackedPackageExports();
    process.stdout.write(`Packed package exports: ${result.packages} packages, ${result.imports} imports, ${result.assets} assets and ${result.declarations} typed entries passed.\n`);
}
