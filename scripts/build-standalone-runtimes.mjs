#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generates Node-20-executable .js companions for .ts sources that are
// imported outside the ts-loader/bundler resolution path: the documented
// Action Escrow example (tested against the minimum supported Node),
// conformance/runners/run-js.mjs (exercised with zero extra tooling by
// deploy/airgap/verify-offline.sh, which the airgap-audit CI job runs on
// Node 20 by design, to prove air-gapped verification needs nothing but
// node + the repo), and apps/gate-service (ships as a BYOC Docker image
// pinned below Node's unflagged stripping threshold, and its own CI job's
// test suite runs on Node 20). Node's built-in TypeScript stripping only
// exists from 22.6 on (unflagged from 23.6), so these consumers need a real
// transpiled .js file, not the ts-loader hook's resolve-only fix. Using
// transpileModule (syntactic type-stripping only, no cross-file semantic
// checking) rather than a full tsc program build is deliberate: these files
// type-check fine under this repo's loose per-tier tsconfigs, but test/
// directories are excluded from every tier's checkJs/typecheck coverage, so
// apps/gate-service/test/helpers.ts in particular has never actually been
// verified against strict-null-checks and isn't worth blocking a Node-20
// compatibility shim on.
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

import { STANDALONE_RUNTIME_SOURCES } from './standalone-runtime-targets.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), '..');
const SCRIPT_NAME = 'scripts/build-standalone-runtimes.mjs';

const TARGETS = STANDALONE_RUNTIME_SOURCES.map((relativeSource) => {
  const sourcePath = resolve(repositoryRoot, relativeSource);
  const runtimePath = sourcePath.replace(/\.mts$/, '.mjs').replace(/\.ts$/, '.js');
  const basename = relativeSource.split('/').pop();
  return {
    relativeSource,
    sourcePath,
    runtimePath,
    // The eslint-disable makes generated output lint-exempt as a unit: the
    // .ts source is what gets linted, and transpileModule can drop detached
    // block comments (a source's own /* eslint-disable */ pragma among them).
    banner: `// Generated from ${basename} by ${SCRIPT_NAME}. Do not edit.\n/* eslint-disable */\n`,
  };
});

async function renderRuntime({ sourcePath, banner }) {
  const source = await readFile(sourcePath, 'utf8');
  const result = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      newLine: ts.NewLineKind.LineFeed,
      removeComments: false,
      sourceMap: false,
      inlineSourceMap: false,
      inlineSources: false,
      verbatimModuleSyntax: true,
    },
    fileName: sourcePath,
    reportDiagnostics: true,
  });
  const errors = (result.diagnostics ?? []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  if (errors.length > 0) {
    throw new Error(ts.formatDiagnostics(errors, {
      getCanonicalFileName: (fileName) => fileName,
      getCurrentDirectory: () => repositoryRoot,
      getNewLine: () => '\n',
    }));
  }
  // Some CLI scripts have a `#!/usr/bin/env node` shebang before the license
  // header; it must stay the first line for direct execution, so the banner
  // is inserted after the header either way, not necessarily at offset 0.
  // Headers themselves vary (`// SPDX-License-Identifier: Apache-2.0` line
  // comment vs. a JSDoc `@license Apache-2.0` block) -- both are legitimate,
  // pre-existing conventions in this repo, so this only checks that transpiling
  // didn't silently drop the license notice, not one exact literal form.
  const shebangMatch = result.outputText.match(/^#!.*\n/);
  const afterShebang = shebangMatch ? result.outputText.slice(shebangMatch[0].length) : result.outputText;
  // Only enforce preservation when the source actually had a license header
  // to begin with -- a handful of these scripts never carried one.
  if (/Apache-2\.0/.test(source) && !/Apache-2\.0/.test(afterShebang.slice(0, 1000))) {
    throw new Error(`${sourcePath} must retain its Apache-2.0 header`);
  }
  const spdxLine = '// SPDX-License-Identifier: Apache-2.0\n';
  if (result.outputText.includes(spdxLine)) {
    return result.outputText.replace(spdxLine, `${spdxLine}${banner}`);
  }
  // No SPDX line comment to anchor on (e.g. a JSDoc @license block instead):
  // insert the banner right after the shebang, or at the very top otherwise.
  return shebangMatch
    ? `${shebangMatch[0]}${banner}${afterShebang}`
    : `${banner}${result.outputText}`;
}

export async function buildStandaloneRuntimes({ check = false } = {}) {
  for (const target of TARGETS) {
    const expected = await renderRuntime(target);
    if (check) {
      let actual = null;
      try {
        actual = await readFile(target.runtimePath, 'utf8');
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
      if (actual !== expected) {
        throw new Error(
          `${target.relativeSource} Node 20 runtime is missing or stale; run npm run build:standalone-runtimes`,
        );
      }
      continue;
    }
    await writeFile(target.runtimePath, expected, 'utf8');
  }
  process.stdout.write(
    `STANDALONE RUNTIMES: ${check ? 'synchronized' : 'generated'} (${TARGETS.length})\n`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await buildStandaloneRuntimes({ check: process.argv.includes('--check') });
}
