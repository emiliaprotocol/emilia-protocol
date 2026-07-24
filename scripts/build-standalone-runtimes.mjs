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

import fsSync from 'node:fs';

import { companionSources } from './standalone-runtime-targets.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), '..');
const SCRIPT_NAME = 'scripts/build-standalone-runtimes.mjs';

const TARGETS = companionSources(fsSync, repositoryRoot).map((relativeSource) => {
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
  const spdxLine = '// SPDX-License-Identifier: Apache-2.0\n';
  let outputText = result.outputText;
  let shebangMatch = outputText.match(/^#!.*\n/);
  let afterShebang = shebangMatch ? outputText.slice(shebangMatch[0].length) : outputText;
  // TypeScript can attach a leading license comment to a type-only import and
  // drop both during transpilation. Restore that exact SPDX line when the
  // source carried it so generated Node 20 companions never lose licensing.
  if (/Apache-2\.0/.test(source) && !/Apache-2\.0/.test(afterShebang)) {
    outputText = shebangMatch
      ? `${shebangMatch[0]}${spdxLine}${afterShebang}`
      : `${spdxLine}${outputText}`;
    shebangMatch = outputText.match(/^#!.*\n/);
    afterShebang = shebangMatch ? outputText.slice(shebangMatch[0].length) : outputText;
  }
  if (outputText.includes(spdxLine)) {
    return outputText.replace(spdxLine, `${spdxLine}${banner}`);
  }
  // No SPDX line comment to anchor on (e.g. a JSDoc @license block instead):
  // insert the banner right after the shebang, or at the very top otherwise.
  return shebangMatch
    ? `${shebangMatch[0]}${banner}${afterShebang}`
    : `${banner}${result.outputText}`;
}

// .gitattributes carries a linguist-generated entry per companion (between the
// BEGIN/END markers below) so GitHub's language stats count only real source.
// The block is owned by this script: --write rewrites it, --check gates it.
const GITATTRIBUTES_PATH = resolve(repositoryRoot, '.gitattributes');
const ATTR_BEGIN = '# BEGIN standalone-runtime companions (generated; do not edit by hand)';
const ATTR_END = '# END standalone-runtime companions';

async function syncGitattributes({ check }) {
  const current = await readFile(GITATTRIBUTES_PATH, 'utf8');
  const beginAt = current.indexOf(ATTR_BEGIN);
  const endAt = current.indexOf(ATTR_END);
  if (beginAt === -1 || endAt === -1 || endAt < beginAt) {
    throw new Error(`.gitattributes is missing the "${ATTR_BEGIN}" ... "${ATTR_END}" block`);
  }
  const block = TARGETS
    .map((target) => `${target.runtimePath.slice(repositoryRoot.length + 1)} linguist-generated=true\n`)
    .join('');
  const expected = `${current.slice(0, beginAt + ATTR_BEGIN.length)}\n${block}${current.slice(endAt)}`;
  if (current === expected) return;
  if (check) {
    throw new Error('.gitattributes companion block is stale; run npm run build:standalone-runtimes');
  }
  await writeFile(GITATTRIBUTES_PATH, expected, 'utf8');
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
    // Clobber guard: never overwrite a runtime path that holds a handwritten
    // (non-generated) file -- the dir-glob scan could otherwise silently
    // replace a real .js sibling of a TS-first source with transpiled output.
    let existing = null;
    try {
      existing = await readFile(target.runtimePath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (existing !== null && existing !== expected
      && !existing.includes(`by ${SCRIPT_NAME}. Do not edit.`)) {
      throw new Error(
        `${target.relativeSource}: refusing to overwrite handwritten ${target.runtimePath.slice(repositoryRoot.length + 1)} with generated output`,
      );
    }
    await writeFile(target.runtimePath, expected, 'utf8');
  }
  await syncGitattributes({ check });
  process.stdout.write(
    `STANDALONE RUNTIMES: ${check ? 'synchronized' : 'generated'} (${TARGETS.length})\n`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await buildStandaloneRuntimes({ check: process.argv.includes('--check') });
}
