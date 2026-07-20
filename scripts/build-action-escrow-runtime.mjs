#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), '..');
const sourcePath = resolve(
  repositoryRoot,
  'lib/integrations/action-escrow/procore-change-order.ts',
);
const runtimePath = resolve(
  repositoryRoot,
  'lib/integrations/action-escrow/procore-change-order.js',
);
const GENERATED_BANNER =
  '// Generated from procore-change-order.ts by scripts/build-action-escrow-runtime.mjs. Do not edit.\n';

export async function renderActionEscrowRuntime() {
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
  if (!result.outputText.startsWith('// SPDX-License-Identifier: Apache-2.0\n')) {
    throw new Error('Action Escrow runtime source must retain its Apache-2.0 header');
  }
  return result.outputText.replace(
    '// SPDX-License-Identifier: Apache-2.0\n',
    `// SPDX-License-Identifier: Apache-2.0\n${GENERATED_BANNER}`,
  );
}

export async function buildActionEscrowRuntime({ check = false } = {}) {
  const expected = await renderActionEscrowRuntime();
  if (check) {
    let actual = null;
    try {
      actual = await readFile(runtimePath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (actual !== expected) {
      throw new Error(
        'Action Escrow Node 20 runtime is missing or stale; run npm run build:action-escrow-runtime',
      );
    }
    process.stdout.write('ACTION ESCROW RUNTIME: synchronized\n');
    return;
  }
  await writeFile(runtimePath, expected, 'utf8');
  process.stdout.write('ACTION ESCROW RUNTIME: generated\n');
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await buildActionEscrowRuntime({ check: process.argv.includes('--check') });
}
