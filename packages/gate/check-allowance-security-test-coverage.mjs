#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFile, readdir } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(packageRoot, '../..');
const packageJsonPath = join(packageRoot, 'package.json');
const generatorName = 'scripts/build-standalone-runtimes.mjs';

async function findTypeScriptTests(directory, found = []) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await findTypeScriptTests(path, found);
    } else if (entry.name.endsWith('.test.ts')) {
      found.push(path);
    }
  }
  return found;
}

function qualificationRuns(command, packageRelativePath) {
  return command
    .split(/\s+/)
    .map((token) => token.replace(/^['"]|['"]$/g, ''))
    .includes(packageRelativePath);
}

async function renderCompanion(sourcePath) {
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

  const sourceName = relative(repositoryRoot, sourcePath);
  const banner = `// Generated from ${basename(sourceName)} by ${generatorName}. Do not edit.\n/* eslint-disable */\n`;
  const spdxLine = '// SPDX-License-Identifier: Apache-2.0\n';
  let outputText = result.outputText;
  if (sourceName.startsWith('packages/gate/') && /\.test\.m?ts$/.test(sourceName)) {
    outputText = outputText.replace(/(\bfrom\s+['"])\.\/src\//g, '$1./dist/');
  }
  let shebangMatch = outputText.match(/^#!.*\n/);
  let afterShebang = shebangMatch ? outputText.slice(shebangMatch[0].length) : outputText;
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
  return shebangMatch
    ? `${shebangMatch[0]}${banner}${afterShebang}`
    : `${banner}${result.outputText}`;
}

async function hasSynchronizedCompanion(sourcePath) {
  const companionPath = sourcePath.replace(/\.ts$/, '.js');
  try {
    const [actual, expected] = await Promise.all([
      readFile(companionPath, 'utf8'),
      renderCompanion(sourcePath),
    ]);
    return actual === expected;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));
const qualificationCommand = packageJson.scripts?.['test:qualification'];
if (typeof qualificationCommand !== 'string') {
  throw new Error('packages/gate package.json is missing scripts.test:qualification');
}
const testCommand = packageJson.scripts?.test;
if (typeof testCommand !== 'string' || !testCommand.includes('npm run test:qualification')) {
  throw new Error('packages/gate scripts.test must invoke npm run test:qualification');
}
const prepackCommand = packageJson.scripts?.prepack;
if (prepackCommand !== 'node run-prepack.mjs') {
  throw new Error('packages/gate scripts.prepack must invoke the output-isolated prepack gate');
}
const prepackSource = await readFile(join(packageRoot, 'run-prepack.mjs'), 'utf8');
for (const required of ["'build'", "'test:qualification'"]) {
  if (!prepackSource.includes(required)) {
    throw new Error(`packages/gate prepack gate is missing ${required}`);
  }
}

const allTests = await findTypeScriptTests(packageRoot);
const allowanceTests = [];
for (const testPath of allTests) {
  const source = await readFile(testPath, 'utf8');
  if (/\ballowance\b/i.test(source)) allowanceTests.push(testPath);
}

if (allowanceTests.length === 0) {
  throw new Error('no allowance security TypeScript tests were discovered');
}

const uncovered = [];
for (const testPath of allowanceTests.sort()) {
  const packageRelativePath = relative(packageRoot, testPath);
  if (qualificationRuns(qualificationCommand, packageRelativePath)) continue;
  if (await hasSynchronizedCompanion(testPath)) continue;
  uncovered.push(packageRelativePath);
}

if (uncovered.length > 0) {
  throw new Error(
    `allowance security tests are neither explicitly executed by test:qualification nor represented by synchronized companions:\n${uncovered.map((path) => `- ${path}`).join('\n')}`,
  );
}

process.stderr.write(`ALLOWANCE SECURITY TEST COVERAGE: ${allowanceTests.length}/${allowanceTests.length}\n`);
