#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest: any = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/conformance-manifest.json'), 'utf8'));
const pin: any = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/external/rust-cleanroom-jdieselny.v1.json'), 'utf8'));
const proofStats: any = JSON.parse(fs.readFileSync(path.join(ROOT, 'lib/proof-stats.json'), 'utf8'));
const expectedSuites: number = manifest.totals.suites;
const expectedVectors: number = manifest.totals.vectors;
const expectedExternalSuites: number = pin.conformance.suites;
const expectedExternalVectors: number = pin.conformance.vectors;
const expectedHostilityCases: number = pin.hostility.structured_cases + pin.hostility.raw_parser_cases;
const expectedTests: number = proofStats.tests.total;
const expectedTestFiles: number = proofStats.tests.files;

const allowedExtensions: Set<string> = new Set(['.html', '.js', '.jsx', '.md', '.mjs', '.py', '.text', '.ts', '.tsx', '.txt']);
// strategy-private is gitignored (never public, never in CI checkouts); scanning
// it locally produces false FAILs, e.g. a caution note quoting a banned phrase.
const excludedDirectories: Set<string> = new Set(['.git', '.next', 'archive', 'node_modules', 'strategy-private']);
const scanRoots: readonly string[] = [
  'AGENTS.md',
  'AI_CONTEXT.md',
  'CLAUDE.md',
  'GEMINI.md',
  'README.md',
  'CONFORMANCE.md',
  'app',
  'docs',
  'examples',
  'packages',
  'papers',
  'public',
  'standards/iana',
];

interface Finding {
  file: string;
  line: number;
  match: string;
  message: string;
}

function lineNumber(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

function finding(file: string, text: string, match: RegExpExecArray, message: string): Finding {
  return { file, line: lineNumber(text, match.index), match: match[0], message };
}

function isNegated(text: string, index: number): boolean {
  const before: string = text.slice(Math.max(0, index - 64), index);
  return /(?:\bnot|\bno|isn't|aren't)\s+(?:yet\s+)?$/i.test(before)
    || /\bnever\b[^.\n]{0,48}$/i.test(before);
}

function isExternalBaselineClaim(text: string, index: number): boolean {
  const before: string = text.slice(Math.max(0, index - 240), index);
  const lastMatch = (pattern: RegExp): number => {
    let last: number = -1;
    for (const match of before.matchAll(pattern)) last = match.index;
    return last;
  };
  const external: number = lastMatch(/\b(?:external(?:ly authored)?\s+(?:from-spec\s+)?(?:rust\s+)?(?:implementation|verifier)|rust\s+(?:implementation|verifier)|clean-room|time-pinned|frozen\s+(?:bundle|baseline|corpus)|pinned\s+(?:bundle|baseline|corpus|vector set))\b/gi);
  const pinnedPrefix: number = /\bpinned\s*$/i.test(before) ? before.lastIndexOf('pinned') : -1;
  const live: number = lastMatch(/\b(?:live(?:\s+same-team)?|same-team|current\s+(?:corpus|bundle)|javascript\s*,\s*python\s*,\s*(?:and\s+)?go)\b/gi);
  return Math.max(external, pinnedPrefix) > live;
}

export function auditClaimText(text: string, file: string = '<text>', expectations: Record<string, any> = {}): Finding[] {
  const suites: number = expectations.suites ?? expectedSuites;
  const vectors: number = expectations.vectors ?? expectedVectors;
  const externalSuites: number = expectations.externalSuites ?? expectedExternalSuites;
  const externalVectors: number = expectations.externalVectors ?? expectedExternalVectors;
  const tests: number = expectations.tests ?? expectedTests;
  const testFiles: number = expectations.testFiles ?? expectedTestFiles;
  const findings: Finding[] = [];
  const categoricalRules: readonly RegExp[] = [
    /\bthree\s+independent\s+(?:cross-language\s+)?(?:implementations|verifiers|languages)\b/gi,
    /\bthree\s+independent,\s*interoperable\s+implementations\b/gi,
    /\b(?:three|3)\s+independent\s+(?:JS\/Python\/Go\s+)?offline\s+verifiers\b/gi,
    /\bthree\s+independent\s+JS\/Python\/Go\s+offline\s+verifiers\b/gi,
    /\bthree\s+independent\s+\(JS\/Python\/Go\)\s+offline\s+verifiers\b/gi,
    /\bthree\s+independent\s+language\s+runtimes\b/gi,
  ];
  for (const rule of categoricalRules) {
    for (const match of text.matchAll(rule)) {
      if (isNegated(text, match.index)) continue;
      findings.push(finding(file, text, match, 'same-team JS/Python/Go ports must not be described as independent implementations'));
    }
  }

  for (const match of text.matchAll(/\b(\d+)\s+(?:cross-language\s+)?conformance\s+suites?\b/gi)) {
    const external = isExternalBaselineClaim(text, match.index);
    const expected = external ? externalSuites : suites;
    const scope = external ? 'externally pinned' : 'current';
    if (Number(match[1]) !== expected) findings.push(finding(file, text, match, `${scope} conformance suite count is ${expected}`));
  }

  const countPairs: readonly RegExp[] = [
    /\b(\d+)\s+(?:cross-language\s+)?conformance\s+suites?\b[^\n]{0,180}?\b(\d+)(?:\/\d+)?\s+(?:published\s+|current\s+|adversarial\s+|test\s+)?vectors?\b/gi,
    /\b(\d+)\s+test\s+suites?\b[^\n]{0,180}?\b(\d+)\s+(?:adversarial\s+)?(?:test\s+)?vectors?\b/gi,
    /\b(\d+)-suite\s*\/\s*(\d+)-vector\b/gi,
    /\b(\d+)\s+suites?\b[^\n]{0,180}?\b(\d+)\s+(?:published\s+|current\s+|adversarial\s+|test\s+)?vectors?\b/gi,
  ];
  for (const rule of countPairs) {
    for (const match of text.matchAll(rule)) {
      const nearby = text.slice(Math.max(0, match.index - 180), Math.min(text.length, match.index + match[0].length + 180));
      if (/\b(?:historical|legacy|signed statement|bound to (?:commit|its input)|input set)\b/i.test(nearby)) continue;
      const external = isExternalBaselineClaim(text, match.index);
      const expectedPairSuites = external ? externalSuites : suites;
      const expectedPairVectors = external ? externalVectors : vectors;
      const scope = external ? 'externally pinned' : 'current';
      if (Number(match[1]) !== expectedPairSuites) findings.push(finding(file, text, match, `${scope} conformance suite count is ${expectedPairSuites}`));
      if (Number(match[2]) !== expectedPairVectors) findings.push(finding(file, text, match, `${scope} conformance vector count is ${expectedPairVectors}`));
    }
  }
  for (const match of text.matchAll(/\ball\s+(\d+)(?:\/\d+)?\s+(?:published\s+|current\s+)?vectors?\b/gi)) {
    const nearby = text.slice(Math.max(0, match.index - 120), Math.min(text.length, match.index + match[0].length + 120));
    if (/\b(?:legacy|predates|signed statement)\b/i.test(nearby)) continue;
    const external = isExternalBaselineClaim(text, match.index);
    const expectedCount = external ? externalVectors : vectors;
    const scope = external ? 'externally pinned' : 'current';
    if (Number(match[1]) !== expectedCount) findings.push(finding(file, text, match, `${scope} conformance vector count is ${expectedCount}`));
  }

  for (const match of text.matchAll(/\b(?:an?\s+)?(?:genuinely\s+)?independent\s+clean-room\s+reimplementation\s+(?:is\s+)?(?:underway|not yet complete)\b/gi)) {
    findings.push(finding(file, text, match, 'an external Rust implementation now exists; describe strict construction attestation as pending instead'));
  }

  const number = (value: any): number => Number(String(value).replaceAll(',', ''));
  // The automated-test case and file counts grow every time anyone adds a test,
  // so docs state them as a FLOOR ("over N", "at least N", "N+") rather than an
  // exact figure that goes stale on the next commit. A floor passes when the true
  // count is >= N; a bare exact number must still equal the true count, so this
  // only relaxes understatement (safe) and still catches overstatement. The exact
  // number lives once in lib/proof-stats.json and is rendered by app/page.js.
  const floorWordBefore = (idx: number): boolean =>
    /\b(?:over|at least|more than|at minimum|minimum of|upwards of|north of)\s+$/i.test(text.slice(Math.max(0, idx - 24), idx));
  const countOk = (n: number, plusSign: string, numIdx: number, actual: number): boolean =>
    (plusSign === '+' || floorWordBefore(numIdx)) ? actual >= n : actual === n;

  for (const match of text.matchAll(/\b(\d{3,}|\d{1,3}(?:,\d{3})+)(\+?)\*{0,2}\s+automated\s+test(?:s|\s+cases)\b([^\n]{0,80})/gi)) {
    const numIdx: number = match.index + match[0].indexOf(match[1]);
    if (!countOk(number(match[1]), match[2], numIdx, tests)) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
    const files = match[3].match(/\bacross\s+(\d+)(\+?)\s+files\b/i);
    if (files) {
      const fileIdx: number = match.index + match[0].indexOf(files[0]) + files[0].indexOf(files[1]);
      if (!countOk(number(files[1]), files[2], fileIdx, testFiles)) findings.push(finding(file, text, match, `current automated-test file count is ${testFiles}`));
    }
  }
  for (const match of text.matchAll(/\bautomated\s+test(?:s|\s+cases)\s*\|\s*(\d{3,}|\d{1,3}(?:,\d{3})+)(\+?)\s+across\s+(\d+)(\+?)\s+files\b/gi)) {
    const numIdx: number = match.index + match[0].indexOf(match[1]);
    if (!countOk(number(match[1]), match[2], numIdx, tests)) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
    const fileIdx: number = match.index + match[0].lastIndexOf(match[3]);
    if (!countOk(number(match[3]), match[4], fileIdx, testFiles)) findings.push(finding(file, text, match, `current automated-test file count is ${testFiles}`));
  }
  for (const match of text.matchAll(/\b0\s+violations\s+in\s+(\d{3,}|\d{1,3}(?:,\d{3})+)\s+tests\b/gi)) {
    if (number(match[1]) !== tests) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
  }
  for (const match of text.matchAll(/\bExpected:\s*(\d{3,}|\d{1,3}(?:,\d{3})+)\s+passing,\s*0\s+failing\b/gi)) {
    if (number(match[1]) !== tests) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
  }
  for (const match of text.matchAll(/\bfull\s+test\s+suite\b[^\n]{0,120}?\ball\s+(\d{3,}|\d{1,3}(?:,\d{3})+)\s+passing\b/gi)) {
    if (number(match[1]) !== tests) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
  }
  const seen: Set<string> = new Set();
  return findings.filter((item: Finding): boolean => {
    const key: string = `${item.file}:${item.line}:${item.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function filesUnder(target: string): string[] {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const files: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
      const absolute: string = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && allowedExtensions.has(path.extname(entry.name).toLowerCase())) files.push(absolute);
    }
  };
  walk(target);
  return files;
}

export function auditRepository(): Finding[] {
  const findings: Finding[] = [];
  for (const root of scanRoots) {
    const target: string = path.join(ROOT, root);
    if (!fs.existsSync(target)) continue;
    for (const file of filesUnder(target)) {
      const relative: string = path.relative(ROOT, file).split(path.sep).join('/');
      const text: string = fs.readFileSync(file, 'utf8');
      findings.push(...auditClaimText(text, relative));
    }
  }
  return findings;
}

function isMain() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMain()) {
  if (manifest?.['@version'] !== 'EP-CONFORMANCE-MANIFEST-v1') throw new Error('unsupported conformance manifest');
  if (pin?.['@version'] !== 'EP-EXTERNAL-IMPLEMENTATION-PIN-v1') throw new Error('unsupported external implementation pin');
  const findings = auditRepository();
  if (findings.length) {
    console.error(`PUBLIC CONFORMANCE CLAIMS: FAIL (${findings.length} finding(s))`);
    for (const item of findings) console.error(`${item.file}:${item.line}: ${item.message}: ${JSON.stringify(item.match)}`);
    process.exitCode = 1;
  } else {
    console.log(`PUBLIC CONFORMANCE CLAIMS: PASS (${expectedSuites} suites, ${expectedVectors} vectors, ${expectedHostilityCases} external hostility cases; ${expectedTests} automated test cases across ${expectedTestFiles} files; JS/Python/Go labeled one-team ports)`);
  }
}
