#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/conformance-manifest.json'), 'utf8'));
const pin = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/external/rust-cleanroom-jdieselny.v1.json'), 'utf8'));
const proofStats = JSON.parse(fs.readFileSync(path.join(ROOT, 'lib/proof-stats.json'), 'utf8'));
const expectedSuites = manifest.totals.suites;
const expectedVectors = manifest.totals.vectors;
const expectedHostilityCases = pin.hostility.structured_cases + pin.hostility.raw_parser_cases;
const expectedTests = proofStats.tests.total;
const expectedTestFiles = proofStats.tests.files;

const allowedExtensions = new Set(['.html', '.js', '.jsx', '.md', '.mjs', '.py', '.text', '.ts', '.tsx', '.txt']);
// strategy-private is gitignored (never public, never in CI checkouts); scanning
// it locally produces false FAILs, e.g. a caution note quoting a banned phrase.
const excludedDirectories = new Set(['.git', '.next', 'archive', 'node_modules', 'strategy-private']);
const scanRoots = [
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

function lineNumber(text, index) {
  return text.slice(0, index).split('\n').length;
}

function finding(file, text, match, message) {
  return { file, line: lineNumber(text, match.index), match: match[0], message };
}

function isNegated(text, index) {
  const before = text.slice(Math.max(0, index - 64), index);
  return /(?:\bnot|\bno|isn't|aren't)\s+(?:yet\s+)?$/i.test(before)
    || /\bnever\b[^.\n]{0,48}$/i.test(before);
}

export function auditClaimText(text, file = '<text>', expectations = {}) {
  const suites = expectations.suites ?? expectedSuites;
  const vectors = expectations.vectors ?? expectedVectors;
  const tests = expectations.tests ?? expectedTests;
  const testFiles = expectations.testFiles ?? expectedTestFiles;
  const findings = [];
  const categoricalRules = [
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
    if (Number(match[1]) !== suites) findings.push(finding(file, text, match, `current conformance suite count is ${suites}`));
  }

  const countPairs = [
    /\b(\d+)\s+(?:cross-language\s+)?conformance\s+suites?\b[^\n]{0,180}?\b(\d+)(?:\/\d+)?\s+(?:published\s+|current\s+|adversarial\s+|test\s+)?vectors?\b/gi,
    /\b(\d+)\s+test\s+suites?\b[^\n]{0,180}?\b(\d+)\s+(?:adversarial\s+)?(?:test\s+)?vectors?\b/gi,
    /\b(\d+)-suite\s*\/\s*(\d+)-vector\b/gi,
    /\b(\d+)\s+suites?\b[^\n]{0,180}?\b(\d+)\s+(?:published\s+|current\s+|adversarial\s+|test\s+)?vectors?\b/gi,
  ];
  for (const rule of countPairs) {
    for (const match of text.matchAll(rule)) {
      const nearby = text.slice(Math.max(0, match.index - 180), Math.min(text.length, match.index + match[0].length + 180));
      if (/\b(?:historical|legacy|signed statement|bound to (?:commit|its input)|input set)\b/i.test(nearby)) continue;
      if (Number(match[1]) !== suites) findings.push(finding(file, text, match, `current conformance suite count is ${suites}`));
      if (Number(match[2]) !== vectors) findings.push(finding(file, text, match, `current conformance vector count is ${vectors}`));
    }
  }
  for (const match of text.matchAll(/\ball\s+(\d+)(?:\/\d+)?\s+(?:published\s+|current\s+)?vectors?\b/gi)) {
    const nearby = text.slice(Math.max(0, match.index - 120), Math.min(text.length, match.index + match[0].length + 120));
    if (/\b(?:legacy|predates|signed statement)\b/i.test(nearby)) continue;
    if (Number(match[1]) !== vectors) findings.push(finding(file, text, match, `current conformance vector count is ${vectors}`));
  }

  for (const match of text.matchAll(/\b(?:an?\s+)?(?:genuinely\s+)?independent\s+clean-room\s+reimplementation\s+(?:is\s+)?(?:underway|not yet complete)\b/gi)) {
    findings.push(finding(file, text, match, 'an external Rust implementation now exists; describe strict construction attestation as pending instead'));
  }

  const number = (value) => Number(String(value).replaceAll(',', ''));
  // The automated-test case and file counts grow every time anyone adds a test,
  // so docs state them as a FLOOR ("over N", "at least N", "N+") rather than an
  // exact figure that goes stale on the next commit. A floor passes when the true
  // count is >= N; a bare exact number must still equal the true count, so this
  // only relaxes understatement (safe) and still catches overstatement. The exact
  // number lives once in lib/proof-stats.json and is rendered by app/page.js.
  const floorWordBefore = (idx) =>
    /\b(?:over|at least|more than|at minimum|minimum of|upwards of|north of)\s+$/i.test(text.slice(Math.max(0, idx - 24), idx));
  const countOk = (n, plusSign, numIdx, actual) =>
    (plusSign === '+' || floorWordBefore(numIdx)) ? actual >= n : actual === n;

  for (const match of text.matchAll(/\b(\d{3,}|\d{1,3}(?:,\d{3})+)(\+?)\*{0,2}\s+automated\s+test(?:s|\s+cases)\b([^\n]{0,80})/gi)) {
    const numIdx = match.index + match[0].indexOf(match[1]);
    if (!countOk(number(match[1]), match[2], numIdx, tests)) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
    const files = match[3].match(/\bacross\s+(\d+)(\+?)\s+files\b/i);
    if (files) {
      const fileIdx = match.index + match[0].indexOf(files[0]) + files[0].indexOf(files[1]);
      if (!countOk(number(files[1]), files[2], fileIdx, testFiles)) findings.push(finding(file, text, match, `current automated-test file count is ${testFiles}`));
    }
  }
  for (const match of text.matchAll(/\bautomated\s+test(?:s|\s+cases)\s*\|\s*(\d{3,}|\d{1,3}(?:,\d{3})+)(\+?)\s+across\s+(\d+)(\+?)\s+files\b/gi)) {
    const numIdx = match.index + match[0].indexOf(match[1]);
    if (!countOk(number(match[1]), match[2], numIdx, tests)) findings.push(finding(file, text, match, `current automated-test case count is ${tests}`));
    const fileIdx = match.index + match[0].lastIndexOf(match[3]);
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
  const seen = new Set();
  return findings.filter((item) => {
    const key = `${item.file}:${item.line}:${item.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function filesUnder(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && allowedExtensions.has(path.extname(entry.name).toLowerCase())) files.push(absolute);
    }
  };
  walk(target);
  return files;
}

export function auditRepository() {
  const findings = [];
  for (const root of scanRoots) {
    const target = path.join(ROOT, root);
    if (!fs.existsSync(target)) continue;
    for (const file of filesUnder(target)) {
      const relative = path.relative(ROOT, file).split(path.sep).join('/');
      const text = fs.readFileSync(file, 'utf8');
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
