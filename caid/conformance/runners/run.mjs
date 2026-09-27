#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// JavaScript conformance runner for the CAID core corpus (vectors.json,
// version 5) and the grammar boundary corpus (grammar-vectors.json). It
// drives an implementation only through its public entry points.
//
//   node caid/conformance/runners/run.mjs [--impl FILE] [--corpus core|grammar|all]
//                                         [--json]
//
// --impl defaults to caid/impl/js/caid.mjs (the vendored Verify copy,
// packages/verify/vendor/caid.mjs, takes the same runner). The entry points
// used are named in API below; all of them are required.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildNative, inputBytes } from './native.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = path.resolve(HERE, '..');
const ROOT = path.resolve(CONFORMANCE, '../..');
const args = process.argv.slice(2);
const arg = (name, fallback) => { const i = args.indexOf(name); return i === -1 ? fallback : args[i + 1]; };
const implPath = path.resolve(arg('--impl', path.join(ROOT, 'caid/impl/js/caid.mjs')));
const corpusChoice = arg('--corpus', 'all');
const port = await import(pathToFileURL(implPath).href);

// ---------------------------------------------------------------- API
const missing = [];
const need = (name, ...candidates) => {
  for (const c of candidates) if (typeof port[c] === 'function') return port[c].bind(port);
  missing.push(name);
  return null;
};
const API = {
  decode: need('decodeCaidJson', 'decodeCaidJson'),
  computeJson: need('computeCaidJson', 'computeCaidJson'),
  verifyJson: need('verifyCaidJson', 'verifyCaidJson'),
  compute: need('computeCaid', 'computeCaid'),
  verify: need('verifyCaid', 'verifyCaid'),
  parse: need('parseCaid', 'parseCaid'),
  definitionSha256: need('definitionSha256', 'definitionSha256', 'definitionDigest'),
};

// ---------------------------------------------------------------- helpers
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
// Results are compared as JSON after dropping members whose value is
// undefined; member order does not matter.
const norm = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x)
  ? Object.fromEntries(Object.keys(x).sort().filter((key) => x[key] !== undefined).map((key) => [key, x[key]])) : x));
const readCorpus = (file) => {
  const bytes = new Uint8Array(readFileSync(path.join(CONFORMANCE, file)));
  // The corpus is strict JSON; read it with the implementation's own
  // decoder when it has one (no size cap applies to corpus files, so fall
  // back to the host parser only if the decoder refuses on size alone).
  if (API.decode) {
    const d = API.decode(bytes);
    if (d && d.ok) return d.value;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
};

const results = [];
let pass = 0;
let fail = 0;
const perCorpus = {};
const report = (corpus, id, ok, detail) => {
  perCorpus[corpus] = perCorpus[corpus] ?? { pass: 0, fail: 0 };
  if (ok) { pass += 1; perCorpus[corpus].pass += 1; } else { fail += 1; perCorpus[corpus].fail += 1; results.push({ corpus, id, detail }); }
};
const guard = (fn) => {
  try { return fn(); } catch (e) { return { thrown: `${e && e.name}: ${e && e.message}` }; }
};

// ---------------------------------------------------------------- core corpus
function runCore() {
  const corpus = readCorpus('vectors.json');
  if (corpus.version !== 5) { report('core', '(corpus)', false, `expected corpus version 5, got ${corpus.version}`); return; }
  const snapshots = corpus.enum_snapshots;
  const caids = new Map();
  for (const v of corpus.vectors) {
    const input = v.input;
    const opts = { definitions: v.definitions, enumSnapshots: snapshots };
    if (v.kind === 'compute' && own(input, 'suite')) opts.suite = input.suite;
    if (v.kind === 'verify' && own(input, 'expected_definition_sha256')) opts.expectedDefinitionSha256 = input.expected_definition_sha256;
    let actual;
    let parity = null;
    let elapsed = 0;
    if (v.kind === 'decode') {
      const r = guard(() => API.decode(inputBytes(input)));
      actual = r && r.ok === true ? { ok: true } : r && r.ok === false ? { ok: false, refusals: r.refusals } : r;
    } else if (v.kind === 'parse') {
      actual = guard(() => API.parse(input.caid));
    } else if (v.kind === 'definition') {
      actual = guard(() => API.definitionSha256(input.definition));
    } else if (own(input, 'native')) {
      const host = buildNative(input.native);
      opts.definitions = buildNative(v.definitions);
      actual = guard(() => (v.kind === 'compute' ? API.compute(host, opts) : API.verify(host, input.caid, opts)));
    } else {
      const bytes = inputBytes(input);
      const t0 = performance.now();
      actual = guard(() => (v.kind === 'compute' ? API.computeJson(bytes, opts) : API.verifyJson(bytes, input.caid, opts)));
      elapsed = performance.now() - t0;
      const d = guard(() => API.decode(bytes));
      if (d && d.ok === true) {
        const n = guard(() => (v.kind === 'compute' ? API.compute(d.value, opts) : API.verify(d.value, input.caid, opts)));
        if (norm(n) !== norm(actual)) parity = `native entry point on the decoded value gave ${norm(n).slice(0, 300)}`;
      }
    }
    if (v.kind === 'compute' && actual && typeof actual.caid === 'string') caids.set(v.id, actual.caid);
    const ok = norm(actual) === norm(v.expect);
    report('core', v.id, ok && !parity, !ok ? `expected ${norm(v.expect).slice(0, 400)} got ${norm(actual).slice(0, 400)}` : parity);
    if (v.time_budget_ms && elapsed > v.time_budget_ms) report('core', `${v.id} (time)`, false, `${elapsed.toFixed(0)} ms exceeds the ${v.time_budget_ms} ms budget`);
  }
  for (const v of corpus.vectors) {
    if (!v.relation) continue;
    const other = v.relation.same_caid_as ?? v.relation.different_caid_from;
    const a = caids.get(v.id);
    const b = caids.get(other);
    const ok = a !== undefined && b !== undefined && (v.relation.same_caid_as ? a === b : a !== b);
    report('core', `${v.id} (relation ${other})`, ok, ok ? null : `${a} vs ${b}`);
  }
}

// ---------------------------------------------------------------- grammar corpus
function substitute(template, value) {
  if (template === '$CASE') return value;
  if (Array.isArray(template)) return template.map((x) => substitute(x, value));
  if (template && typeof template === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(template)) {
      Object.defineProperty(out, k === '$CASE' ? value : k, { value: substitute(v, value), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return template;
}
const caseString = (c) => (typeof c === 'string' ? c : own(c, '$units') ? String.fromCharCode(...c.$units)
  : own(c, 'repeat') ? c.repeat.prefix + c.repeat.unit.repeat(c.repeat.count) + c.repeat.suffix : null);

function runGrammar() {
  const corpus = readCorpus('grammar-vectors.json');
  const placeholder = corpus.placeholder;
  corpus.cases.forEach((c, index) => {
    const d = corpus.drivers[c.driver];
    const id = `grammar[${index}] ${c.driver} ${c.lane}`;
    let actual;
    if (d.operation === 'parse') {
      actual = guard(() => API.parse(d.caid.prefix + caseString(c.case) + d.caid.suffix));
    } else {
      const s = c.lane === 'bytes' ? placeholder : caseString(c.case);
      const def = substitute(d.definition, s);
      const obj = substitute(d.object, s);
      const opts = { definitions: [def], enumSnapshots: [], suite: d.suite === '$CASE' ? s : 'jcs-sha256' };
      if (c.lane === 'native') {
        actual = guard(() => API.compute(obj, opts));
      } else {
        let bytes;
        if (c.lane === 'bytes') {
          const raw = Buffer.from(c.case.b64, 'base64');
          const parts = JSON.stringify(obj).split(placeholder).map((p) => Buffer.from(p, 'utf8'));
          bytes = new Uint8Array(Buffer.concat(parts.flatMap((p, i) => (i ? [raw, p] : [p]))));
        } else {
          bytes = new Uint8Array(Buffer.from(JSON.stringify(obj), 'utf8'));
        }
        actual = guard(() => API.computeJson(bytes, opts));
        if (c.lane === 'text') {
          const dec = guard(() => API.decode(bytes));
          if (dec && dec.ok === true) {
            const n = guard(() => API.compute(dec.value, opts));
            if (norm(n) !== norm(actual)) { report('grammar', id, false, `native parity: ${norm(n).slice(0, 200)} vs ${norm(actual).slice(0, 200)}`); return; }
          }
        }
      }
      // Compute expectations are {caid} or {refusals}.
      if (actual && typeof actual.caid === 'string' && own(c.expect, 'caid')) actual = { caid: actual.caid };
    }
    const ok = norm(actual) === norm(c.expect);
    report('grammar', id, ok, ok ? null : `case ${JSON.stringify(c.case).slice(0, 80)}: expected ${norm(c.expect).slice(0, 200)} got ${norm(actual).slice(0, 200)}`);
  });
}

// ---------------------------------------------------------------- main
if (missing.length) {
  console.error(`FAIL ${path.relative(ROOT, implPath)} lacks the entry points ${missing.join(', ')} (see caid/conformance/README.md)`);
  process.exit(1);
}
if (corpusChoice === 'core' || corpusChoice === 'all') runCore();
if (corpusChoice === 'grammar' || corpusChoice === 'all') runGrammar();
const summary = { runner: 'javascript', impl: path.relative(ROOT, implPath), corpus: corpusChoice, pass, fail, per_corpus: perCorpus, failures: results.slice(0, 500) };
if (args.includes('--json')) process.stdout.write(JSON.stringify(summary) + '\n');
else {
  for (const r of results.slice(0, 60)) console.log(`FAIL ${r.corpus} ${r.id}\n     ${r.detail}`);
  if (results.length > 60) console.log(`... ${results.length - 60} more failures`);
  console.log(`${summary.runner} ${summary.impl} (${corpusChoice}): ${pass} passed, ${fail} failed ${JSON.stringify(perCorpus)}`);
}
process.exit(fail ? 1 : 0);
