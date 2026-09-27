#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Proves the generated CAID matchers equal the grammar, and that each is
// linear-time safe.
//
//   node caid/spec/abnf-check.mjs [--js-only] [--no-timing]
//                                 [--out FILE [--per-rule N]]
//
// 1. Membership. For every compiled rule (patterns, code formats, suite
//    digest syntax) it generates a deterministic case list: members drawn
//    from the grammar, every single-character deletion, replacement and
//    insertion at the character-class boundaries, exhaustive short strings,
//    astral characters, lone surrogates, look-alike digits and letters, and
//    strings of 2^16 to 2^17 characters. It asserts that the ABNF
//    interpreter agrees with the GENERATED matchers exactly as each port
//    receives them from caid/spec/gen.mjs: the JavaScript region imported
//    as a module, the Python module imported by the interpreter named in
//    CAID_PYTHON (default python3, with match, fullmatch and search all
//    checked), and the Go file compiled into a package. Python receives
//    each case as JSON (lone surrogates survive as escapes); Go receives
//    the WTF-8 bytes, so a lone surrogate reaches it as invalid UTF-8.
// 2. Rules that are not compiled (non-ASCII: field-name, json-pointer,
//    source-path) are compared with the predicates the ports implement.
// 3. Linear time. Every compiled expression must pass the static analysis
//    of abnf.mjs (deterministic, or finite with no nested or overlapping
//    quantifiers and a bounded step count); every code format must pass
//    the finite analysis. Known catastrophic patterns (including the
//    review's (a|a){1,99}) must fail it.
// 4. Timing. Adversarial inputs of 2^20 characters run against every
//    generated matcher in JavaScript, Python and Go; each match must
//    finish inside the budget.
// 5. Reasons. Every reason string the conformance corpora expect
//    (caid/conformance and caid/interop) matches the reason rule.
//
// Exits 1 on any mismatch or failure. --out writes the case list with the
// interpreter's verdicts (at most N cases per rule with --per-rule) for the
// conformance corpus.

import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyzeRegex, matches, parseRegex, prng, sample } from './abnf.mjs';
import { buildSpec, emitGo, emitJsRegion, emitPython, loadCaidGrammar } from './gen.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TIMING_BUDGET_MS = 250;
const TIMING_LENGTH = 1 << 20;
const LONG_LENGTH = 1 << 16;

const args = { jsOnly: false, timing: true, out: /** @type {string | null} */ (null), perRule: Infinity };
for (let i = 2; i < process.argv.length; i += 1) {
  const a = process.argv[i];
  if (a === '--js-only') args.jsOnly = true;
  else if (a === '--no-timing') args.timing = false;
  else if (a === '--out') args.out = path.resolve(process.argv[++i] ?? '');
  else if (a === '--per-rule') args.perRule = Number(process.argv[++i]);
  else { process.stderr.write(`unknown argument ${a}\n`); process.exit(2); }
}

const failures = [];
const fail = (msg) => failures.push(msg);

const spec = buildSpec(ROOT);
const { rules } = loadCaidGrammar(ROOT);

// Compiled rules: [label, abnf rule name, portable expression].
const compiled = [];
const coreGrammar = JSON.parse(readFileSync(path.join(ROOT, 'caid/spec/core.json'), 'utf8')).grammar;
const ruleOfPattern = new Map(coreGrammar.patterns.map((p) => [p.id, p.rule]));
for (const [id, src] of Object.entries(spec.patterns)) compiled.push([`pattern:${id}`, ruleOfPattern.get(id), src]);
for (const [format, src] of Object.entries(spec.code_formats)) compiled.push([`code_format:${format}`, format, src]);
// The ABNF digest rule of each digest length, from core.json (gen.mjs checks
// that each rule equals the syntax derived for its length).
const digestRules = new Map(coreGrammar.suite_digest_rules.map((r) => [r.digest_octets, r.rule]));
for (const s of spec.suites) {
  const rule = digestRules.get(s.digest_octets);
  if (!rule) fail(`no ABNF digest rule for ${s.digest_octets} octets`);
  else compiled.push([`suite_digest:${s.suite}`, rule, s.digest_pattern]);
}

// The generated artifacts, written to a scratch directory exactly as the
// ports receive them.
const PYTHON = process.env.CAID_PYTHON || 'python3';
const workDir = mkdtempSync(path.join(os.tmpdir(), 'caid-abnf-check-'));
writeFileSync(path.join(workDir, 'caid-spec-region.mjs'), emitJsRegion(spec));
writeFileSync(path.join(workDir, 'caid_spec.py'), emitPython(spec));
const generatedJs = await import(pathToFileURL(path.join(workDir, 'caid-spec-region.mjs')).href);
const jsMatcher = (label) => {
  const [kind, id] = label.split(/:(.*)/s);
  const table = { pattern: generatedJs.CAID_PATTERNS, code_format: generatedJs.CAID_CODE_FORMATS, suite_digest: generatedJs.CAID_SUITE_DIGEST_PATTERNS }[kind];
  const re = table?.[id];
  if (!(re instanceof RegExp)) throw new Error(`generated JavaScript has no matcher for ${label}`);
  return re;
};

// ---------------------------------------------------------------------------
// Case generation
// ---------------------------------------------------------------------------

const SPECIALS = [
  '\u0000', '\t', '\n', '\r', ' ', '\u007f', 'é', 'İ', 'ſ', 'K',
  '٠', '０', 'Ａ', '�', '﻿', '\u{1d7ce}', '\u{1f600}', '\ud800', '\udc00',
];

function classRanges(src) {
  const out = [];
  const walk = (n) => {
    if (n.t === 'cls') out.push(...n.ranges);
    else if (n.t === 'rep') walk(n.item);
    else n.items.forEach(walk);
  };
  walk(parseRegex(src));
  return out;
}

function boundaryChars(src) {
  const set = new Set();
  for (const [lo, hi] of classRanges(src)) {
    for (const cp of [lo - 1, lo, hi, hi + 1]) if (cp >= 0x20 && cp <= 0x7e) set.add(String.fromCharCode(cp));
  }
  for (const c of ':.-_~/%@+!$&\'()*,;=?[]{}|\\^`"#<> ') set.add(c);
  for (const c of 'aAzZ09') set.add(c);
  return [...set].sort();
}

function casesFor(label, rule, src) {
  const rng = prng([...label].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0, 7));
  const cases = new Set(['']);
  const seeds = [];
  for (let k = 0; k < 16; k += 1) seeds.push(sample(rules, rule, rng, { extra: k % 4 }));
  for (let k = 0; k < 4; k += 1) seeds.push(sample(rules, rule, rng, { extra: 40 }));
  const alphabet = [...boundaryChars(src), ...SPECIALS];
  for (const seed of seeds) {
    cases.add(seed);
    for (const s of SPECIALS) { cases.add(seed + s); cases.add(s + seed); }
    cases.add(seed.toUpperCase());
    cases.add(seed.toLowerCase());
    cases.add(seed + seed);
    const chars = Array.from(seed);
    const positions = chars.length <= 16
      ? [...Array(chars.length + 1).keys()]
      : [0, 1, 2, 3, chars.length - 3, chars.length - 2, chars.length - 1, chars.length,
        ...Array.from({ length: 8 }, () => Math.floor(rng() * chars.length))];
    for (const p of new Set(positions)) {
      if (p < chars.length) cases.add([...chars.slice(0, p), ...chars.slice(p + 1)].join(''));
      for (const c of alphabet) {
        if (p < chars.length) cases.add([...chars.slice(0, p), c, ...chars.slice(p + 1)].join(''));
        cases.add([...chars.slice(0, p), c, ...chars.slice(p)].join(''));
      }
    }
  }
  const small = boundaryChars(src).filter((c) => /[A-Za-z0-9:.\-]/.test(c)).slice(0, 14);
  for (const a of small) {
    cases.add(a);
    for (const b of small) {
      cases.add(a + b);
      for (const c of small) cases.add(a + b + c);
    }
  }
  // Long strings: repeated members and single characters, valid and not.
  const unit = seeds.find((s) => s.length > 0) ?? 'a';
  for (const s of [unit, ...boundaryChars(src).slice(0, 6)]) {
    const long = s.repeat(Math.ceil(LONG_LENGTH / Math.max(1, s.length)));
    cases.add(long);
    cases.add(long + '!');
    cases.add(long + '\ud800');
    cases.add('\u{1f600}' + long);
  }
  return [...cases];
}

// WTF-8: UTF-8 with each lone surrogate encoded as its own three bytes,
// which Go reads as invalid UTF-8.
function toWtf8(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    let cp = s.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); i += 1; }
    }
    if (cp < 0x80) bytes.push(cp);
    else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return Buffer.from(bytes).toString('base64');
}

// ---------------------------------------------------------------------------
// 1. Membership: interpreter == JavaScript, Python, Go
// ---------------------------------------------------------------------------

const lanes = { js: 0, python: 0, go: 0 };
const corpus = [];
const perRule = [];
let totalCases = 0;
const laneInput = [];
for (const [label, rule, src] of compiled) {
  const cases = casesFor(label, rule, src);
  const re = jsMatcher(label);
  if (re.source !== `^(?:${src})$` || re.flags !== '') fail(`${label}: generated JavaScript matcher ${re} is not ^(?:R)$ over the compiled expression`);
  const expected = cases.map((c) => matches(rules, rule, c));
  let jsMismatch = 0;
  cases.forEach((c, i) => {
    if (re.test(c) !== expected[i]) {
      jsMismatch += 1;
      if (jsMismatch <= 3) fail(`${label}: JavaScript ${re.test(c)} vs interpreter ${expected[i]} for ${JSON.stringify(c.slice(0, 80))}`);
    }
  });
  lanes.js += jsMismatch;
  totalCases += cases.length;
  perRule.push({ rule: label, cases: cases.length, accepted: expected.filter(Boolean).length, astral: cases.filter((c) => /[\u{10000}-\u{10FFFF}]/u.test(c)).length, lone_surrogate: cases.filter((c) => /\p{Cs}/u.test(c)).length, max_length: Math.max(...cases.map((c) => c.length)) });
  laneInput.push({ label, src, cases, expected });
  if (args.out) {
    const picked = cases.length <= args.perRule ? cases.map((_, i) => i)
      : [...new Set([...expected.map((e, i) => (e ? i : -1)).filter((i) => i >= 0).slice(0, Math.ceil(args.perRule / 2)), ...cases.map((_, i) => i)])].slice(0, args.perRule);
    for (const i of picked) if (cases[i].length <= 4096) corpus.push({ rule: label, abnf_rule: rule, input: cases[i], match: expected[i] });
  }
}

function runLane(command, commandArgs, input, cwd) {
  const r = spawnSync(command, commandArgs, { input, encoding: 'utf8', cwd, maxBuffer: 1 << 30 });
  if (r.error || r.status !== 0) throw new Error(`${command} failed: ${r.error?.message ?? ''}${r.stderr}`);
  return JSON.parse(r.stdout);
}

const PY_PRELUDE = `
import json, sys
sys.path.insert(0, sys.argv[1])
import caid_spec
def matcher(label):
    kind, _, name = label.partition(":")
    table = {"pattern": caid_spec.PATTERNS, "code_format": caid_spec.CODE_FORMATS, "suite_digest": caid_spec.SUITE_DIGEST_PATTERNS}[kind]
    return table[name]
data = json.loads(sys.stdin.read())
`;
const PY_MEMBERSHIP = `${PY_PRELUDE}
out = {}
for lane in data:
    rx = matcher(lane["label"])
    bits = []
    for c in lane["cases"]:
        verdicts = {bool(rx.match(c)), bool(rx.fullmatch(c)), bool(rx.search(c))}
        bits.append("x" if len(verdicts) != 1 else ("1" if verdicts.pop() else "0"))
    out[lane["label"]] = "".join(bits)
sys.stdout.write(json.dumps(out))
`;

const GO_EXPORT = `package caid

import "regexp"

// Matcher returns the generated matcher for an abnf-check label.
func Matcher(label string) *regexp.Regexp {
	for i := 0; i < len(label); i++ {
		if label[i] != ':' {
			continue
		}
		kind, name := label[:i], label[i+1:]
		switch kind {
		case "pattern":
			return specPatterns[name]
		case "code_format":
			return specCodeFormats[name]
		case "suite_digest":
			return specSuiteDigestPatterns[name]
		}
		return nil
	}
	return nil
}
`;

const GO_MEMBERSHIP = `package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	"caidcheck/caid"
)

type lane struct {
	Label string   \`json:"label"\`
	Src   string   \`json:"src"\`
	Cases []string \`json:"cases"\`
}

func main() {
	var in struct {
		Mode  string \`json:"mode"\`
		Lanes []lane \`json:"lanes"\`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	out := map[string]interface{}{}
	for _, l := range in.Lanes {
		rx := caid.Matcher(l.Label)
		if rx == nil || rx.String() != "^(?:"+l.Src+")$" {
			panic("generated Go has no matching expression for " + l.Label)
		}
		if in.Mode == "timing" {
			ms := make([]float64, 0, len(l.Cases))
			for _, c := range l.Cases {
				b, err := base64.StdEncoding.DecodeString(c)
				if err != nil {
					panic(err)
				}
				start := time.Now()
				rx.Match(b)
				ms = append(ms, float64(time.Since(start).Microseconds())/1000)
			}
			out[l.Label] = ms
			continue
		}
		bits := make([]byte, len(l.Cases))
		for i, c := range l.Cases {
			b, err := base64.StdEncoding.DecodeString(c)
			if err != nil {
				panic(err)
			}
			if rx.Match(b) {
				bits[i] = '1'
			} else {
				bits[i] = '0'
			}
		}
		out[l.Label] = string(bits)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
`;

let goBuilt = false;
function goRun(payload) {
  const goDir = path.join(workDir, 'go');
  if (!goBuilt) {
    mkdirSync(path.join(goDir, 'caid'), { recursive: true });
    writeFileSync(path.join(goDir, 'go.mod'), 'module caidcheck\n\ngo 1.21\n');
    writeFileSync(path.join(goDir, 'caid', 'spec_gen.go'), emitGo(spec));
    writeFileSync(path.join(goDir, 'caid', 'export_check.go'), GO_EXPORT);
    writeFileSync(path.join(goDir, 'main.go'), GO_MEMBERSHIP);
    const vet = spawnSync('go', ['vet', './...'], { cwd: goDir, encoding: 'utf8', env: { ...process.env, GOFLAGS: '-mod=mod' } });
    if (vet.status !== 0) throw new Error(`go vet of the generated spec_gen.go failed: ${vet.error?.message ?? ''}${vet.stderr}`);
    const build = spawnSync('go', ['build', '-o', 'check', '.'], { cwd: goDir, encoding: 'utf8' });
    if (build.status !== 0) throw new Error(`go build failed: ${build.error?.message ?? ''}${build.stderr}`);
    goBuilt = true;
  }
  return runLane(path.join(goDir, 'check'), [], JSON.stringify(payload), goDir);
}

const compareLane = (name, results) => {
  for (const { label, cases, expected } of laneInput) {
    const bits = results[label];
    if (typeof bits !== 'string' || bits.length !== cases.length) { fail(`${name}: no result for ${label}`); lanes[name] += cases.length; continue; }
    let shown = 0;
    for (let i = 0; i < cases.length; i += 1) {
      if (bits[i] === 'x' || (bits[i] === '1') !== expected[i]) {
        lanes[name] += 1;
        if (shown++ < 3) fail(`${label}: ${name} ${bits[i] === '1'} vs interpreter ${expected[i]} for ${JSON.stringify(cases[i].slice(0, 80))}`);
      }
    }
  }
};

try {
  if (!args.jsOnly) {
    compareLane('python', runLane(PYTHON, ['-c', PY_MEMBERSHIP, workDir], JSON.stringify(laneInput.map(({ label, cases }) => ({ label, cases })))));
    compareLane('go', goRun({ mode: 'membership', lanes: laneInput.map(({ label, src, cases }) => ({ label, src, cases: cases.map(toWtf8) })) }));
  }

  // -------------------------------------------------------------------------
  // 2. Interpreted rules against the predicates the ports implement
  // -------------------------------------------------------------------------

  const hasLoneSurrogate = (s) => /\p{Cs}/u.test(s);
  const fieldNamePredicate = (s) => s.length > 0 && !s.includes(':') && !hasLoneSurrogate(s);
  const pointerPredicate = (s, allowEmpty) => {
    if (hasLoneSurrogate(s)) return false;
    if (s === '') return allowEmpty;
    if (s[0] !== '/') return false;
    return s.slice(1).split('/').every((seg) => !/~(?![01])/u.test(seg));
  };
  /** @type {Array<[string, (s: string) => boolean, string[]]>} */
  const interpretedChecks = [
    ['field-name', fieldNamePredicate, ['amount', '@version', 'a:b', ':', '', 'café', '\u0000', 'action_type', '\u{1f600}', '\ud800x', 'x\udc00', 'a b', '__proto__']],
    ['json-pointer', (s) => pointerPredicate(s, true), ['', '/', '//', '/a~0b', '/a~1b', '/a~2', '/a~', 'a', '/0', '/é', '/\ud800', '/a/b~01']],
    ['source-path', (s) => pointerPredicate(s, false), ['', '/', '//', '/a~0b', '/a~1b', '/a~2', '/a~', 'a', '/0', '/é', '/\ud800', '/a/b~01']],
  ];
  let interpretedCases = 0;
  for (const [rule, predicate, seeds] of interpretedChecks) {
    const rng = prng(rule.length * 977);
    const cases = new Set(seeds);
    for (let k = 0; k < 300; k += 1) cases.add(sample(rules, rule, rng, { extra: 6 }));
    for (const seed of [...cases]) {
      for (const s of [...SPECIALS, ':', '/', '~', '~0', '~1', '~2', 'a']) { cases.add(seed + s); cases.add(s + seed); }
    }
    for (const c of cases) {
      interpretedCases += 1;
      if (matches(rules, rule, c) !== predicate(c)) fail(`${rule}: interpreter ${matches(rules, rule, c)} vs predicate for ${JSON.stringify(c)}`);
    }
  }

  // -------------------------------------------------------------------------
  // 3. Static linear-time proof
  // -------------------------------------------------------------------------

  const linear = {};
  for (const [label, , src] of compiled) {
    const a = analyzeRegex(src);
    const isFormat = label.startsWith('code_format:');
    linear[label] = { deterministic: a.deterministic, finite: a.finite, step_bound: a.step_bound };
    if (!a.linear) fail(`${label} is not linear-time safe: ${JSON.stringify(a.conflicts)}`);
    if (isFormat && !a.finite) fail(`${label} is not finite with no nested or overlapping quantifiers: ${JSON.stringify(a)}`);
  }
  const controls = ['(?:a|a){1,99}', '(?:a|aa){1,99}', '(?:[0-9]|[0-9]){1,99}', '(?:a+)+', '(?:a*)*', '(?:a|a)*', 'a*a*', 'a{0,50}a{0,50}a{0,50}', '(?:[0-9]{1,4}){1,4}'];
  for (const src of controls) {
    const a = analyzeRegex(src);
    if (a.linear) fail(`linear-time analysis accepts the catastrophic control ${src}`);
    if (a.finite) fail(`finite analysis accepts the control ${src}`);
  }

  // -------------------------------------------------------------------------
  // 4. Adversarial timing in JavaScript, Python and Go
  // -------------------------------------------------------------------------

  /** @type {{length: number, budget_ms: number, js_max_ms: number, python_max_ms: number | null, go_max_ms: number | null, [key: string]: number | null}} */
  const timing = { length: TIMING_LENGTH, budget_ms: TIMING_BUDGET_MS, js_max_ms: 0, python_max_ms: null, go_max_ms: null };
  if (args.timing) {
    const adversarial = [];
    for (const [label, rule, src] of compiled) {
      const rng = prng(label.length * 131);
      const member = sample(rules, rule, rng, { extra: 2 }) || 'a';
      const inputs = [];
      const chars = [...new Set(classRanges(src).flatMap(([lo, hi]) => [lo, hi]).map((c) => String.fromCharCode(c)))].slice(0, 8);
      for (const c of chars) {
        inputs.push(c.repeat(TIMING_LENGTH));
        inputs.push(c.repeat(TIMING_LENGTH - 1) + '!');
      }
      inputs.push(member.repeat(Math.ceil(TIMING_LENGTH / member.length)).slice(0, TIMING_LENGTH) + '\u0000');
      inputs.push(member + '\ud800'.repeat(TIMING_LENGTH));
      adversarial.push({ label, src, inputs });
    }
    for (const { label, inputs } of adversarial) {
      const re = jsMatcher(label);
      for (const s of inputs) {
        let best = Infinity;
        for (let k = 0; k < 3; k += 1) {
          const t0 = process.hrtime.bigint();
          re.test(s);
          best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
        }
        timing.js_max_ms = Math.max(timing.js_max_ms, best);
        if (best > TIMING_BUDGET_MS) fail(`${label}: JavaScript took ${best.toFixed(1)} ms on a ${s.length}-unit input`);
      }
    }
    if (!args.jsOnly) {
      const PY_TIMING = `${PY_PRELUDE}
import time
out = {}
for lane in data:
    rx = matcher(lane["label"])
    ms = []
    for s in lane["inputs"]:
        best = None
        for _ in range(3):
            t0 = time.perf_counter()
            rx.fullmatch(s)
            rx.match(s)
            dt = (time.perf_counter() - t0) * 500
            best = dt if best is None or dt < best else best
        ms.append(best)
    out[lane["label"]] = ms
sys.stdout.write(json.dumps(out))
`;
      const py = runLane(PYTHON, ['-c', PY_TIMING, workDir], JSON.stringify(adversarial.map(({ label, inputs }) => ({ label, inputs }))));
      const go = goRun({ mode: 'timing', lanes: adversarial.map(({ label, src, inputs }) => ({ label, src, cases: inputs.map(toWtf8) })) });
      timing.python_max_ms = 0;
      timing.go_max_ms = 0;
      for (const { label } of adversarial) {
        for (const [name, result] of [['python', py], ['go', go]]) {
          for (const ms of result[label] ?? [Infinity]) {
            timing[`${name}_max_ms`] = Math.max(timing[`${name}_max_ms`] ?? 0, ms);
            if (ms > TIMING_BUDGET_MS) fail(`${label}: ${name} took ${ms.toFixed(1)} ms on an adversarial input`);
          }
        }
      }
    }
    for (const key of ['js_max_ms', 'python_max_ms', 'go_max_ms']) if (typeof timing[key] === 'number') timing[key] = Number(timing[key].toFixed(2));
  }

  // -------------------------------------------------------------------------
  // 5. Every reason the corpora expect matches the reason rule
  // -------------------------------------------------------------------------

  const corpusFiles = ['caid/conformance'];
  const interopRoot = path.join(ROOT, 'caid/interop');
  for (const dir of readdirSync(interopRoot)) if (statSync(path.join(interopRoot, dir)).isDirectory()) corpusFiles.push(`caid/interop/${dir}`);
  const reasonStrings = new Set();
  const REASON_KEYS = new Set(['refusals', 'reasons', 'reason_contains']);
  const collect = (value, key) => {
    if (Array.isArray(value)) value.forEach((v) => collect(v, key));
    else if (value !== null && typeof value === 'object') for (const [k, v] of Object.entries(value)) collect(v, k);
    else if (typeof value === 'string' && REASON_KEYS.has(key)) reasonStrings.add(value);
  };
  for (const dir of corpusFiles) {
    for (const name of readdirSync(path.join(ROOT, dir))) {
      if (!name.endsWith('.json')) continue;
      collect(JSON.parse(readFileSync(path.join(ROOT, dir, name), 'utf8')), '');
    }
  }
  for (const r of reasonStrings) if (!matches(rules, 'reason', r)) fail(`the reason rule refuses the corpus reason ${JSON.stringify(r)}`);

  if (args.out) writeFileSync(args.out, JSON.stringify({ '@version': 'CAID-GRAMMAR-CASES-v1', generator: 'caid/spec/abnf-check.mjs', cases: corpus }, null, 1) + '\n');

  const summary = {
    rules: compiled.length,
    cases: totalCases,
    interpreted_rule_cases: interpretedCases,
    mismatches: args.jsOnly ? { js: lanes.js } : lanes,
    lanes: args.jsOnly ? ['interpreter', 'js'] : ['interpreter', 'js', 'python', 'go'],
    linear,
    catastrophic_controls_rejected: controls.length,
    corpus_reasons_matched: reasonStrings.size,
    python: args.jsOnly ? null : spawnSync(PYTHON, ['-c', 'import sys; print(sys.version.split()[0])'], { encoding: 'utf8' }).stdout.trim(),
    go: args.jsOnly ? null : spawnSync('go', ['env', 'GOVERSION'], { encoding: 'utf8' }).stdout.trim(),
    node: process.version,
    timing: args.timing ? timing : 'skipped',
    per_rule: perRule,
    failures: failures.length,
  };
  console.log(JSON.stringify(summary, null, 1));
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
if (failures.length) {
  process.stderr.write(`caid/spec/abnf-check.mjs FAILED\n${failures.slice(0, 40).map((f) => `  ${f}`).join('\n')}\n`);
  process.exit(1);
}
