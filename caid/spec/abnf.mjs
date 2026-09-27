// SPDX-License-Identifier: Apache-2.0
//
// ABNF (RFC 5234, with the RFC 7405 %s and %i string notation) for the CAID
// grammar file: a parser, a membership interpreter, a compiler to the
// portable regular-expression subset that JavaScript RegExp, Python re, and
// Go regexp (RE2) evaluate identically, a static linear-time analysis of
// compiled expressions, and a sampler that draws members of a rule.
//
// Dev-time only. The CAID ports never load this module or the grammar file
// at run time; caid/spec/gen.mjs writes the compiled expressions into them.
//
// The portable subset (the compiler emits nothing else, and parseRegex
// refuses anything else):
//   - literal ASCII letters and digits, every other character as \xHH with
//     HH in 20-7E;
//   - character classes of such atoms and ascending ranges, never negated;
//   - non-capturing groups (?:...), alternation |;
//   - quantifiers ? * + {n} {n,} {n,m}, with every bound at most 1000
//     (the RE2 repetition limit).
// No anchors, no dot, no shorthand classes, no flags, no backreferences, no
// lookaround, no non-ASCII code point. Whole-string membership of such an
// expression is the same under the leftmost-first backtracking of V8 and
// CPython and the leftmost-longest automaton of RE2, and a character outside
// ASCII fails every class in all three: a UTF-16 unit in JavaScript, a code
// point in Python, a rune in Go (where invalid UTF-8 reads as U+FFFD).

const MAX_REPEAT = 1000;

// RFC 5234 Appendix B.1 core rules.
const CORE_TEXT = [
  'ALPHA  = %x41-5A / %x61-7A',
  'BIT    = "0" / "1"',
  'CHAR   = %x01-7F',
  'CR     = %x0D',
  'CRLF   = CR LF',
  'CTL    = %x00-1F / %x7F',
  'DIGIT  = %x30-39',
  'DQUOTE = %x22',
  'HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"',
  'HTAB   = %x09',
  'LF     = %x0A',
  'LWSP   = *(WSP / CRLF WSP)',
  'OCTET  = %x00-FF',
  'SP     = %x20',
  'VCHAR  = %x21-7E',
  'WSP    = SP / HTAB',
].join('\n');

/**
 * Parses ABNF text into a Map from lowercase rule name to AST node. A line
 * that begins with white space continues the previous line, so a rule name
 * may stand alone on its line with "=" on the next.
 *
 * Node shapes: {t:'range',lo,hi} | {t:'str',value,cs} | {t:'ref',name}
 * | {t:'alt',items} | {t:'cat',items} | {t:'rep',min,max,item}.
 *
 * @param {string} text
 * @param {string} [source] label for error messages
 * @returns {Map<string, any>}
 */
export function parseAbnf(text, source = 'abnf') {
  const logical = [];
  text.split('\n').forEach((raw, index) => {
    const where = `${source}:${index + 1}`;
    if (raw.includes('\r') || raw.includes('\t')) throw new Error(`${where}: CR or TAB in grammar text`);
    const line = stripComment(raw, where);
    if (!line.trim()) return;
    if (/^\s/.test(line)) {
      if (!logical.length) throw new Error(`${where}: continuation line without a rule`);
      logical[logical.length - 1].src += ' ' + line.trim();
      return;
    }
    logical.push({ src: line.trimEnd(), line: index + 1 });
  });
  const defs = new Map();
  for (const { src, line } of logical) {
    const m = /^([A-Za-z][A-Za-z0-9-]*)\s*(=\/|=)\s*(.*)$/.exec(src);
    if (!m) throw new Error(`${source}:${line}: not a rule definition`);
    const name = m[1].toLowerCase();
    if (m[2] === '=') {
      if (defs.has(name)) throw new Error(`${source}:${line}: rule ${m[1]} defined twice`);
      defs.set(name, { alternatives: [{ src: m[3], line }] });
    } else {
      const base = defs.get(name);
      if (!base) throw new Error(`${source}:${line}: =/ before ${m[1]} is defined`);
      base.alternatives.push({ src: m[3], line });
    }
  }
  const out = new Map();
  for (const [name, def] of defs) {
    const alternatives = def.alternatives.map((a) => parseElements(a.src, `${source}:${a.line} ${name}`));
    out.set(name, alternatives.length === 1 ? alternatives[0] : { t: 'alt', items: alternatives });
  }
  return out;
}

function stripComment(line, where) {
  let inString = false;
  let inProse = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (inString) { if (c === '"') inString = false; continue; }
    if (inProse) { if (c === '>') inProse = false; continue; }
    if (c === '"') inString = true;
    else if (c === '<') inProse = true;
    else if (c === ';') return line.slice(0, i);
  }
  if (inString) throw new Error(`${where}: unterminated quoted string`);
  return line;
}

function parseElements(src, where) {
  let i = 0;
  const ws = () => { while (i < src.length && src[i] === ' ') i += 1; };
  /** @param {string} msg @returns {never} */
  const fail = (msg) => { throw new Error(`${where}: ${msg} at ${JSON.stringify(src.slice(i, i + 12))}`); };
  function alternation() {
    const items = [concatenation()];
    ws();
    while (src[i] === '/') { i += 1; items.push(concatenation()); ws(); }
    return items.length === 1 ? items[0] : { t: 'alt', items };
  }
  function concatenation() {
    const items = [];
    for (;;) {
      ws();
      if (i >= src.length || src[i] === '/' || src[i] === ')' || src[i] === ']') break;
      items.push(repetition());
    }
    if (!items.length) fail('empty concatenation');
    return items.length === 1 ? items[0] : { t: 'cat', items };
  }
  function repetition() {
    const m = /^(\d*)\*(\d*)|^(\d+)/.exec(src.slice(i));
    let min = 1;
    let max = 1;
    if (m) {
      i += m[0].length;
      if (m[3] !== undefined) {
        min = Number(m[3]);
        max = min;
      } else {
        min = m[1] ? Number(m[1]) : 0;
        max = m[2] ? Number(m[2]) : Infinity;
      }
      if (max < min) fail('repetition maximum below minimum');
      if (max === 0) fail('repetition that matches nothing');
    }
    const el = element();
    return min === 1 && max === 1 ? el : { t: 'rep', min, max, item: el };
  }
  function element() {
    ws();
    const c = src[i];
    if (c === '(') {
      i += 1;
      const a = alternation();
      ws();
      if (src[i] !== ')') fail('expected )');
      i += 1;
      return a;
    }
    if (c === '[') {
      i += 1;
      const a = alternation();
      ws();
      if (src[i] !== ']') fail('expected ]');
      i += 1;
      return { t: 'rep', min: 0, max: 1, item: a };
    }
    if (c === '"') return charVal(false);
    if (c === '%') {
      const k = (src[i + 1] ?? '').toLowerCase();
      if (k === 's' || k === 'i') {
        i += 2;
        return charVal(k === 's');
      }
      return numVal();
    }
    if (c === '<') fail('prose-val is not machine-checkable');
    const m = /^[A-Za-z][A-Za-z0-9-]*/.exec(src.slice(i));
    if (!m) fail('unexpected text');
    i += m[0].length;
    return { t: 'ref', name: m[0].toLowerCase() };
  }
  function charVal(cs) {
    if (src[i] !== '"') fail('expected "');
    const j = src.indexOf('"', i + 1);
    if (j < 0) fail('unterminated quoted string');
    const value = src.slice(i + 1, j);
    for (const ch of value) {
      const cp = ch.codePointAt(0);
      if (cp < 0x20 || cp > 0x7e || cp === 0x22) fail('quoted string outside %x20-21 / %x23-7E');
    }
    if (!value.length) fail('empty quoted string');
    i = j + 1;
    return { t: 'str', value, cs };
  }
  function numVal() {
    const m = /^%([xXdDbB])([0-9A-Fa-f]+)(?:-([0-9A-Fa-f]+)|((?:\.[0-9A-Fa-f]+)+))?/.exec(src.slice(i));
    if (!m) fail('bad num-val');
    i += m[0].length;
    const base = { x: 16, d: 10, b: 2 }[m[1].toLowerCase()];
    const digitsOk = (s) => [...s].every((ch) => parseInt(ch, base) < base);
    for (const part of [m[2], m[3], ...(m[4] ? m[4].slice(1).split('.') : [])]) {
      if (part !== undefined && !digitsOk(part)) fail('num-val digit outside its base');
    }
    const lo = parseInt(m[2], base);
    if (m[3] !== undefined) {
      const hi = parseInt(m[3], base);
      if (hi < lo) fail('descending num-val range');
      return { t: 'range', lo, hi };
    }
    if (m[4] !== undefined) {
      const values = [lo, ...m[4].slice(1).split('.').map((x) => parseInt(x, base))];
      return { t: 'cat', items: values.map((v) => ({ t: 'range', lo: v, hi: v })) };
    }
    return { t: 'range', lo, hi: lo };
  }
  const node = alternation();
  ws();
  if (i !== src.length) fail('trailing text');
  return node;
}

const CORE = parseAbnf(CORE_TEXT, 'RFC 5234 B.1');

/**
 * Parses and merges grammar files into one rule set, refusing a rule
 * defined twice, a redefined core rule, a reference to an undefined rule,
 * and recursion.
 *
 * @param {Array<{text: string, source: string}>} files
 * @returns {Map<string, any>}
 */
export function loadGrammar(files) {
  const rules = new Map();
  for (const { text, source } of files) {
    for (const [name, node] of parseAbnf(text, source)) {
      if (rules.has(name)) throw new Error(`${source}: rule ${name} is already defined`);
      if (CORE.has(name)) throw new Error(`${source}: rule ${name} redefines an RFC 5234 core rule`);
      rules.set(name, node);
    }
  }
  const visiting = new Set();
  const done = new Set();
  const walk = (node, from) => {
    switch (node.t) {
      case 'ref': {
        const target = lookup(rules, node.name, from);
        if (done.has(node.name) || CORE.has(node.name)) return;
        if (visiting.has(node.name)) throw new Error(`recursive rule ${node.name}`);
        visiting.add(node.name);
        walk(target, node.name);
        visiting.delete(node.name);
        done.add(node.name);
        return;
      }
      case 'alt': case 'cat': node.items.forEach((n) => walk(n, from)); return;
      case 'rep': walk(node.item, from); return;
      default: return;
    }
  };
  for (const [name, node] of rules) {
    visiting.add(name);
    walk(node, name);
    visiting.delete(name);
    done.add(name);
  }
  return rules;
}

function lookup(rules, name, from = '?') {
  const node = rules.get(name) ?? CORE.get(name);
  if (!node) throw new Error(`rule ${from} references undefined rule ${name}`);
  return node;
}

const foldAscii = (cp) => (cp >= 0x41 && cp <= 0x5a ? cp + 32 : cp);

/**
 * Whole-string membership of `s` in rule `ruleName`, by direct evaluation of
 * the grammar over the string's code points. A lone surrogate is a code
 * point of its own here, as in Python; no CAID rule admits one.
 *
 * @param {Map<string, any>} rules
 * @param {string} ruleName
 * @param {string} s
 * @returns {boolean}
 */
export function matches(rules, ruleName, s) {
  const cps = Array.from(s, (c) => c.codePointAt(0));
  return endPositions(rules, lookup(rules, ruleName.toLowerCase()), cps, 0).has(cps.length);
}

function endPositions(rules, node, cps, pos) {
  switch (node.t) {
    case 'range':
      return pos < cps.length && cps[pos] >= node.lo && cps[pos] <= node.hi ? new Set([pos + 1]) : new Set();
    case 'str': {
      let k = 0;
      for (const ch of node.value) {
        const want = ch.codePointAt(0);
        const got = cps[pos + k];
        if (got === undefined) return new Set();
        if (node.cs ? got !== want : foldAscii(got) !== foldAscii(want)) return new Set();
        k += 1;
      }
      return new Set([pos + k]);
    }
    case 'ref':
      return endPositions(rules, lookup(rules, node.name), cps, pos);
    case 'alt': {
      const out = new Set();
      for (const item of node.items) for (const e of endPositions(rules, item, cps, pos)) out.add(e);
      return out;
    }
    case 'cat': {
      let cur = new Set([pos]);
      for (const item of node.items) {
        const next = new Set();
        for (const p of cur) for (const e of endPositions(rules, item, cps, p)) next.add(e);
        cur = next;
        if (!cur.size) break;
      }
      return cur;
    }
    case 'rep': {
      const result = new Set();
      if (node.min === 0) result.add(pos);
      let frontier = new Set([pos]);
      const seen = new Set([pos]);
      for (let n = 1; n <= node.max && frontier.size; n += 1) {
        const next = new Set();
        for (const p of frontier) for (const e of endPositions(rules, node.item, cps, p)) next.add(e);
        if (n >= node.min) {
          for (const e of next) result.add(e);
          // Past the minimum only new positions can extend the match set.
          frontier = new Set();
          for (const e of next) if (!seen.has(e)) { seen.add(e); frontier.add(e); }
        } else {
          frontier = next;
        }
      }
      return result;
    }
    default:
      throw new Error(`unknown node ${node.t}`);
  }
}

/**
 * The string values of a rule that is an alternation of case-sensitive
 * quoted strings (possibly through references), in grammar order, or null
 * when the rule has any other shape.
 *
 * @param {Map<string, any>} rules
 * @param {string} ruleName
 * @returns {string[] | null}
 */
export function literalAlternatives(rules, ruleName) {
  const out = [];
  const walk = (node) => {
    if (node.t === 'str' && node.cs) { out.push(node.value); return true; }
    if (node.t === 'ref') return walk(lookup(rules, node.name));
    if (node.t === 'alt') return node.items.every(walk);
    return false;
  };
  return walk(lookup(rules, ruleName.toLowerCase())) ? out : null;
}

// ---------------------------------------------------------------------------
// Sampler
// ---------------------------------------------------------------------------

/**
 * A deterministic pseudo-random generator (mulberry32) for case generation.
 *
 * @param {number} seed
 * @returns {() => number} uniform in [0, 1)
 */
export function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Draws one member of rule `ruleName`. Unbounded repetitions draw at most
 * `extra` iterations beyond their minimum.
 *
 * @param {Map<string, any>} rules
 * @param {string} ruleName
 * @param {() => number} rng
 * @param {{extra?: number}} [options]
 * @returns {string}
 */
export function sample(rules, ruleName, rng, { extra = 3 } = {}) {
  const pick = (n) => Math.floor(rng() * n);
  const go = (node) => {
    switch (node.t) {
      case 'range': {
        let cp = node.lo + pick(node.hi - node.lo + 1);
        if (cp >= 0xd800 && cp <= 0xdfff) cp = node.lo;
        return String.fromCodePoint(cp);
      }
      case 'str':
        return node.cs ? node.value : [...node.value].map((ch) => (pick(2) ? ch.toUpperCase() : ch.toLowerCase())).join('');
      case 'ref': return go(lookup(rules, node.name));
      case 'alt': return go(node.items[pick(node.items.length)]);
      case 'cat': return node.items.map(go).join('');
      case 'rep': {
        const hi = node.max === Infinity ? node.min + extra : Math.min(node.max, node.min + extra);
        const n = node.min + pick(hi - node.min + 1);
        let s = '';
        for (let k = 0; k < n; k += 1) s += go(node.item);
        return s;
      }
      default: throw new Error(`unknown node ${node.t}`);
    }
  };
  return go(lookup(rules, ruleName.toLowerCase()));
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

function escapeCodePoint(cp) {
  if (cp < 0x20 || cp > 0x7e) {
    throw new Error(`code point U+${cp.toString(16).toUpperCase().padStart(4, '0')} is outside the portable ASCII subset`);
  }
  const ch = String.fromCharCode(cp);
  return /[A-Za-z0-9]/.test(ch) ? ch : '\\x' + cp.toString(16).padStart(2, '0');
}

// The single-character set a node matches, as sorted disjoint [lo, hi]
// ranges, or null when the node can match anything other than exactly one
// character.
function charSet(rules, node) {
  switch (node.t) {
    case 'range': return [[node.lo, node.hi]];
    case 'str': {
      const chars = [...node.value];
      if (chars.length !== 1) return null;
      const cp = chars[0].codePointAt(0);
      if (node.cs) return [[cp, cp]];
      const lower = foldAscii(cp);
      return lower >= 0x61 && lower <= 0x7a ? normalizeRanges([[lower - 32, lower - 32], [lower, lower]]) : [[cp, cp]];
    }
    case 'ref': return charSet(rules, lookup(rules, node.name));
    case 'alt': {
      const all = [];
      for (const item of node.items) {
        const s = charSet(rules, item);
        if (!s) return null;
        all.push(...s);
      }
      return normalizeRanges(all);
    }
    default: return null;
  }
}

function normalizeRanges(ranges) {
  const sorted = ranges.map((r) => [...r]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push(r);
  }
  return out;
}

function classSource(ranges) {
  if (ranges.length === 1 && ranges[0][0] === ranges[0][1]) return escapeCodePoint(ranges[0][0]);
  const body = ranges.map(([lo, hi]) => {
    if (lo === hi) return escapeCodePoint(lo);
    if (hi === lo + 1) return escapeCodePoint(lo) + escapeCodePoint(hi);
    return `${escapeCodePoint(lo)}-${escapeCodePoint(hi)}`;
  }).join('');
  return `[${body}]`;
}

/**
 * Compiles rule `ruleName` to an expression in the portable subset, without
 * anchors. Each port wraps it in its own whole-string idiom.
 *
 * @param {Map<string, any>} rules
 * @param {string} ruleName
 * @returns {string}
 */
export function compile(rules, ruleName) {
  // Returns [source, kind] where kind is 'atom' (one class or escaped
  // character: safe to quantify), 'seq' (safe to concatenate), or 'alt'.
  const go = (node) => {
    const set = charSet(rules, node);
    if (set) return [classSource(set), 'atom'];
    switch (node.t) {
      case 'str': {
        const parts = [...node.value].map((ch) => {
          const cp = ch.codePointAt(0);
          const lower = foldAscii(cp);
          if (!node.cs && lower >= 0x61 && lower <= 0x7a) return classSource([[lower - 32, lower - 32], [lower, lower]]);
          return escapeCodePoint(cp);
        });
        return [parts.join(''), 'seq'];
      }
      case 'ref':
        return go(lookup(rules, node.name));
      case 'alt': {
        // Single-character alternatives merge into one class, placed first.
        // Whole-string membership does not depend on alternative order.
        const singles = [];
        const others = [];
        for (const n of node.items) {
          const s = charSet(rules, n);
          if (s) singles.push(...s);
          else others.push(go(n)[0]);
        }
        const parts = singles.length ? [classSource(normalizeRanges(singles)), ...others] : others;
        return parts.length === 1 ? [parts[0], 'seq'] : [parts.join('|'), 'alt'];
      }
      case 'cat':
        return [node.items.map((n) => {
          const [src, kind] = go(n);
          return kind === 'alt' ? `(?:${src})` : src;
        }).join(''), 'seq'];
      case 'rep': {
        if (node.min > MAX_REPEAT || (node.max !== Infinity && node.max > MAX_REPEAT)) {
          throw new Error(`repetition bound above ${MAX_REPEAT} is not portable`);
        }
        const [src, kind] = go(node.item);
        const body = kind === 'atom' ? src : `(?:${src})`;
        let q;
        if (node.min === 0 && node.max === 1) q = '?';
        else if (node.min === 0 && node.max === Infinity) q = '*';
        else if (node.min === 1 && node.max === Infinity) q = '+';
        else if (node.max === Infinity) q = `{${node.min},}`;
        else if (node.min === node.max) q = `{${node.min}}`;
        else q = `{${node.min},${node.max}}`;
        return [body + q, 'seq'];
      }
      default:
        throw new Error(`cannot compile node ${node.t}`);
    }
  };
  const [src, kind] = go(lookup(rules, ruleName.toLowerCase()));
  const out = kind === 'alt' ? `(?:${src})` : src;
  parseRegex(out);
  return out;
}

// ---------------------------------------------------------------------------
// Regular-expression AST, independent of the compiler
// ---------------------------------------------------------------------------

/**
 * Parses an expression of the portable subset into an AST, throwing on
 * anything outside the subset. Independent of the compiler, so a compiler
 * defect cannot emit a non-portable expression unnoticed.
 *
 * AST: {t:'cls',ranges} | {t:'seq',items} | {t:'alt',items}
 * | {t:'rep',min,max,item}; max is Infinity for an unbounded quantifier.
 *
 * @param {string} src
 */
export function parseRegex(src) {
  let i = 0;
  /** @param {string} msg @returns {never} */
  const fail = (msg) => { throw new Error(`non-portable regular expression (${msg}) at ${i}: ${src}`); };
  const atomChar = () => {
    const c = src[i];
    if (c === undefined) fail('unexpected end');
    if (/[A-Za-z0-9]/.test(c)) { i += 1; return c.charCodeAt(0); }
    if (c === '\\') {
      const m = /^\\x([0-9a-f]{2})/.exec(src.slice(i));
      if (!m) fail('escape other than \\xHH');
      const cp = parseInt(m[1], 16);
      if (cp < 0x20 || cp > 0x7e) fail('escaped code point outside 20-7E');
      if (/[A-Za-z0-9]/.test(String.fromCharCode(cp))) fail('escaped letter or digit');
      i += 4;
      return cp;
    }
    return fail('bare punctuation');
  };
  const bound = (s) => {
    const n = Number(s);
    if (!/^(0|[1-9][0-9]*)$/.test(s) || n > MAX_REPEAT) fail('repetition bound');
    return n;
  };
  const quantified = (item) => {
    const c = src[i];
    let q = null;
    if (c === '?') q = [0, 1];
    else if (c === '*') q = [0, Infinity];
    else if (c === '+') q = [1, Infinity];
    if (q) i += 1;
    else if (c === '{') {
      const m = /^\{([0-9]+)(,([0-9]*))?\}/.exec(src.slice(i));
      if (!m) fail('malformed {}');
      const lo = bound(m[1]);
      let hi = lo;
      if (m[2] !== undefined) hi = m[3] ? bound(m[3]) : Infinity;
      if (hi < lo) fail('descending {m,n}');
      if (hi === 0) fail('quantifier that matches nothing');
      i += m[0].length;
      q = [lo, hi];
    }
    if (!q) return item;
    if (i < src.length && '?*+{'.includes(src[i])) fail('stacked quantifier');
    return { t: 'rep', min: q[0], max: q[1], item };
  };
  const alternation = () => {
    const items = [sequence()];
    while (src[i] === '|') { i += 1; items.push(sequence()); }
    return items.length === 1 ? items[0] : { t: 'alt', items };
  };
  const sequence = () => {
    const items = [];
    while (i < src.length && src[i] !== '|' && src[i] !== ')') {
      const c = src[i];
      let atom;
      if (c === '(') {
        if (src.slice(i, i + 3) !== '(?:') fail('group other than (?:');
        i += 3;
        atom = alternation();
        if (src[i] !== ')') fail('unclosed group');
        i += 1;
      } else if (c === '[') {
        i += 1;
        if (src[i] === '^') fail('negated class');
        const ranges = [];
        while (src[i] !== ']') {
          const lo = atomChar();
          let hi = lo;
          if (src[i] === '-' && src[i + 1] !== ']') {
            i += 1;
            hi = atomChar();
            if (hi < lo) fail('descending class range');
          }
          ranges.push([lo, hi]);
        }
        if (!ranges.length) fail('empty class');
        i += 1;
        atom = { t: 'cls', ranges: normalizeRanges(ranges) };
      } else {
        const cp = atomChar();
        atom = { t: 'cls', ranges: [[cp, cp]] };
      }
      items.push(quantified(atom));
    }
    if (!items.length) fail('empty alternative');
    return items.length === 1 ? items[0] : { t: 'seq', items };
  };
  const ast = alternation();
  if (i !== src.length) fail('unbalanced )');
  return ast;
}

// ---------------------------------------------------------------------------
// Linear-time analysis
// ---------------------------------------------------------------------------
//
// Two sufficient conditions, each checked statically on the AST above.
//
// Deterministic (LL(1)): at every choice point, which is an alternation or
// an optional iteration of a quantifier, the alternatives' first characters
// (with end of input as a character) are pairwise disjoint, and no
// quantified body can match the empty string. A backtracking engine then
// leaves every wrong branch after one character comparison and a bounded
// number of empty steps, so an anchored whole-string match costs
// O(n * |R|). RE2 is linear in any case.
//
// Finite: every quantifier is bounded, no quantifier whose maximum exceeds
// one contains another such quantifier (no nested quantifiers), and at
// every optional quantifier iteration the body's first characters are
// disjoint from what may follow (no overlapping quantifiers). The language
// is then finite; a backtracking engine explores at most the pattern's path
// count times its maximum match length steps per start position, a
// constant independent of the input, so an anchored match costs O(n) in
// the worst case (JavaScript's ^ fails in O(1) at every later position).

const END = -1;

function unionRanges(a, b) { return normalizeRanges([...a, ...b]); }
function intersects(a, b) {
  for (const [lo1, hi1] of a) for (const [lo2, hi2] of b) if (lo1 <= hi2 && lo2 <= hi1) return true;
  return false;
}

function nullable(node) {
  switch (node.t) {
    case 'cls': return false;
    case 'seq': return node.items.every(nullable);
    case 'alt': return node.items.some(nullable);
    case 'rep': return node.min === 0 || nullable(node.item);
    default: throw new Error(`unknown regex node ${node.t}`);
  }
}

function first(node) {
  switch (node.t) {
    case 'cls': return node.ranges;
    case 'seq': {
      let out = [];
      for (const item of node.items) {
        out = unionRanges(out, first(item));
        if (!nullable(item)) break;
      }
      return out;
    }
    case 'alt': return node.items.reduce((acc, item) => unionRanges(acc, first(item)), []);
    case 'rep': return first(node.item);
    default: throw new Error(`unknown regex node ${node.t}`);
  }
}

const describe = (ranges) => ranges.map(([lo, hi]) => {
  const c = (x) => (x === END ? 'END' : x >= 0x21 && x <= 0x7e ? String.fromCharCode(x) : `U+${x.toString(16)}`);
  return lo === hi ? c(lo) : `${c(lo)}-${c(hi)}`;
}).join(' ');

// Collects choice-point conflicts. `follow` is the set of characters (END
// included) that may come right after `node`.
function choiceConflicts(node, follow, out) {
  switch (node.t) {
    case 'cls': return;
    case 'seq': {
      for (let k = 0; k < node.items.length; k += 1) {
        let f = [];
        let restNullable = true;
        for (let j = k + 1; j < node.items.length; j += 1) {
          f = unionRanges(f, first(node.items[j]));
          if (!nullable(node.items[j])) { restNullable = false; break; }
        }
        if (restNullable) f = unionRanges(f, follow);
        choiceConflicts(node.items[k], f, out);
      }
      return;
    }
    case 'alt': {
      const sets = node.items.map((item) => (nullable(item) ? unionRanges(first(item), follow) : first(item)));
      if (node.items.filter(nullable).length > 1) out.push({ kind: 'alternation', detail: 'two alternatives match the empty string' });
      for (let a = 0; a < sets.length; a += 1) {
        for (let b = a + 1; b < sets.length; b += 1) {
          if (intersects(sets[a], sets[b])) {
            out.push({ kind: 'alternation', detail: `alternatives ${a + 1} and ${b + 1} both start with ${describe(normalizeRanges(sets[a].filter((r) => intersects([r], sets[b]))))}` });
          }
        }
      }
      node.items.forEach((item) => choiceConflicts(item, follow, out));
      return;
    }
    case 'rep': {
      const variable = node.min < node.max;
      if (node.max > 1 && nullable(node.item)) out.push({ kind: 'quantifier', detail: 'a repeated body matches the empty string' });
      if (variable && intersects(first(node.item), follow)) {
        out.push({ kind: 'quantifier', detail: `an optional iteration and what follows both start with ${describe(normalizeRanges(first(node.item).filter((r) => intersects([r], follow))))}` });
      }
      const inner = node.max > 1 ? unionRanges(first(node.item), follow) : follow;
      choiceConflicts(node.item, inner, out);
      return;
    }
    default: throw new Error(`unknown regex node ${node.t}`);
  }
}

function maxLength(node) {
  switch (node.t) {
    case 'cls': return 1;
    case 'seq': return node.items.reduce((acc, item) => acc + maxLength(item), 0);
    case 'alt': return Math.max(...node.items.map(maxLength));
    case 'rep': return node.max === Infinity ? Infinity : node.max * maxLength(node.item);
    default: throw new Error(`unknown regex node ${node.t}`);
  }
}

function pathCount(node) {
  switch (node.t) {
    case 'cls': return 1n;
    case 'seq': return node.items.reduce((acc, item) => acc * pathCount(item), 1n);
    case 'alt': return node.items.reduce((acc, item) => acc + pathCount(item), 0n);
    case 'rep': {
      if (node.max === Infinity) return -1n;
      const body = pathCount(node.item);
      let total = 0n;
      for (let k = node.min; k <= node.max; k += 1) total += body ** BigInt(k);
      return total;
    }
    default: throw new Error(`unknown regex node ${node.t}`);
  }
}

function nestedQuantifiers(node, inside, out) {
  if (node.t === 'rep') {
    const repeats = node.max > 1;
    if (repeats && inside) out.push({ kind: 'nesting', detail: 'a quantifier with maximum above 1 inside another' });
    nestedQuantifiers(node.item, inside || repeats, out);
  } else if (node.items) {
    node.items.forEach((item) => nestedQuantifiers(item, inside, out));
  }
}

function unbounded(node) {
  if (node.t === 'rep') return node.max === Infinity || unbounded(node.item);
  return node.items ? node.items.some(unbounded) : false;
}

/** Worst-case backtracking steps per start position a finite pattern may take. */
export const FINITE_STEP_BUDGET = 4096n;

/**
 * Static linear-time analysis of a portable expression.
 *
 * @param {string} src
 * @returns {{
 *   deterministic: boolean, finite: boolean, linear: boolean,
 *   conflicts: Array<{kind: string, detail: string}>,
 *   nesting: Array<{kind: string, detail: string}>,
 *   max_length: number | null, paths: string | null, step_bound: string | null
 * }}
 */
export function analyzeRegex(src) {
  const ast = parseRegex(src);
  const conflicts = [];
  choiceConflicts(ast, [[END, END]], conflicts);
  const nesting = [];
  nestedQuantifiers(ast, false, nesting);
  const deterministic = conflicts.length === 0;
  const isFinite = !unbounded(ast);
  const length = isFinite ? maxLength(ast) : null;
  const paths = isFinite ? pathCount(ast) : null;
  const steps = isFinite && paths !== null && length !== null ? paths * BigInt(length) : null;
  const quantifierConflicts = conflicts.filter((c) => c.kind === 'quantifier');
  const finiteSafe = isFinite && nesting.length === 0 && quantifierConflicts.length === 0 && steps !== null && steps >= 0n && steps <= FINITE_STEP_BUDGET;
  return {
    deterministic,
    finite: finiteSafe,
    linear: deterministic || finiteSafe,
    conflicts,
    nesting,
    max_length: length,
    paths: paths === null ? null : paths.toString(),
    step_bound: steps === null ? null : steps.toString(),
  };
}

/**
 * The digest syntax of a suite whose digest is `octets` octets, derived as
 * the draft states it: ceil(8n/6) base64url characters, the final one
 * carrying (6 * ceil(8n/6) - 8n) zero low bits. Returns the portable
 * expression and, for inspection, the permitted final characters.
 *
 * @param {number} octets
 * @returns {{source: string, length: number, finals: string}}
 */
export function digestSyntax(octets) {
  if (!Number.isSafeInteger(octets) || octets < 1) throw new Error(`bad digest length ${octets}`);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const length = Math.ceil((octets * 8) / 6);
  const unused = length * 6 - octets * 8;
  const mask = (1 << unused) - 1;
  const finals = [...alphabet].filter((_, value) => (value & mask) === 0).join('');
  if (length - 1 > MAX_REPEAT) throw new Error('digest too long for the portable subset');
  const all = classSource(normalizeRanges([...alphabet].map((c) => [c.charCodeAt(0), c.charCodeAt(0)])));
  const last = classSource(normalizeRanges([...finals].map((c) => [c.charCodeAt(0), c.charCodeAt(0)])));
  const source = unused === 0
    ? `${all}{${length}}`
    : `${length - 1 === 1 ? all : `${all}{${length - 1}}`}${last}`;
  parseRegex(source);
  return { source, length, finals };
}
