// SPDX-License-Identifier: Apache-2.0
//
// Token-exact JSON text helpers for building the corpora.
//
// rawSpans(text, want) walks a JSON text and returns the exact source text
// of every value whose path satisfies want(path). Tokens are never
// re-encoded, so a number literal such as 1e400 or 12.0, or a string escape
// such as \ud800, keeps its original spelling. minify(raw) removes the
// white space between tokens and nothing else. stringify(value) is the
// canonical-free, compact encoder the corpus uses for new inputs.

/**
 * @param {string} text
 * @param {(path: (string|number)[]) => boolean} want
 * @returns {Map<string, string>} JSON-encoded path -> raw value text
 */
export function rawSpans(text, want) {
  let i = 0;
  const out = new Map();
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i += 1; };
  const str = () => {
    const start = i;
    i += 1;
    while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    i += 1;
    return JSON.parse(text.slice(start, i));
  };
  const value = (path) => {
    ws();
    const start = i;
    const c = text[i];
    if (c === '{') {
      i += 1;
      ws();
      if (text[i] === '}') i += 1;
      else {
        for (;;) {
          ws();
          const key = str();
          ws();
          i += 1; // ':'
          value([...path, key]);
          ws();
          if (text[i] === ',') { i += 1; continue; }
          i += 1; // '}'
          break;
        }
      }
    } else if (c === '[') {
      i += 1;
      ws();
      if (text[i] === ']') i += 1;
      else {
        for (let k = 0; ; k += 1) {
          value([...path, k]);
          ws();
          if (text[i] === ',') { i += 1; continue; }
          i += 1;
          break;
        }
      }
    } else if (c === '"') {
      str();
    } else {
      const m = /-?[0-9][0-9.eE+-]*|true|false|null/y;
      m.lastIndex = i;
      const r = m.exec(text);
      if (!r) throw new Error(`bad token at ${i}`);
      i += r[0].length;
    }
    if (want(path)) out.set(JSON.stringify(path), text.slice(start, i));
  };
  value([]);
  return out;
}

/** Removes white space between tokens; string tokens are kept byte for byte. */
export function minify(raw) {
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw[i];
    if (c === '"') {
      const start = i;
      i += 1;
      while (raw[i] !== '"') i += raw[i] === '\\' ? 2 : 1;
      out += raw.slice(start, i + 1);
    } else if (!' \t\n\r'.includes(c)) {
      out += c;
    }
  }
  return out;
}
