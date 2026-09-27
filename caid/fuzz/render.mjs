// SPDX-License-Identifier: Apache-2.0
// Raw JSON text rendering for the CAID fuzzer.
//
// Node kinds accepted by render():
//   null / boolean / number / string / array / plain object   ordinary JSON
//   {$raw: "text"}              emitted verbatim (number literal forms, junk)
//   {$pairs: [[key, node], ...]} object whose member list may repeat a name;
//                               key is a string or {$raw: '"..."'}
// Strings are rendered with JSON.stringify (lone surrogates become \uXXXX
// escapes, which is what a raw JSON producer would send), or with every
// code unit \u-escaped when style.escape === "all".

const hex4 = (n) => n.toString(16).padStart(4, "0");

export function renderString(s, style = {}) {
  if (style.escape === "all") {
    let out = '"';
    for (let i = 0; i < s.length; i++) out += "\\u" + hex4(s.charCodeAt(i));
    return out + '"';
  }
  if (style.escape === "upper") {
    // Uppercase hex in escapes the stringifier emits.
    return JSON.stringify(s).replace(/\\u([0-9a-f]{4})/g, (_, h) => "\\u" + h.toUpperCase());
  }
  if (style.escape === "slash") return JSON.stringify(s).replaceAll("/", "\\/");
  return JSON.stringify(s);
}

export function render(node, style = {}, depth = 0) {
  const ws = style.ws || "compact";
  const nl = ws === "pretty" ? "\n" : ws === "crlf" ? "\r\n" : ws === "tabs" ? "\n" : "";
  const ind = (d) => (ws === "pretty" || ws === "crlf" ? "  ".repeat(d) : ws === "tabs" ? "\t".repeat(d) : "");
  const colon = ws === "compact" ? ":" : ": ";
  const comma = ws === "spaced" ? ", " : ",";
  if (node === null) return "null";
  if (typeof node === "boolean") return node ? "true" : "false";
  if (typeof node === "number") return Object.is(node, -0) ? "-0" : JSON.stringify(node);
  if (typeof node === "string") return renderString(node, style);
  if (Array.isArray(node)) {
    if (node.length === 0) return "[]";
    return "[" + nl + node.map((x) => ind(depth + 1) + render(x, style, depth + 1)).join(comma + nl) + nl + ind(depth) + "]";
  }
  if (typeof node === "object") {
    if (Object.prototype.hasOwnProperty.call(node, "$raw")) return node.$raw;
    const pairs = (Object.prototype.hasOwnProperty.call(node, "$pairs") ? node.$pairs : Object.entries(node)).filter(([, v]) => v !== undefined);
    if (pairs.length === 0) return "{}";
    return (
      "{" + nl +
      pairs
        .map(([k, v]) => ind(depth + 1) + (typeof k === "string" ? renderString(k, style) : k.$raw) + colon + render(v, style, depth + 1))
        .join(comma + nl) +
      nl + ind(depth) + "}"
    );
  }
  throw new Error("unrenderable node: " + typeof node + " " + String(node));
}
