// SPDX-License-Identifier: Apache-2.0
// CAID differential fuzz driver: JavaScript lanes.
//
// Reads JSON-lines cases on stdin, writes one JSON line per case on stdout:
//   {"id": ..., "r": {"js": <outcome>, "vendor": <outcome>}}
//
// Lanes:
//   js      <root>/caid/impl/js/caid.mjs and mapping.mjs
//   vendor  <root>/packages/verify/vendor/caid.mjs under the same mapping.mjs
//           (copied side by side into a scratch shim directory)
//
// Objects under test ("obj", base64 octets) go to the JSON text entry
// points (computeCaidJson, verifyCaidJson). When the octets decode
// (decodeCaidJson), the native entry point also runs on the decoded value
// and a different result is reported as "parity". "native" cases go to
// computeCaid and verifyCaid. Mapping sources in "src" are decoded with
// decodeCaidJson; a refusal is {"json_error": true}.
//
// Usage: node js-driver.mjs --root <tree root> --shim <dir> --tables <tables.json>

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { lines } from "../lines.mjs";
import { buildNative } from "../../conformance/runners/native.mjs";

const args = process.argv.slice(2);
const arg = (name) => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
/** @param {string} name */
const required = (name) => {
  const value = arg(name);
  if (value === undefined) throw new Error(`js-driver: ${name} is required`);
  return value;
};
const root = path.resolve(required("--root"));
const shim = path.resolve(required("--shim"));
const tables = JSON.parse(readFileSync(required("--tables"), "utf8"));
const load = (p) => import(pathToFileURL(p).href);
const LANES = {
  js: { core: await load(path.join(root, "caid/impl/js/caid.mjs")), map: await load(path.join(root, "caid/impl/js/mapping.mjs")) },
  vendor: { core: await load(path.join(shim, "caid.mjs")), map: await load(path.join(shim, "mapping.mjs")) },
};

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const resolve = (c, inlineKey, refKey, table) => (own(c, refKey) ? tables[table][c[refKey]] : c[inlineKey]);
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x)
  ? Object.fromEntries(Object.keys(x).sort().filter((key) => x[key] !== undefined).map((key) => [key, x[key]])) : x));
const clean = (r) => (r && typeof r === "object" ? JSON.parse(stable(r)) : r);

function api(core) {
  return {
    decode: (b) => core.decodeCaidJson(b),
    computeJson: (b, o) => core.computeCaidJson(b, o),
    verifyJson: (b, caid, o) => core.verifyCaidJson(b, caid, o),
    compute: (v, o) => core.computeCaid(v, o),
    verify: (v, caid, o) => core.verifyCaid(v, caid, o),
    parse: (s) => core.parseCaid(s),
  };
}
const APIS = Object.fromEntries(Object.entries(LANES).map(([k, l]) => [k, api(l.core)]));

function normMap(r) {
  if (!r || typeof r !== "object") return { bad_result: true };
  return r.ok === true ? { ok: true, caid: r.caid, digest: r.digest } : { ok: false, reasons: r.reasons };
}

function runLane(lane, c) {
  const { map } = LANES[lane];
  const a = APIS[lane];
  const rawDefs = resolve(c, "defs", "defs_ref", "defs");
  const defs = c.defs_native ? buildNative(rawDefs) : rawDefs;
  const snaps = resolve(c, "snaps", "snaps_ref", "snaps");
  try {
    const computeOpts = { definitions: defs, enumSnapshots: snaps };
    if (own(c, "suite")) computeOpts.suite = c.suite;
    const verifyOpts = { definitions: defs, enumSnapshots: snaps };
    if (own(c, "expected")) verifyOpts.expectedDefinitionSha256 = c.expected;
    switch (c.op) {
      case "compute":
      case "verify": {
        const run = (native, value) => (c.op === "compute"
          ? (native ? a.compute(value, computeOpts) : a.computeJson(value, computeOpts))
          : (native ? a.verify(value, c.caid, verifyOpts) : a.verifyJson(value, c.caid, verifyOpts)));
        if (own(c, "native")) return clean(run(true, buildNative(c.native)));
        const bytes = new Uint8Array(Buffer.from(c.obj, "base64"));
        const out = clean(run(false, bytes));
        const d = a.decode(bytes);
        if (d && d.ok === true) {
          const n = clean(run(true, d.value));
          if (stable(n) !== stable(out)) return { ...out, parity: n };
        }
        return out;
      }
      case "parse":
        return clean(a.parse(c.caid));
      case "definition":
        return clean(LANES[lane].core.definitionSha256(c.definition_native ? buildNative(c.definition) : c.definition));
      case "canon":
        return clean(LANES[lane].core.canonicalize(buildNative(c.native)));
      case "map": {
        let source = c.source;
        if (own(c, "src")) {
          const d = a.decode(new Uint8Array(Buffer.from(c.src, "base64")));
          if (!d || d.ok !== true) return { json_error: true };
          source = d.value;
        }
        const params = { profile: c.profile, sourceDescriptor: c.desc, expectedProfileHash: c.pin, nativeVerified: c.nv, definitions: defs, enumSnapshots: snaps };
        if (own(c, "suite")) params.suite = c.suite;
        return normMap(map.mapAction(source, params));
      }
      case "compare": {
        const params = { definitions: defs, enumSnapshots: snaps };
        if (own(c, "suite")) params.suite = c.suite;
        const r = map.compareMappedActions(c.left, c.right, params);
        return { verdict: r.verdict, reasons: r.reasons, left: normMap(r.left), right: normMap(r.right) };
      }
      default:
        return { driver_error: "unknown op " + c.op };
    }
  } catch (e) {
    return { crash: (e && e.name) || "throw" };
  }
}

const out = [];
const flush = () => {
  if (out.length) {
    process.stdout.write(out.join(""));
    out.length = 0;
  }
};
for await (const line of lines(process.stdin)) {
  if (!line) continue;
  const c = JSON.parse(line);
  const r = {};
  for (const lane of Object.keys(LANES)) r[lane] = runLane(lane, c);
  out.push(JSON.stringify({ id: c.id, r }) + "\n");
  if (out.length >= 256) flush();
}
flush();
