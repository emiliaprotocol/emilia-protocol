#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// CAID cross-language differential fuzzer: orchestrator.
//
// Feeds identical cases (gen.mjs) to four lanes through their public entry
// points, and compares every lane's outcome with the spec oracle
// (caid/conformance/tools/oracle.mjs and mapping-oracle.mjs, built from the
// generated caid/spec constants and core.json):
//   js      <root>/caid/impl/js
//   vendor  <root>/packages/verify/vendor/caid.mjs (with the js mapping)
//   py      <root>/caid/impl/python
//   go      <root>/caid/impl/go
// Objects under test travel as octets and go to the -05 JSON text entry
// points; each driver also checks native-entry-point parity on decodable
// text. Native-lane cases go to the native entry points.
//
// Every lane outcome that differs from the oracle is grouped into a class
// ("op | lane | cause | oracle=shape | lane=shape") with a smallest
// reproducer and a named root cause (rootcauses.mjs).
//
// Usage:
//   node run.mjs [--root <tree root>] [--out DIR] [--seed N] [--quick]
//                [--cases DIR]      reuse cases.jsonl/tables.json from DIR
//                [--allow FILE]     JSON array of root-cause ids that do not fail
//                [--ci]             exit 1 on any class not allowed
//                [--selftest]       drive only the JavaScript lanes, with the
//                                   spec oracle itself as the implementation:
//                                   any class is a harness defect
// The tree is only read. Everything is written under --out. CAID_PYTHON
// names the Python interpreter (default python3).

import { spawn, spawnSync } from "node:child_process";
import { closeSync, copyFileSync, createReadStream, mkdirSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lines } from "./lines.mjs";
import { rootCauseOf } from "./rootcauses.mjs";
import * as oracle from "../conformance/tools/oracle.mjs";
import { compareMappedActions, mapAction } from "../conformance/tools/mapping-oracle.mjs";
import { decodeStrict } from "../conformance/tools/strict-json.mjs";
import { buildNative } from "../conformance/runners/native.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const arg = (n, d) => {
  const i = args.indexOf(n);
  return i === -1 ? d : args[i + 1];
};
// The default output directory is outside the checkout: the scratch Go
// module it holds must not be mistaken for a repository module.
const OUT = path.resolve(arg("--out", path.join(os.tmpdir(), "caid-fuzz", "run")));
const SELFTEST = args.includes("--selftest");
let ROOT = path.resolve(arg("--root", path.resolve(HERE, "../..")));
if (SELFTEST) {
  // A tree whose JavaScript implementation is the spec oracle.
  ROOT = path.join(OUT, "selftest-tree");
  rmSync(ROOT, { recursive: true, force: true });
  mkdirSync(path.join(ROOT, "caid/impl/js"), { recursive: true });
  mkdirSync(path.join(ROOT, "packages/verify/vendor"), { recursive: true });
  const tools = path.resolve(HERE, "../conformance/tools");
  const core = `export * from ${JSON.stringify(path.join(tools, "reference-port.mjs"))};\n`;
  writeFileSync(path.join(ROOT, "caid/impl/js/caid.mjs"), core);
  writeFileSync(path.join(ROOT, "packages/verify/vendor/caid.mjs"), core);
  writeFileSync(path.join(ROOT, "caid/impl/js/mapping.mjs"), `export { mapAction, compareMappedActions, mappingProfileHash } from ${JSON.stringify(path.join(tools, "mapping-oracle.mjs"))};\n`);
}
const SEED = arg("--seed", "20260926");
const QUICK = args.includes("--quick");
const CASES_DIR = arg("--cases") ? path.resolve(arg("--cases")) : null;
const ALLOW = arg("--allow") ? new Set(JSON.parse(readFileSync(arg("--allow"), "utf8"))) : new Set();
const CI = args.includes("--ci");
const PYTHON = process.env.CAID_PYTHON || "python3";
mkdirSync(OUT, { recursive: true });
const t0 = Date.now();
const timings = {};

// ---------------------------------------------------------------- generate
let casesDir = CASES_DIR;
if (!casesDir) {
  casesDir = OUT;
  const t = Date.now();
  const g = spawnSync(process.execPath, [path.join(HERE, "gen.mjs"), "--out", OUT, "--seed", SEED, ...(QUICK ? ["--quick"] : [])], { encoding: "utf8", maxBuffer: 64 << 20 });
  if (g.status !== 0) {
    process.stderr.write(g.stdout + g.stderr);
    process.exit(2);
  }
  timings.generate_ms = Date.now() - t;
}
const casesPath = path.join(casesDir, "cases.jsonl");
const tablesPath = path.join(casesDir, "tables.json");
const tables = JSON.parse(readFileSync(tablesPath, "utf8"));

// ---------------------------------------------------------------- build
const shim = path.join(OUT, "vendor-shim");
mkdirSync(shim, { recursive: true });
copyFileSync(path.join(ROOT, "packages/verify/vendor/caid.mjs"), path.join(shim, "caid.mjs"));
copyFileSync(path.join(ROOT, "caid/impl/js/mapping.mjs"), path.join(shim, "mapping.mjs"));
const goBuild = path.join(OUT, "go-build");
const goBin = path.join(OUT, "go-driver");
if (!SELFTEST) {
  mkdirSync(goBuild, { recursive: true });
  writeFileSync(path.join(goBuild, "go.mod"), `module fuzzdriver\n\ngo 1.22\n\nrequire caid v0.0.0\n\nreplace caid => ${path.join(ROOT, "caid/impl/go")}\n`);
  for (const f of readdirSync(path.join(HERE, "drivers/go"))) if (f.endsWith(".go")) copyFileSync(path.join(HERE, "drivers/go", f), path.join(goBuild, f));
  // The native-lane builder is the conformance runner's, shared.
  copyFileSync(path.resolve(HERE, "../conformance/runners/go/native.go"), path.join(goBuild, "native.go"));
  {
    const t = Date.now();
    const env = { ...process.env, GOFLAGS: "-mod=mod" };
    const b = spawnSync("go", ["build", "-o", goBin, "."], { cwd: goBuild, encoding: "utf8", env });
    if (b.status !== 0) {
      process.stderr.write("go build failed\n" + b.stdout + b.stderr);
      process.exit(2);
    }
    timings.go_build_ms = Date.now() - t;
  }
}

// ---------------------------------------------------------------- drive
function drive(name, cmd, argv) {
  return new Promise((resolve) => {
    const t = Date.now();
    const inFd = openSync(casesPath, "r");
    const outPath = path.join(OUT, `out-${name}.jsonl`);
    const outFd = openSync(outPath, "w");
    const errPath = path.join(OUT, `err-${name}.txt`);
    const errFd = openSync(errPath, "w");
    const p = spawn(cmd, argv, { stdio: [inFd, outFd, errFd] });
    p.on("close", (code, signal) => {
      closeSync(inFd);
      closeSync(outFd);
      closeSync(errFd);
      timings[name + "_ms"] = Date.now() - t;
      resolve({ name, code, signal, outPath, errPath });
    });
  });
}
const runs = await Promise.all([
  drive("js", process.execPath, ["--stack-size=984", path.join(HERE, "drivers/js-driver.mjs"), "--root", ROOT, "--shim", shim, "--tables", tablesPath]),
  ...(SELFTEST ? [] : [
    drive("py", PYTHON, [path.join(HERE, "drivers/py_driver.py"), "--root", ROOT, "--tables", tablesPath]),
    drive("go", goBin, ["--tables", tablesPath]),
  ]),
]);
for (const r of runs) {
  if (r.code !== 0) {
    process.stderr.write(`driver ${r.name} exited ${r.code} ${r.signal || ""}\n` + readFileSync(r.errPath, "utf8").slice(-4000));
    process.exit(2);
  }
}

// ---------------------------------------------------------------- oracle
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const resolveRef = (c, inlineKey, refKey, table) => (own(c, refKey) ? tables[table][c[refKey]] : c[inlineKey]);
const normMap = (r) => (r.ok === true ? { ok: true, caid: r.caid, digest: r.digest } : { ok: false, reasons: r.reasons });

function expected(c) {
  const rawDefs = resolveRef(c, "defs", "defs_ref", "defs");
  // A case whose definitions are native-lane encodings (defs_native).
  const defs = c.defs_native ? buildNative(rawDefs) : rawDefs;
  const snaps = resolveRef(c, "snaps", "snaps_ref", "snaps");
  switch (c.op) {
    case "compute": {
      const o = { definitions: defs, enum_snapshots: snaps };
      if (own(c, "suite")) o.suite = c.suite;
      return own(c, "native") ? oracle.compute(buildNative(c.native), o) : oracle.computeText(new Uint8Array(Buffer.from(c.obj, "base64")), o);
    }
    case "verify": {
      const o = { definitions: defs, enum_snapshots: snaps };
      if (own(c, "expected")) o.expected_definition_sha256 = c.expected;
      return own(c, "native") ? oracle.verify(buildNative(c.native), c.caid, o) : oracle.verifyText(new Uint8Array(Buffer.from(c.obj, "base64")), c.caid, o);
    }
    case "parse":
      return oracle.parse(c.caid);
    case "definition":
      return oracle.definitionSha256(c.definition_native ? buildNative(c.definition) : c.definition);
    case "canon":
      // The ports' canonicalize takes a document: the document ceiling
      // applies, not the action-object limit.
      return oracle.reference.canonicalizeDocument(buildNative(c.native));
    case "map": {
      let source = c.source;
      if (own(c, "src")) {
        const d = oracle.decode(new Uint8Array(Buffer.from(c.src, "base64")));
        if (!d.ok) return { json_error: true };
        source = d.value;
      }
      return normMap(mapAction(source, { profile: c.profile, sourceDescriptor: c.desc, expectedProfileHash: c.pin, nativeVerified: c.nv, definitions: defs, enumSnapshots: snaps, suite: own(c, "suite") ? c.suite : undefined }));
    }
    case "compare": {
      const r = compareMappedActions(c.left, c.right, { definitions: defs, enumSnapshots: snaps, suite: own(c, "suite") ? c.suite : undefined });
      return { verdict: r.verdict, reasons: r.reasons, left: normMap(r.left), right: normMap(r.right) };
    }
  }
  return { driver_error: "unknown op" };
}

// The typed Go API cannot carry a non-object profile, descriptor or side
// (it receives a nil map), so those mapping cases are not compared in the
// go lane.
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function goExpressible(c) {
  if (c.op === "map") return isObject(c.profile) && (c.desc === undefined || isObject(c.desc));
  if (c.op === "compare") return [c.left, c.right].every((s) => isObject(s) && isObject(s.profile) && (s.source_descriptor === undefined || isObject(s.source_descriptor)));
  return true;
}

// ---------------------------------------------------------------- compare
function stable(v) {
  if (Array.isArray(v)) return "[" + v.map(stable).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",") + "}";
  return JSON.stringify(v);
}
const code = (r) => String(r).split(":")[0];
function shape(op, o) {
  if (!o || typeof o !== "object") return "NONE";
  if (o.json_error) return "JSON_ERROR";
  if (o.crash) return "THROWS:" + o.crash;
  if (o.driver_error) return "DRIVER:" + o.driver_error;
  if (o.parity) return "PARITY";
  switch (op) {
    case "compute":
      return typeof o.caid === "string" ? "CAID" : "REFUSE{" + (o.refusals || []).map(code).join(",") + "}";
    case "verify":
      return (o.valid ? "VALID" : "INVALID") + "{" + (o.reasons || []).join(",") + "}";
    case "parse":
      return o.ok ? "OK" : "REFUSE{" + (o.refusals || []).join(",") + "}";
    case "definition":
      return typeof o.definition_sha256 === "string" ? "DIGEST" : "REFUSE{" + (o.refusals || []).join(",") + "}";
    case "canon":
      return o.ok ? "OK" : "REFUSE{" + (o.refusals || []).join(",") + "}";
    case "map":
      return o.ok ? "OK" : "FAIL{" + (o.reasons || []).map(code).join(",") + "}";
    case "compare":
      return o.verdict + "{" + (o.reasons || []).map((r) => r.split(":").slice(0, 2).join(":")).join(",") + "}";
  }
  return "?";
}
function causeOf(c) {
  const b64 = c.obj ?? c.src;
  if (b64 !== undefined) {
    const d = decodeStrict(new Uint8Array(Buffer.from(b64, "base64")));
    if (!d.ok) return "JSON text: " + d.detail.replace(/ at offset \d+$/, "").replace(/input is \d+ octets.*/, "size limit");
  }
  if (own(c, "native")) return "native " + (c.mut || c.fam).replace(/^native /, "");
  return c.mut || c.note || c.fam;
}

const LANES = ["js", "vendor", "py", "go"];
const classes = new Map();
const perFamily = {};
const byOp = {};
let total = 0;
function addClass(key, c, outcomes, exp, extra) {
  let e = classes.get(key);
  const size = JSON.stringify(c).length;
  if (!e) {
    e = { key, count: 0, families: {}, example_ids: [], min_size: Infinity, reproducer: null, ...extra };
    classes.set(key, e);
  }
  e.count++;
  e.families[c.fam] = (e.families[c.fam] || 0) + 1;
  if (e.example_ids.length < 5) e.example_ids.push(c.id);
  if (size < e.min_size) {
    e.min_size = size;
    e.reproducer = { case: c, expected: exp, outcomes };
  }
}
const caseStream = lines(createReadStream(casesPath));
const outStreams = Object.fromEntries(runs.map((r) => [r.name, lines(createReadStream(r.outPath))]));
for await (const line of caseStream) {
  if (!line) continue;
  const c = JSON.parse(line);
  total++;
  byOp[c.op] = (byOp[c.op] || 0) + 1;
  perFamily[c.fam] = perFamily[c.fam] || { cases: 0, divergent: 0 };
  perFamily[c.fam].cases++;
  const outcomes = {};
  for (const [name, it] of Object.entries(outStreams)) {
    const n = await it.next();
    if (n.done) throw new Error("driver output short: " + name);
    const o = JSON.parse(n.value);
    if (o.id !== c.id) throw new Error(`driver ${name} out of order at ${c.id} (got ${o.id})`);
    Object.assign(outcomes, o.r);
  }
  const exp = expected(c);
  const expS = stable(exp);
  let divergent = false;
  for (const lane of LANES) {
    if (!(lane in outcomes)) continue;
    if (lane === "go" && !goExpressible(c)) continue;
    if (stable(outcomes[lane]) === expS) continue;
    divergent = true;
    const a = shape(c.op, exp);
    const b = shape(c.op, outcomes[lane]);
    const key = `${c.op} | ${lane} | ${causeOf(c)} | oracle=${a} | ${lane}=${b}${a === b ? " | detail" : ""}`;
    addClass(key, c, outcomes, exp, { op: c.op, lane });
  }
  if (divergent) perFamily[c.fam].divergent++;
}

// ---------------------------------------------------------------- report
function readable(c) {
  if (!c) return c;
  const r = { ...c };
  for (const k of ["obj", "src"]) {
    if (r[k] === undefined) continue;
    const buf = Buffer.from(r[k], "base64");
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf);
    } catch {
      text = null;
    }
    r[k + "_text"] = text === null ? "<non-UTF-8 octets: " + buf.subarray(0, 120).toString("hex") + (buf.length > 120 ? "..." : "") + ">" : text.length > 400 ? text.slice(0, 200) + `...<${text.length} chars>...` + text.slice(-100) : text;
    delete r[k];
  }
  if (typeof r.caid === "string" && r.caid.length > 300) r.caid = r.caid.slice(0, 120) + `...<${r.caid.length} chars>`;
  return r;
}
const classList = [...classes.values()].sort((x, y) => y.count - x.count).map((e) => ({ key: e.key, count: e.count, families: e.families, example_ids: e.example_ids, reproducer: e.reproducer ? { ...e.reproducer, case: readable(e.reproducer.case) } : null }));
const rcMap = new Map();
for (const e of classList) {
  const rc = rootCauseOf(e.key) || { id: "UNCLASSIFIED", title: "no root-cause rule matches" };
  let g = rcMap.get(rc.id);
  if (!g) {
    g = { id: rc.id, title: rc.title, case_lanes: 0, classes: 0, lanes: {}, ops: {}, class_keys: [], reproducer: null };
    rcMap.set(rc.id, g);
  }
  g.case_lanes += e.count;
  g.classes++;
  const [op, lane] = e.key.split(" | ");
  g.lanes[lane] = (g.lanes[lane] || 0) + e.count;
  g.ops[op] = (g.ops[op] || 0) + e.count;
  if (g.class_keys.length < 12) g.class_keys.push(e.key);
  if (!g.reproducer) g.reproducer = { class_key: e.key, ...e.reproducer };
}
const rcList = [...rcMap.values()].sort((x, y) => x.id.localeCompare(y.id));
const version = (cmd, a) => {
  const r = spawnSync(cmd, a, { encoding: "utf8" });
  return ((r.stdout || "") + (r.stderr || "")).trim();
};
const summary = {
  root: ROOT,
  seed: SEED,
  quick: QUICK,
  cases: total,
  by_op: byOp,
  per_family: perFamily,
  root_causes: rcList.map((g) => `${g.id} (${g.case_lanes})`),
  classes: classList.length,
  divergent_case_lanes: classList.reduce((n, e) => n + e.count, 0),
  timings_ms: { ...timings, total_ms: Date.now() - t0 },
  toolchains: { node: process.version, python: version(PYTHON, ["--version"]), go: version("go", ["version"]) },
};
writeFileSync(path.join(OUT, "classes.json"), JSON.stringify(classList, null, 2));
writeFileSync(path.join(OUT, "rootcauses.json"), JSON.stringify(rcList, null, 2));
writeFileSync(path.join(OUT, "summary.json"), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));
console.log("\nROOT CAUSES (lane outcomes that differ from the spec oracle):");
for (const g of rcList) console.log(`  ${g.id.padEnd(12)} ${String(g.case_lanes).padStart(7)} case-lanes  ${JSON.stringify(g.lanes)}  ${g.title}`);
console.log(`\n(${classList.length} classes in ${path.join(OUT, "classes.json")})`);
if (CI) {
  const failing = rcList.filter((g) => !ALLOW.has(g.id));
  if (failing.length) {
    for (const g of failing) console.error(`FAIL ${g.id}: ${g.title} (${g.case_lanes} case-lanes; first class: ${g.class_keys[0]})`);
    process.exit(1);
  }
  console.log(SELFTEST ? "PASS harness self-test: the oracle-backed lanes match the oracle on every case" : "PASS every lane matches the spec oracle on every case");
}
