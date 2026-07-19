// run-vectors.mjs - runs every vector in conformance/vectors.json against
// caid.mjs. Prints pass/fail per vector and exits nonzero on any failure.
//
// Usage: node run-vectors.mjs
//
// Vector kinds:
//   compute - computeCaid(input.object, {suite: input.suite, definitions})
//   verify  - verifyCaid(input.object, input.caid, {definitions})
//   parse   - parseCaid(input.caid)
//
// Optional per-vector "relation" cross-checks:
//   same_caid_as       - actual computed caid must equal that vector's
//   different_caid_from - actual computed caid must differ from that vector's

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { computeCaid, verifyCaid, parseCaid } from "./caid.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "conformance", "vectors.json");
const suite = JSON.parse(readFileSync(vectorsPath, "utf8"));

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

let pass = 0;
let fail = 0;
const actualCaids = new Map(); // id -> caid string (successful computes only)

function report(id, ok, detail) {
  if (ok) {
    pass++;
    console.log("PASS " + id);
  } else {
    fail++;
    console.log("FAIL " + id);
    if (detail) console.log("     " + detail);
  }
}

for (const v of suite.vectors) {
  let actual;
  if (v.kind === "compute") {
    actual = computeCaid(v.input.object, {
      suite: v.input.suite,
      definitions: v.definitions,
    });
    if (actual && typeof actual.caid === "string") {
      actualCaids.set(v.id, actual.caid);
    }
  } else if (v.kind === "verify") {
    actual = verifyCaid(v.input.object, v.input.caid, {
      definitions: v.definitions,
    });
  } else if (v.kind === "parse") {
    actual = parseCaid(v.input.caid);
  } else {
    report(v.id, false, "unknown vector kind: " + v.kind);
    continue;
  }
  const ok = deepEqual(actual, v.expect);
  report(
    v.id,
    ok,
    ok
      ? null
      : "expected " + JSON.stringify(v.expect) + " got " + JSON.stringify(actual)
  );
}

// Relation cross-checks over ACTUAL computed values, not just the
// expectations written in the file.
for (const v of suite.vectors) {
  if (!v.relation) continue;
  const targetId = v.relation.same_caid_as || v.relation.different_caid_from;
  const mine = actualCaids.get(v.id);
  const theirs = actualCaids.get(targetId);
  if (mine === undefined || theirs === undefined) {
    report(v.id + " (relation)", false, "missing computed caid for relation");
    continue;
  }
  if (v.relation.same_caid_as) {
    report(
      v.id + " same_caid_as " + targetId,
      mine === theirs,
      mine === theirs ? null : mine + " != " + theirs
    );
  } else {
    report(
      v.id + " different_caid_from " + targetId,
      mine !== theirs,
      mine !== theirs ? null : "caids unexpectedly equal: " + mine
    );
  }
}

console.log("");
console.log(pass + " passed, " + fail + " failed, " + suite.vectors.length + " vectors");
process.exit(fail > 0 ? 1 : 0);
