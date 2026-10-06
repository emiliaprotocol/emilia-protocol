#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sourcePath = resolve(
  here,
  "../NEXT-WIMSE-CAID-SCOPE-01/vectors.json",
);
const outputPath = join(here, "vectors.json");

function cloneWithCurrentScheme(value) {
  if (Array.isArray(value)) return value.map(cloneWithCurrentScheme);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, member]) => [
        key,
        cloneWithCurrentScheme(member),
      ]),
    );
  }
  if (typeof value === "string" && value.startsWith("caid:1:")) {
    return `canactid:${value.slice("caid:".length)}`;
  }
  return value;
}

/**
 * Derive the successor corpus without rewriting the frozen version 01
 * evidence. The material action objects and their digests remain unchanged;
 * only the draft-05 scheme changes for current identifiers. The added hostile
 * vector preserves one structurally valid legacy value to prove that this
 * profile refuses rather than silently rewriting it.
 *
 * @param {Record<string, any>} sourceSuite
 */
export function generateVectorSuite(sourceSuite) {
  const suite = cloneWithCurrentScheme(sourceSuite);
  suite.suite = "WIMSE-CAID-SCOPE-02-vectors";
  suite.version = 3;
  suite.note =
    "COVERED is operation-family plus exact-action correlation under pinned inputs. It is not authorization or execution. Current identifiers use canactid:; legacy caid: is refused without rewrite.";

  const sourcePayment = sourceSuite.vectors?.find(
    (vector) => vector.id === "payment-literal-covered",
  );
  const currentPayment = suite.vectors?.find(
    (vector) => vector.id === "payment-literal-covered",
  );
  if (!sourcePayment || !currentPayment) {
    throw new Error("version 01 source lacks payment-literal-covered");
  }
  if (typeof sourcePayment.input?.presented_caid !== "string" ||
      !sourcePayment.input.presented_caid.startsWith("caid:1:")) {
    throw new Error("version 01 payment vector does not carry a legacy caid: value");
  }
  if (typeof currentPayment.input?.presented_caid !== "string" ||
      !currentPayment.input.presented_caid.startsWith("canactid:1:")) {
    throw new Error("scheme migration did not produce a current canactid: value");
  }

  const legacyVector = {
    id: "legacy-caid-scheme-refused",
    description:
      "A structurally valid draft-04 caid: value is an obsolete identifier, not a current canactid: value; this profile refuses it without prefix rewriting.",
    input: {
      ...structuredClone(currentPayment.input),
      presented_caid: sourcePayment.input.presented_caid,
    },
    expect: {
      decision: "REFUSED",
      reason: "legacy_caid_scheme",
    },
  };

  const insertionPoint = suite.vectors.findIndex(
    (vector) => vector.id === "tool-call-literal-covered",
  );
  if (insertionPoint < 0) {
    throw new Error("version 01 source lacks tool-call-literal-covered");
  }
  suite.vectors.splice(insertionPoint, 0, legacyVector);
  return suite;
}

function render() {
  const sourceSuite = JSON.parse(readFileSync(sourcePath, "utf8"));
  return `${JSON.stringify(generateVectorSuite(sourceSuite), null, 2)}\n`;
}

function main() {
  const mode = process.argv[2] ?? "--check";
  const expected = render();
  if (mode === "--write") {
    writeFileSync(outputPath, expected);
    console.log(`WROTE ${outputPath}`);
    return;
  }
  if (mode !== "--check") {
    console.error("usage: generate-vectors.mjs [--check|--write]");
    process.exitCode = 2;
    return;
  }
  let actual;
  try {
    actual = readFileSync(outputPath, "utf8");
  } catch {
    console.error(`FAIL missing generated vector file ${outputPath}`);
    process.exitCode = 1;
    return;
  }
  if (actual !== expected) {
    console.error(
      "FAIL vectors.json is stale; run generate-vectors.mjs --write",
    );
    process.exitCode = 1;
    return;
  }
  const suite = JSON.parse(actual);
  console.log(`PASS generated vectors (${suite.vectors.length} cases)`);
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main();
}
