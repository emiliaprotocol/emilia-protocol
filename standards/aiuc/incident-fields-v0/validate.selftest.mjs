// node:test suite for validate.mjs. Zero dependencies.
// Run: node --test validate.selftest.mjs   (from this directory or by path)

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const validator = join(here, "validate.mjs");

function run(file, extraArgs = []) {
  const res = spawnSync(process.execPath, [validator, file, ...extraArgs], {
    cwd: here,
    encoding: "buffer",
  });
  return { status: res.status, stdout: res.stdout, text: res.stdout.toString("utf8") };
}

function failLines(text) {
  return text.split("\n").filter((l) => l.startsWith("CHECK ") && l.includes(" FAIL "));
}

test("positive example passes every check with exit 0", () => {
  const r = run("example-aiid-1152.json");
  assert.equal(r.status, 0);
  assert.ok(r.text.includes("RESULT PASS"));
  assert.equal(failLines(r.text).length, 0);
});

// Each hostile vector must fail with exactly its specific named reason.
const hostileCases = [
  {
    file: "vectors/unknown-status-code.json",
    expect: "CHECK authorization-status-code FAIL unknown-authorization-status: AS-2",
  },
  {
    file: "vectors/missing-evidence-grade.json",
    expect: "CHECK required-fields FAIL missing-required-field: authorization.evidence_grade",
  },
  {
    file: "vectors/e0-grade-with-determinate-status.json",
    expect: "CHECK e0-requires-indeterminate FAIL e0-grade-with-non-indeterminate-status: revoked",
  },
  {
    file: "vectors/missing-reasoning-trail.json",
    expect: "CHECK basis-summary-required FAIL missing-basis-summary-for-status: revoked",
  },
  {
    file: "vectors/unknown-field.json",
    expect: "CHECK unknown-fields FAIL unknown-field: liability_assessment",
  },
  {
    file: "vectors/malformed.json",
    expect: "CHECK json-well-formed FAIL malformed-json",
  },
  {
    file: "vectors/timing-after-attempt.json",
    expect:
      "CHECK timing-cross-rule FAIL decision-timing-must-be-before-attempt: specific_approval/after_attempt",
  },
  {
    file: "vectors/dangling-evidence-ref.json",
    expect: "CHECK evidence-refs-resolve FAIL unresolved-evidence-ref: authorization/S9",
  },
];

for (const c of hostileCases) {
  test(`${c.file} fails with its specific named reason only`, () => {
    const r = run(c.file);
    assert.equal(r.status, 1, "hostile vector must exit 1");
    const fails = failLines(r.text);
    assert.deepEqual(fails, [c.expect], "exactly one named failure expected");
    assert.ok(r.text.includes("RESULT FAIL"));
  });
}

test("--report output is byte-identical across runs (positive example)", () => {
  const a = run("example-aiid-1152.json", ["--report"]);
  const b = run("example-aiid-1152.json", ["--report"]);
  assert.equal(a.status, 0);
  assert.equal(b.status, 0);
  assert.ok(a.stdout.equals(b.stdout), "two --report runs must be byte-identical");
});

test("--report output is byte-identical across runs (hostile vector)", () => {
  const a = run("vectors/unknown-status-code.json", ["--report"]);
  const b = run("vectors/unknown-status-code.json", ["--report"]);
  assert.equal(a.status, 1);
  assert.equal(b.status, 1);
  assert.ok(a.stdout.equals(b.stdout), "two --report runs must be byte-identical");
});

test("--report output matches default output byte for byte", () => {
  const a = run("example-aiid-1152.json");
  const b = run("example-aiid-1152.json", ["--report"]);
  assert.ok(a.stdout.equals(b.stdout));
});

test("report contains no timestamps or volatile content", () => {
  const r = run("example-aiid-1152.json", ["--report"]);
  // No ISO datetime stamps (calendar dates inside coded data are allowed but
  // none appear in report lines for a passing run).
  assert.ok(!/\d{2}:\d{2}:\d{2}/.test(r.text), "report must not contain times");
});

test("unreadable file exits 1 with a named failure", () => {
  const r = run("vectors/does-not-exist.json");
  assert.equal(r.status, 1);
  assert.ok(r.text.includes("CHECK file-readable FAIL unreadable-file"));
});
