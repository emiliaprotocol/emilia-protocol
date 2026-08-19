// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildReferenceReport, PROFILE, runProfile } from "./run.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

test("all carrier-neutral crossing-record cases pass and match the committed digest", async () => {
  const report = await runProfile();
  const reference = JSON.parse(
    readFileSync(resolve(HERE, "report.reference.json"), "utf8"),
  );
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 15);
  assert.equal(report.results_digest, reference.results_digest);
  assert.deepEqual(await buildReferenceReport(), reference);
});

test("the kit keeps native formats separate while one verifier evaluates the record contract", async () => {
  const report = await runProfile();
  const ids = new Set(report.cases.map((entry) => entry.id));
  for (const id of [
    "MAPPING-WIMSE-OAUTH",
    "MAPPING-BCR",
    "OPEN-SET-SHARED-CONTRACT",
    "ONE-VERIFIER-MULTIPLE-NATIVE-SYSTEMS",
  ])
    assert.equal(ids.has(id), true, id);
  assert.match(
    report.known_limits.join(" "),
    /do not claim native semantic equivalence/,
  );
});

test("the record cannot become a carrier or a fresh authorization grant", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(
    report.cases.map((entry) => [entry.id, entry]),
  );
  assert.equal(byId["CARRIER-INJECTION-REFUSED"].passed, true);
  assert.equal(byId["MISSING-ADMISSION-IS-NONAUTHORIZING"].passed, true);
  assert.equal(byId["LOCAL-BROADENING-REFUSED"].passed, true);
  assert.match(
    report.known_limits.join(" "),
    /never authorizes another action/,
  );
});

test("an external execution self-describes as reproduction, not independent implementation", async () => {
  const report = await runProfile({
    name: "External operator",
    affiliation: "Example project",
    revision: "example-commit",
    executed_at: "2026-08-19T06:00:00Z",
  });
  assert.match(report.reproduction_statement, /15\/15/);
  assert.match(
    report.reproduction_statement,
    /not an independent implementation/,
  );
});
