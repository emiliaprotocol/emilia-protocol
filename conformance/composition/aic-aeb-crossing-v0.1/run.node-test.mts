// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildReferenceReport, PROFILE, runProfile } from "./run.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

test("all AIC crossing cases pass and match the committed deterministic report", async () => {
  const report = await runProfile();
  const reference = JSON.parse(
    readFileSync(resolve(HERE, "report.reference.json"), "utf8"),
  );
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 10);
  assert.equal(report.results_digest, reference.results_digest);
  assert.deepEqual(await buildReferenceReport(), reference);
});

test("pure JSON jkt and X.509 SPKI stay separate while both produce non-authorizing receipts", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId["AIC-JWT-JKT-CROSSING"].passed, true);
  assert.equal(byId["AIC-X509-SPKI-CROSSING"].passed, true);
  assert.equal(byId["NATIVE-BINDINGS-REMAIN-DISTINCT"].passed, true);
  assert.match(report.known_limits.join(" "), /never treated as interchangeable/);
  assert.match(report.known_limits.join(" "), /never authorizes another action/);
});

test("hostile native inputs fail before a crossing authority is emitted", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  for (const id of [
    "PRINCIPAL-BINDING-MISMATCH",
    "UNTRUSTED-ISSUER",
    "NATIVE-TYPE-CONFUSION",
    "NATIVE-VERIFICATION-REFUSAL",
  ]) assert.equal(byId[id].passed, true, id);
});

test("strict JWT-SVID projection changes typ only by requiring a new signature and rejects lost authority semantics", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId["STRICT-JWT-SVID-PROJECTION"].passed, true);
  assert.equal(byId["JWT-SVID-MULTIPLE-AUDIENCE-REFUSED"].passed, true);
  assert.equal(byId["JWT-SVID-AUTHORITY-SEMANTIC-LOSS"].passed, true);
  assert.match(report.known_limits.join(" "), /unsigned typ=JWT projection/);
  assert.match(report.known_limits.join(" "), /does not preserve AIC authority/);
});

test("the report carries exact source revisions and calls an external run a reproduction", async () => {
  const report = await runProfile({
    name: "External operator",
    affiliation: "Example project",
    revision: "example-commit",
    executed_at: "2026-08-26T20:00:00Z",
  });
  assert.equal(report.source_lock.varwof.repositories.length, 3);
  assert.equal(report.source_lock.drafts.length, 2);
  assert.match(report.reproduction_statement, /10\/10/);
  assert.match(report.reproduction_statement, /not independent AIC or JWT-SVID interoperability/);
});
