// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildReferenceReport, PROFILE, runProfile } from "./run.mjs";
import {
  assertAicInspectionBoundary,
  assertAicRawRepositoryFileUrl,
} from "./verify-source-lock.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_LOCK = JSON.parse(
  readFileSync(resolve(HERE, "source-lock.json"), "utf8"),
);

test("current AIC inspected-file URLs bind the declared repositories, revisions, and paths", () => {
  let inspectedFileCount = 0;
  for (const repository of SOURCE_LOCK.varwof.repositories) {
    for (const inspectedFile of repository.inspected_files) {
      assertAicRawRepositoryFileUrl(
        repository.repository,
        repository.revision,
        inspectedFile.path,
        inspectedFile.url,
      );
      inspectedFileCount += 1;
    }
  }
  assert.equal(inspectedFileCount, 9);
});

test("AIC source-lock validation rejects a raw URL with a different revision", () => {
  const repository = SOURCE_LOCK.varwof.repositories[0];
  const inspectedFile = repository.inspected_files[0];
  const differentRevision = repository.revision === "0".repeat(40)
    ? "1".repeat(40)
    : "0".repeat(40);
  const mismatchedUrl = inspectedFile.url.replace(
    `/${repository.revision}/`,
    `/${differentRevision}/`,
  );
  assert.throws(
    () => assertAicRawRepositoryFileUrl(
      repository.repository,
      repository.revision,
      inspectedFile.path,
      mismatchedUrl,
    ),
    /does not match declared repository, revision, and path/,
  );
});

test("AIC source-lock validation rejects a raw URL with a different path", () => {
  const repository = SOURCE_LOCK.varwof.repositories[0];
  const inspectedFile = repository.inspected_files[0];
  assert.throws(
    () => assertAicRawRepositoryFileUrl(
      repository.repository,
      repository.revision,
      inspectedFile.path,
      `${inspectedFile.url}.different`,
    ),
    /does not match declared repository, revision, and path/,
  );
});

test("AIC source lock keeps carrier provenance and upstream wiring limits fail closed", () => {
  assert.doesNotThrow(() => assertAicInspectionBoundary(SOURCE_LOCK));
  const relabeled = structuredClone(SOURCE_LOCK);
  relabeled.inspection.gateway_bearer_bridge
    .synthesized_certificate_admissible_to_native_x509_mapping = true;
  assert.throws(
    () => assertAicInspectionBoundary(relabeled),
    /inspection fact changed/,
  );
  const wired = structuredClone(SOURCE_LOCK);
  wired.inspection.upstream_wiring.deployed_wiring_verified = true;
  assert.throws(
    () => assertAicInspectionBoundary(wired),
    /upstream wiring boundary changed/,
  );
  const widenedSpki = structuredClone(SOURCE_LOCK);
  widenedSpki.inspection.native_x509_bundle.principal_spki_hash_algorithm = "sha-512";
  assert.throws(
    () => assertAicInspectionBoundary(widenedSpki),
    /SPKI algorithm changed/,
  );
});

test("all AIC crossing cases pass and match the committed deterministic report", async () => {
  const report = await runProfile();
  const reference = JSON.parse(
    readFileSync(resolve(HERE, "report.reference.json"), "utf8"),
  );
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 19);
  assert.equal(report.results_digest, reference.results_digest);
  assert.deepEqual(await buildReferenceReport(), reference);
});

test("pure JSON jkt and X.509 SPKI stay separate while both produce non-authorizing receipts", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId["AIC-JWT-JKT-CROSSING"].passed, true);
  assert.equal(byId["AIC-X509-SPKI-CROSSING"].passed, true);
  assert.equal(byId["NATIVE-BINDINGS-REMAIN-DISTINCT"].passed, true);
  assert.equal(byId["X509-DER-REPLAY-IDENTITY-STABLE"].passed, true);
  assert.equal(byId["SYNTHESIZED-X509-CARRIER-CONFUSION-REFUSED"].passed, true);
  assert.equal(
    byId["SYNTHESIZED-X509-CARRIER-CONFUSION-REFUSED"].observed.x509_path_reason,
    "aic_carrier_provenance_unverifiable",
  );
  assert.match(report.known_limits.join(" "), /never treated as interchangeable/);
  assert.match(report.known_limits.join(" "), /requires the original compact token/);
  assert.match(report.known_limits.join(" "), /tagged or authenticated verifier-result wrapper/);
  assert.match(report.known_limits.join(" "), /never authorizes another action/);
});

test("hostile native inputs fail before a crossing authority is emitted", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  for (const id of [
    "PRINCIPAL-BINDING-MISMATCH",
    "RP-POLICY-SELF-PIN-REFUSED",
    "NATIVE-TYPE-CONFUSION",
    "SYNTHESIZED-X509-CARRIER-CONFUSION-REFUSED",
    "NATIVE-VERIFICATION-REFUSAL",
    "REQUEST-CAPABILITY-SUBSTITUTION-REFUSED",
    "JWT-AUDIENCE-SUBSTITUTION-REFUSED",
    "JWT-TEMPORAL-RELABELING-REFUSED",
  ]) assert.equal(byId[id].passed, true, id);
  assert.deepEqual(byId["RP-POLICY-SELF-PIN-REFUSED"].observed, {
    self_pin: "mapping_input_invalid",
    untrusted: "aic_issuer_untrusted",
  });
  assert.match(
    report.known_limits.join(" "),
    /native verifier result and relying-party policy are structurally separate/,
  );
});

test("exact action, admission domain, and source-status substitutions all refuse", async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  for (const id of [
    "EXACT-ACTION-SUBSTITUTION-REFUSED",
    "RELYING-PARTY-DOMAIN-SUBSTITUTION-REFUSED",
    "STATUS-OBSERVATION-TIME-REFUSALS",
    "STATUS-FRESHNESS-PROFILE-WIDENING-REFUSED",
    "NON-CURRENT-SOURCE-STATUS-REFUSED",
    "NATIVE-VALIDITY-WINDOW-REFUSED",
    "SIGNED-CROSSING-RP-SUBSTITUTION-REFUSED",
  ]) assert.equal(byId[id].passed, true, id);
  assert.match(report.known_limits.join(" "), /binds one exact action/);
  assert.match(report.known_limits.join(" "), /explicit source-status observation time/);
  assert.match(report.known_limits.join(" "), /exactly a 60-second maximum age/);
});

test("the report carries exact source revisions and calls an external run a reproduction", async () => {
  const report = await runProfile({
    name: "External operator",
    affiliation: "Example project",
    revision: "example-commit",
    executed_at: "2026-08-26T20:00:00Z",
  });
  assert.equal(report.source_lock.varwof.repositories.length, 4);
  assert.equal(report.source_lock.drafts.length, 2);
  assert.equal(
    report.source_lock.inspection.gateway_bearer_bridge
      .non_test_verify_bearer_call_sites_observed,
    false,
  );
  assert.equal(
    report.source_lock.inspection.upstream_wiring
      .cross_process_authenticated_provenance_wrapper_required,
    true,
  );
  assert.equal(report.native_verification_fixture.execution, "STIPULATED_NOT_EXECUTED");
  assert.equal(report.native_verification_fixture.upstream_native_acceptance_claimed, false);
  assert.match(report.known_limits.join(" "), /does not claim the pinned upstream verifiers accepted/);
  assert.match(report.reproduction_statement, /19\/19/);
  assert.match(report.reproduction_statement, /not independent AIC interoperability/);
});
