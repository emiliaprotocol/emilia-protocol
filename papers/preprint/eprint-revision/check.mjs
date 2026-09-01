// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../..");
const sourcePath = join(here, "main.tex");
const pdfPath = join(here, "main.pdf");
const proofStatusPath = join(repo, "formal/PROOF_STATUS.md");
const receiptModelPath = join(repo, "formal/tamarin/ep_receipt_core.spthy");
const quorumModelPath = join(repo, "formal/tamarin/ep_quorum_core.spthy");
const verificationPath = join(here, "VERIFICATION.md");
const readmePath = join(here, "README.md");
const submissionPath = join(here, "IACR-SUBMISSION.md");
const zenodoPath = join(here, "ZENODO.md");
const composedSummaryPath = join(repo, "formal/tamarin/results/ep_reliance_composed.summary.txt");
const deliveryPath = join(repo, "output/pdf/authorization-non-amplification-v4.pdf");

const [
  source,
  proofStatus,
  receiptModel,
  quorumModel,
  verification,
  readme,
  submission,
  zenodo,
  composedSummary,
  pdfBytes,
] = await Promise.all([
  readFile(sourcePath, "utf8"),
  readFile(proofStatusPath, "utf8"),
  readFile(receiptModelPath, "utf8"),
  readFile(quorumModelPath, "utf8"),
  readFile(verificationPath, "utf8"),
  readFile(readmePath, "utf8"),
  readFile(submissionPath, "utf8"),
  readFile(zenodoPath, "utf8"),
  readFile(composedSummaryPath, "utf8"),
  readFile(pdfPath),
]);

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const pdfDigest = digest(pdfBytes);
assert(
  [verification, readme, submission, zenodo].every((text) => text.includes(pdfDigest)),
  `PDF digest ${pdfDigest} is not pinned in every publication record`,
);
assert.equal(pdfBytes.length, 152612, "main.pdf byte count drifted");
for (const record of [verification, readme, submission, zenodo]) {
  assert(record.includes("152,612"), "publication record is missing the final PDF byte count");
}

const deliveryBytes = await readFile(deliveryPath).catch((error) => {
  if (error?.code === "ENOENT") return null;
  throw error;
});
if (deliveryBytes) {
  assert.equal(digest(deliveryBytes), pdfDigest, "local delivery PDF differs from main.pdf");
}

const sourceArtifacts = [
  "formal/tamarin/ep_receipt_core.spthy",
  "formal/tamarin/ep_quorum_core.spthy",
  "formal/tamarin/ep_reliance_composed.spthy",
  "formal/tamarin/ep_six_claim_composed.spthy",
  "formal/tamarin/run-receipt-core.sh",
  "formal/tamarin/run-quorum.sh",
  "formal/tamarin/run-composed.sh",
];

for (const relative of sourceArtifacts) {
  const artifactDigest = digest(await readFile(join(repo, relative)));
  assert(
    verification.includes(`| \`${relative}\` | \`${artifactDigest}\` |`),
    `VERIFICATION.md does not pin the current digest for ${relative}: ${artifactDigest}`,
  );
}

const requiredSource = [
  "Authorization Non-Amplification",
  "Chosen-Context Signer Harvesting",
  "Stateless replay impossibility",
  "\\begin{definition}[Authorization non-amplification]",
  "\\begin{lemma}[Functional completeness]",
  "\\begin{theorem}[ANA compiler]",
  "\\mathsf{RegistryBreak}",
  "\\mathsf{MediationBreak}",
  "\\mathsf{Exp}^{\\ANA,\\mathrm{real}}",
  "Signer-to-collector injective agreement does not imply ANA",
  "ANA does not imply agreement among approvers",
  "\\mathsf{Cert}",
  "\\mathsf{Aud}",
  "per-issued-instance",
  "semantic replay",
  "It does not authorize a blind retry",
  "Anonymous Counting Tokens",
  "Multi-Signatures in the Plain Public-Key Model",
  "Object Capabilities and Isolation of Untrusted Web Applications",
  "source-authority non-amplification",
  "ep_receipt_core.spthy",
  "ep_quorum_core.spthy",
  "The TAMARIN Prover for the Symbolic Analysis of Security Protocols",
  "10.5281/zenodo.21968577",
];

for (const text of requiredSource) {
  assert(source.includes(text), `main.tex is missing required text: ${text}`);
}

const forbiddenSource = [
  "\\begin{definition}[Transplantation]",
  "\\begin{theorem}[ABIA composition]",
  "AtomicityFail",
  "MediationBypass",
  "one approval ceremony",
  "fresh slot nonce",
  "Injective agreement and ANA are incomparable",
  "The witness clause is stronger than replay prevention",
  "exactly-once physical execution is guaranteed",
  "IETF-adopted",
  "awaiting editor review",
];

for (const text of forbiddenSource) {
  assert(!source.includes(text), `main.tex contains forbidden text: ${text}`);
}

const proofClaims = [
  ["executable_honest_receipt: verified (9 steps)", "executable_honest_receipt (exists-trace): verified (9 steps)"],
  ["core_authenticity_uv_gated: verified (11 steps)", "core_authenticity_uv_gated (all-traces): verified (11 steps)"],
  ["acceptance_prefix_integrity_after_later_reveal: verified (12 steps)", "acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)"],
  ["no_replay_across_actions: verified (11 steps)", "no_replay_across_actions (all-traces): verified (11 steps)"],
  ["injective_acceptance_with_consumption: verified (11 steps)", "injective_acceptance_with_consumption (all-traces): verified (11 steps)"],
  ["unchecked_acceptance_is_injective: falsified (11 steps)", "unchecked_acceptance_is_injective (all-traces): falsified"],
  ["executable_quorum: verified (13 steps)", "executable_quorum (exists-trace): verified (13 steps)"],
  ["quorum_requires_two_distinct_uv_gated_signatures: verified (27 steps)", "quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)"],
  ["initiator_cannot_self_approve: verified (4 steps)", "initiator_cannot_self_approve (all-traces): verified (4 steps)"],
  ["no_single_signer_fills_quorum: verified (4 steps)", "no_single_signer_fills_quorum (all-traces): verified (4 steps)"],
  ["commit_requires_signature_over_that_action: verified (8 steps)", "commit_requires_signature_over_that_action (all-traces): verified (8 steps)"],
];

for (const [paperClaim, statusClaim] of proofClaims) {
  assert(source.includes(paperClaim), `main.tex is missing proof claim: ${paperClaim}`);
  assert(proofStatus.includes(statusClaim), `formal/PROOF_STATUS.md does not support: ${statusClaim}`);
}

const composedClaims = [
  "executable_composed_reliance (exists-trace): verified (20 steps)",
  "execution_requires_full_composition (all-traces): verified (101 steps)",
  "caid_binds_family_and_material (all-traces): verified (2 steps)",
  "initiator_cannot_self_approve (all-traces): verified (4 steps)",
  "no_single_signer_fills_quorum (all-traces): verified (2 steps)",
  "no_issuer_laundering (all-traces): verified (785 steps)",
  "strict_registry_view_is_exact (all-traces): verified (25 steps)",
  "no_cross_action_profile_or_audience_replay (all-traces): verified (41 steps)",
  "execution_has_honest_approvals_or_prior_compromise (all-traces): verified (178 steps)",
  "injective_execution_with_consumption (all-traces): verified (250 steps)",
  "unchecked_composition_is_injective (all-traces): falsified - found trace (31 steps)",
  "unchecked_registry_view_is_current (all-traces): falsified - found trace (20 steps)",
  "executable_six_claim_composition (exists-trace): verified (11 steps)",
  "signed_denial_remains_verifiable_evidence (exists-trace): verified (8 steps)",
  "class_a_downgrade_refused (all-traces): verified (22 steps)",
  "signed_denial_cannot_authorize (all-traces): verified (2 steps)",
  "scoped_authority_is_pinned (all-traces): verified (49 steps)",
  "reliance_requires_pinned_profile (all-traces): verified (12 steps)",
  "evidence_challenge_is_registered_and_consumed (all-traces): verified (41 steps)",
  "fresh_challenge_registration_is_unique (all-traces): verified (2 steps)",
  "aec_execution_is_action_keyed_and_fleet_fail_closed (all-traces): verified (13 steps)",
  "action_reservation_failure_is_fail_closed (all-traces): verified (3 steps)",
  "unchecked_presenter_class_is_pinned (all-traces): falsified - found trace (14 steps)",
  "unchecked_signed_denial_cannot_authorize (all-traces): falsified - found trace (14 steps)",
  "unchecked_authority_scope_is_pinned (all-traces): falsified - found trace (16 steps)",
  "unchecked_reliance_profile_is_pinned (all-traces): falsified - found trace (14 steps)",
  "unchecked_unregistered_challenge_is_registered (all-traces): falsified - found trace (14 steps)",
  "unchecked_presenter_execution_key_is_canonical (all-traces): falsified - found trace (14 steps)",
];

for (const claim of composedClaims) {
  assert(composedSummary.includes(claim), `composed proof summary is missing: ${claim}`);
}

for (const lemma of [
  "executable_honest_receipt",
  "core_authenticity_uv_gated",
  "acceptance_prefix_integrity_after_later_reveal",
  "no_replay_across_actions",
  "injective_acceptance_with_consumption",
  "unchecked_acceptance_is_injective",
]) {
  assert(receiptModel.includes(`lemma ${lemma}:`), `receipt model is missing ${lemma}`);
}

for (const lemma of [
  "executable_quorum",
  "quorum_requires_two_distinct_uv_gated_signatures",
  "initiator_cannot_self_approve",
  "no_single_signer_fills_quorum",
  "commit_requires_signature_over_that_action",
]) {
  assert(quorumModel.includes(`lemma ${lemma}:`), `quorum model is missing ${lemma}`);
}

for (const text of [
  "Authorization Non-Amplification under Chosen-Context Signer Harvesting",
  "The IACR Cryptology ePrint Archive is no longer a distribution target for this paper",
  "No further ePrint submission will be made under any title",
  "`xxxx/111420`",
  "Contribution to cryptology",
]) {
  assert(submission.includes(text), `IACR-SUBMISSION.md is missing required text: ${text}`);
}

const pdfText = execFileSync("pdftotext", [pdfPath, "-"], { encoding: "utf8" });
const pdfInfo = execFileSync("pdfinfo", [pdfPath], { encoding: "utf8" });
assert(/^Pages:\s+15$/m.test(pdfInfo), "main.pdf page count drifted");
const normalizedPdfText = pdfText
  .replaceAll("ﬁ", "fi")
  .replaceAll("ﬀ", "ff")
  .replaceAll("ﬂ", "fl")
  .replace(/\s+/g, " ");
for (const text of [
  "Authorization Non-Amplification",
  "Authorization non-amplification",
  "ANA compiler",
  "Functional completeness",
  "Deployment composition",
  "Anonymous Counting Tokens",
  "does not claim exactly-once physical execution",
  "Artifact Availability",
]) {
  assert(normalizedPdfText.includes(text), `main.pdf is missing required text: ${text}`);
}

console.log("Focused ANA v4 manuscript and artifact checks passed.");
