// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../..");
const sourcePath = join(here, "main.tex");
const pdfPath = join(here, "main.pdf");
const deliveryPath = join(repo, "output/pdf/authorization-non-amplification-v5.pdf");
const verificationPath = join(here, "VERIFICATION.md");
const readmePath = join(here, "README.md");
const submissionPath = join(here, "IACR-SUBMISSION.md");
const zenodoPath = join(here, "ZENODO.md");
const proofStatusPath = join(repo, "formal/PROOF_STATUS.md");
const receiptModelPath = join(repo, "formal/tamarin/ep_receipt_core.spthy");
const quorumModelPath = join(repo, "formal/tamarin/ep_quorum_core.spthy");
const composedSummaryPath = join(repo, "formal/tamarin/results/ep_reliance_composed.summary.txt");

const [
  source,
  pdfBytes,
  verification,
  readme,
  submission,
  zenodo,
  proofStatus,
  receiptModel,
  quorumModel,
  composedSummary,
  deliveryBytes,
] = await Promise.all([
  readFile(sourcePath, "utf8"),
  readFile(pdfPath),
  readFile(verificationPath, "utf8"),
  readFile(readmePath, "utf8"),
  readFile(submissionPath, "utf8"),
  readFile(zenodoPath, "utf8"),
  readFile(proofStatusPath, "utf8"),
  readFile(receiptModelPath, "utf8"),
  readFile(quorumModelPath, "utf8"),
  readFile(composedSummaryPath, "utf8"),
  readFile(deliveryPath),
]);

const digest = (value) => createHash("sha256").update(value).digest("hex");
const pdfDigest = digest(pdfBytes);
const sourceDigest = digest(source);
const records = [verification, readme, submission, zenodo];

assert.equal(pdfBytes.length, 173254, "main.pdf byte count drifted");
assert.equal(pdfDigest, "1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b");
assert.equal(digest(deliveryBytes), pdfDigest, "delivery PDF differs from main.pdf");
assert.equal(sourceDigest, "ebc93f0a57af389c2b9eefaa910a74ed82c50f13ae3f3d80ec8eeb313d592864");
assert(verification.includes(sourceDigest), "verification receipt does not pin main.tex");
for (const record of records) {
  assert(record.includes(pdfDigest), "publication record does not pin final PDF digest");
  assert(record.includes("173,254"), "publication record does not pin final PDF bytes");
  assert(record.includes("19"), "publication record does not pin final page count");
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
    `VERIFICATION.md does not pin ${relative}: ${artifactDigest}`,
  );
}

const requiredSource = [
  "Per-Issuance Authorization Non-Amplification",
  "under Chosen-Context Signature Collection",
  "\\begin{definition}[Authorization non-amplification]",
  "\\begin{lemma}[Functional completeness conditioned on correctness]",
  "\\begin{theorem}[Exact-witness authenticity with ideal resources]",
  "\\begin{lemma}[Ideal non-amplification]",
  "\\begin{corollary}[Per-issuance ANA composition]",
  "\\mathsf{KeyCollision}",
  "\\mathsf{ValidatedIssueInput}(d,u,c,a)",
  "\\mathsf{ValidatedEntryInput}(d,u,a,c,S,\\tau)",
  "\\Entry(d,u,h,\\tau,a,c,S)",
  "u=H(\\Enc(\\code{ANA-ADMIT-v1},c))",
  "Enrolled ANA keys are purpose-separated",
  "Signer-to-collector injective agreement does not imply ANA",
  "ANA does not imply agreement among approvers",
  "It does not authorize a blind retry",
  "\\mathsf{RegistryBreak}",
  "\\mathsf{MediationBreak}",
  "ep_receipt_core.spthy",
  "ep_quorum_core.spthy",
  "10.5281/zenodo.21968577",
];
for (const text of requiredSource) {
  assert(source.includes(text), `main.tex is missing required text: ${text}`);
}
assert(/including byte-identical\s+duplicates/.test(source),
  "main.tex is missing the byte-identical duplicate-issuance condition");
assert(/exactly one matching\s+\$\\mathsf\{Consumed\}\(d,u,c,\\tau\)\$ event/.test(source),
  "main.tex is missing the atomic matching Consumed-event condition");

const forbiddenSource = [
  "Authorization Non-Amplification under Chosen-Context Signer Harvesting",
  "ANA compiler",
  "key generation is repeated",
  "ValidatedEntryInput(d,u,c,S",
  "F_MED.Enter(d,u,c,S",
  "The v5 source and PDF are released with this preprint",
  "exactly-once physical execution is guaranteed",
  "IETF-adopted",
  "awaiting editor review",
];
for (const text of forbiddenSource) {
  assert(!source.includes(text), `main.tex contains forbidden text: ${text}`);
}

const issueValidation = source.indexOf("emit ValidatedIssueInput(d,u,c,a)");
const exactIssue = source.indexOf("reject unless F_IC.IssueExact(d,u,c,a) = true");
assert(issueValidation >= 0 && issueValidation < exactIssue, "issue input is not validated before atomic issue");
const consume = source.indexOf("tau <- F_IC.ConsumeExact(d,u,c)");
const entryValidation = source.indexOf("emit ValidatedEntryInput(d,u,a,c,S,tau)");
const mediatedEntry = source.indexOf("return F_MED.Enter(d,u,a,c,S,tau)");
assert(consume >= 0 && consume < entryValidation && entryValidation < mediatedEntry,
  "admission ordering is not consume -> validated input -> mediated entry");

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
  assert(proofStatus.includes(statusClaim), `formal proof status does not support: ${statusClaim}`);
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

for (const claim of [
  "execution_requires_full_composition (all-traces): verified (101 steps)",
  "no_issuer_laundering (all-traces): verified (785 steps)",
  "injective_execution_with_consumption (all-traces): verified (250 steps)",
  "unchecked_composition_is_injective (all-traces): falsified - found trace (31 steps)",
  "unchecked_registry_view_is_current (all-traces): falsified - found trace (20 steps)",
]) {
  assert(composedSummary.includes(claim), `composed proof summary is missing: ${claim}`);
}

for (const text of [
  "IACR ePrint submission packet: v5",
  "Per-Issuance Authorization Non-Amplification under Chosen-Context Signature Collection",
  "Prepared for a new Cryptology ePrint Archive submission. Not yet submitted.",
  "Creative Commons Attribution 4.0 International",
  "Contribution to cryptology",
  "xxxx/111404",
]) {
  assert(submission.includes(text), `IACR-SUBMISSION.md is missing: ${text}`);
}

for (const record of [readme, verification, submission, zenodo]) {
  assert(!record.includes("authorization-non-amplification-v4.pdf"), "publication packet still names v4 PDF");
  assert(!record.includes("152,612"), "publication packet still contains v4 byte count");
  assert(!record.includes("3f86f29129f0ed4b1b2d502b7b9a6e62a7a311b022d19ea3eed9e3462992990d"),
    "publication packet still contains v4 PDF digest");
}

const pdfText = execFileSync("pdftotext", [pdfPath, "-"], { encoding: "utf8" });
const pdfInfo = execFileSync("pdfinfo", [pdfPath], { encoding: "utf8" });
assert(/^Pages:\s+19$/m.test(pdfInfo), "main.pdf page count drifted");
const normalizedPdfText = pdfText
  .replaceAll("ﬁ", "fi")
  .replaceAll("ﬀ", "ff")
  .replaceAll("ﬂ", "fl")
  .replace(/\s+/g, " ");
for (const text of [
  "Per-Issuance Authorization Non-Amplification",
  "Functional completeness conditioned on correctness",
  "Exact-witness authenticity with ideal resources",
  "Per-issuance ANA composition",
  "KeyCollision",
  "including byte-identical duplicates",
  "does not claim exactly-once physical execution",
  "Artifact Availability",
]) {
  assert(normalizedPdfText.includes(text), `main.pdf is missing required text: ${text}`);
}

console.log("Focused ANA v5 manuscript and artifact checks passed.");
