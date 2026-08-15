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

const [source, proofStatus, receiptModel, quorumModel, verification, readme, pdfBytes] = await Promise.all([
  readFile(sourcePath, "utf8"),
  readFile(proofStatusPath, "utf8"),
  readFile(receiptModelPath, "utf8"),
  readFile(quorumModelPath, "utf8"),
  readFile(verificationPath, "utf8"),
  readFile(readmePath, "utf8"),
  readFile(pdfPath),
]);

const pdfDigest = createHash("sha256").update(pdfBytes).digest("hex");
assert(
  verification.includes(pdfDigest) && readme.includes(pdfDigest),
  `PDF digest ${pdfDigest} is not pinned in README.md and VERIFICATION.md`,
);

const requiredSource = [
  "Action-Bound Injective Authorization",
  "signer-harvesting",
  "\\begin{definition}[Transplantation]",
  "\\begin{definition}[Duplicate admission]",
  "\\begin{definition}[Quorum substitution]",
  "\\begin{theorem}[ABIA composition]",
  "Forger B_j(pk*, Sign*)",
  "Nine machine-found separations",
  "\\begin{lemma}[Acceptance-prefix integrity]",
  "\\begin{proposition}[Offline anti-backdating is impossible here]",
  "Signature Instantiations and Context Strings",
  "Symbolic-to-computational correspondence",
  "AtomicityFail",
  "MediationBypass",
  "does not claim exactly-once physical execution",
  "ep_receipt_core.spthy",
  "ep_quorum_core.spthy",
  "Policy-Compliant Signatures",
  "Stateful Least Privilege Authorization for the Cloud",
  "Module-Lattice-Based Digital Signature Standard",
  "The TAMARIN Prover for the Symbolic Analysis of Security Protocols",
];

for (const text of requiredSource) {
  assert(source.includes(text), `main.tex is missing required text: ${text}`);
}

const forbiddenSource = [
  "awaiting editor review",
  "IETF-adopted",
  "exactly-once physical execution is guaranteed",
];

for (const text of forbiddenSource) {
  assert(!source.includes(text), `main.tex contains forbidden text: ${text}`);
}

const proofClaims = [
  "executable_honest_receipt (exists-trace): verified (9 steps)",
  "core_authenticity_uv_gated (all-traces): verified (11 steps)",
  "acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)",
  "no_replay_across_actions (all-traces): verified (11 steps)",
  "injective_acceptance_with_consumption (all-traces): verified (11 steps)",
  "unchecked_acceptance_is_injective (all-traces): falsified",
  "executable_quorum (exists-trace): verified (13 steps)",
  "quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)",
  "initiator_cannot_self_approve (all-traces): verified (4 steps)",
  "no_single_signer_fills_quorum (all-traces): verified (4 steps)",
  "commit_requires_signature_over_that_action (all-traces): verified (8 steps)",
];

for (const claim of proofClaims) {
  assert(source.includes(claim), `main.tex is missing proof claim: ${claim}`);
  assert(proofStatus.includes(claim), `formal/PROOF_STATUS.md does not support: ${claim}`);
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

const pdfText = execFileSync("pdftotext", [pdfPath, "-"], { encoding: "utf8" });
const normalizedPdfText = pdfText.replace(/\s+/g, " ");
for (const text of [
  "Action-Bound Injective Authorization",
  "Transplantation",
  "Duplicate admission",
  "Quorum substitution",
  "ABIA composition",
  "Artifact Availability",
  "does not claim exactly-once physical execution",
]) {
  assert(normalizedPdfText.includes(text), `main.pdf is missing required text: ${text}`);
}

console.log("Focused ePrint revision checks passed.");
