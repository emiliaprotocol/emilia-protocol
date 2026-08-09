// SPDX-License-Identifier: Apache-2.0
//
// Watch It Refuse — plain-English rendering for typed decision codes.
//
// Every typed reason the demo can surface maps to one human sentence. The
// typed code always ships alongside the sentence; this table never replaces
// or reinterprets a code, it only translates it.

const REASON_SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  // Gate refusal reasons (packages/gate check()).
  receipt_required:
    'No human authorization evidence was presented for this exact action.',
  replay_refused:
    'This authorization was already used once. A receipt authorizes exactly one execution; the same receipt cannot authorize a second.',
  assurance_too_low:
    'The evidence presented does not meet the assurance tier this action requires.',
  execution_binding_failed:
    'The action the human approved is not the action the system was about to execute.',
  capability_required:
    'This receipt only authorizes issuance of a bounded capability, not direct execution.',
  manifest_missing_assurance_class:
    'This guarded action has no declared assurance tier, so the gate fails closed.',
  manifest_selector_ambiguous:
    'The action selector matches more than one guarded action, so the gate fails closed.',
  evidence_log_failed:
    'The decision could not be durably recorded, so the gate refuses rather than act unaccountably.',
  not_guarded:
    'This action is not guarded by the manifest; no receipt is required.',
  allow:
    'A valid, in-scope, sufficiently-assured, fresh, unused authorization receipt was presented for this exact action.',

  // verifyEmiliaReceipt rejection reasons (surface as receipt_rejected:<code>).
  malformed_receipt:
    'The presented document is not a well-formed authorization receipt.',
  payload_outside_ijson_profile:
    'The receipt payload contains values outside the canonical JSON profile, so its signature cannot be checked safely.',
  no_trusted_keys_configured:
    'No issuer keys are pinned, so no receipt can be trusted.',
  bad_signature_encoding:
    'The receipt signature is not valid base64url and cannot be checked.',
  untrusted_or_invalid_signature:
    'The receipt signature does not verify under any pinned issuer key.',
  receipt_expired:
    'The receipt is older than the maximum age this action allows, or past its signed expiry.',
  receipt_not_yet_valid:
    'The receipt is dated in the future beyond the allowed clock skew.',
  action_mismatch:
    'The receipt authorizes a different action type than the one proposed.',
  signed_action_required:
    'The receipt does not embed the signed canonical action this check requires.',
  signed_action_invalid:
    'The signed action inside the receipt cannot be canonically hashed.',
  signed_action_hash_mismatch:
    'The signed action does not match the action hash the receipt claims.',
  action_hash_mismatch:
    'The receipt is bound to a different exact action than the one observed.',
  signed_action_required_field_missing:
    'A material field this action requires is missing from the signed action.',
  signed_action_caid_invalid:
    'The signed action does not carry a valid canonical action identifier.',
  outcome_not_accepted:
    'The receipt records a decision outcome that does not authorize execution.',
  missing_receipt_id:
    'The receipt has no issuer-generated receipt id, so one-time consumption cannot be enforced.',

  // Assurance evaluation reasons (evaluateReceiptAssurance).
  software_receipt:
    'The receipt is machine-signed at the software tier, which is what this demo action requires.',
  assurance_ok:
    'The receipt cryptographically earns the assurance tier this action requires.',
  assurance_proof_required:
    'No verifiable human-signoff proof is embedded or pinned, so only the software tier is credited.',

  // CAID computation/verification refusals (caid/impl).
  invalid_action_type:
    'The action type is missing or does not follow the registry grammar.',
  unknown_action_type:
    'The action type is not defined in the configured action-type registry.',
  unknown_suite:
    'The requested canonicalization suite is not implemented, so no identifier is issued.',
  malformed_caid:
    'The canonical action identifier string is malformed.',
  action_type_mismatch:
    'The identifier commits to a different action type than the object presented.',
  digest_mismatch:
    'The action object does not recompute to this identifier: the content differs.',
  invalid_object:
    'The action object fails the registry\'s material-field requirements.',

  // Admissibility verdicts (lib/evidence/admissibility).
  admissible:
    'The presented evidence satisfies the relying party\'s sufficiency policy for this action.',
  missing_evidence:
    'The evidence this action requires was not presented.',
  stale:
    'The required evidence exists but is stale or revoked under the relying party\'s freshness policy.',
  conflicted:
    'The presented evidence contradicts itself or binds a different action.',
  unverifiable:
    'The presented evidence could not be verified, so no sufficiency verdict can be issued.',
});

const PREFIX_SENTENCES: ReadonlyArray<readonly [string, (detail: string) => string]> = Object.freeze([
  ['receipt_rejected:', (detail: string) =>
    REASON_SENTENCES[detail]
    || 'The presented receipt was rejected by the verifier.'],
  ['missing_material_field:', (detail: string) =>
    `The material field "${detail}" this action type requires is missing from the action object.`],
  ['mistyped_field:', (detail: string) =>
    `The field "${detail}" does not match the type the registry requires.`],
  ['invalid_amount:', (detail: string) =>
    `The field "${detail}" is not a valid amount string.`],
]);

/**
 * One human sentence for a typed decision code. Unknown codes get an honest
 * fallback that repeats the code rather than inventing a meaning.
 */
export function plainReason(code: unknown): string {
  if (typeof code !== 'string' || !code) {
    return 'No typed reason was returned.';
  }
  if (REASON_SENTENCES[code]) return REASON_SENTENCES[code];
  for (const [prefix, render] of PREFIX_SENTENCES) {
    if (code.startsWith(prefix)) return render(code.slice(prefix.length));
  }
  return `The evaluation returned the typed code "${code}".`;
}
