// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-DOC-PROOF-JOIN-v1.
 *
 * Establishes one narrow fact: a cryptographically valid Authority Proof was
 * issued by a registry issuer key accepted through a relying-party-anchored
 * Authority Document chain. It does NOT decide whether the proof's grant
 * authorizes an action, whether a delegation chain is valid, or whether the
 * authority-registry snapshot contains the asserted grant.
 */
import {
  authorityInstantMs,
  docCoreDigest,
  isStableAuthorityIdentifier,
  resolveIssuerKeyAt,
  verifyAuthorityChain,
} from './authority-doc.js';
import { verifyAuthorityProofSignature } from './proof.js';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ISSUER_KID_RE = /^ep:authority-issuer-key:sha256:[0-9a-f]{64}$/;

function exactObject(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

/**
 * Verify an Authority Proof issuer through an Authority Document chain.
 *
 * @param {object} proof EP-AUTHORITY-PROOF-v1 with the join-profile members
 * @param {object[]} docs EP-AUTHORITY-DOC-v1 chain, oldest first
 * @param {object} opts relying-party trust inputs
 * @param {string} [opts.expectedDocumentHead] accepted current chain head
 * @param {string} [opts.expectedBootstrapDigest] accepted document zero
 * @param {string} [opts.expectedOrganizationId] organization expected in proof
 * @param {string} [opts.expectedOrganizationDomain] domain expected in documents
 * @param {string} [opts.expectedRegistryIssuerId] stable registry issuer identity
 * @param {string} [opts.expectedProofIssuedAt] independently authenticated proof time;
 *   this MUST be relying-party evidence, not a copy of proof.issued_at
 * @param {string} [opts.expectRegistryHead] authority-registry snapshot head
 * @param {number} [opts.expectMinEpoch] minimum authority-registry epoch
 */
export function verifyAuthorityProofViaDocument(proof, docs, opts = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const checks = {
    document_chain: false,
    continuity: false,
    document_anchor: false,
    organization_binding: false,
    proof_document_binding: false,
    registry_issuer_binding: false,
    issuer_key_resolved: false,
    issuer_key_usage: false,
    proof_signature: false,
    proof_time_anchor: false,
    registry_head: false,
    epoch_fresh: false,
  };
  const signature = verifyAuthorityProofSignature(proof);
  checks.proof_signature = signature.verified;
  const fail = (reason, extra = {}) => ({
    // Verification is proof mathematics plus document-chain continuity.
    // Acceptance additionally requires relying-party identity, time, document,
    // key-usage, and registry-snapshot trust inputs.
    verified: checks.proof_signature && checks.document_chain && checks.continuity,
    issuer_accepted: false,
    accepted: false,
    authority_evaluated: false,
    delegation_evaluated: false,
    checks: { ...checks, ...(extra.checks || {}) },
    reason,
    ...(extra.document_head ? { document_head: extra.document_head } : {}),
    ...(extra.bootstrap_digest ? { bootstrap_digest: extra.bootstrap_digest } : {}),
    ...(extra.proof_digest ? { proof_digest: extra.proof_digest } : {}),
  });

  let chain;
  try {
    chain = verifyAuthorityChain(docs);
  } catch {
    return fail('authority_document_chain_invalid');
  }
  if (!chain.verified || !chain.head) return fail('authority_document_chain_invalid');
  checks.document_chain = true;
  let documentHead;
  let bootstrapDigest;
  try {
    documentHead = docCoreDigest(chain.head);
    bootstrapDigest = docCoreDigest(docs[0]);
  } catch {
    return fail('authority_document_chain_invalid');
  }
  const context = { document_head: documentHead, bootstrap_digest: bootstrapDigest };

  if (chain.breaks.length > 0) return fail('authority_document_continuity_break', context);
  checks.continuity = true;

  const hasHeadAnchor = typeof opts.expectedDocumentHead === 'string';
  const hasBootstrapAnchor = typeof opts.expectedBootstrapDigest === 'string';
  if (!hasHeadAnchor && !hasBootstrapAnchor) {
    return fail('authority_document_anchor_required', context);
  }
  if ((hasHeadAnchor && opts.expectedDocumentHead !== documentHead)
      || (hasBootstrapAnchor && opts.expectedBootstrapDigest !== bootstrapDigest)) {
    return fail('authority_document_anchor_mismatch', context);
  }
  checks.document_anchor = true;

  const organizationId = opts.expectedOrganizationId;
  const organizationDomain = opts.expectedOrganizationDomain;
  if (!isStableAuthorityIdentifier(organizationId)
      || !isStableAuthorityIdentifier(organizationDomain)
      || proof?.organization_id !== organizationId
      || !docs.every((doc) => doc?.org?.id === organizationId
        && doc?.org?.domain === organizationDomain)) {
    return fail('authority_document_organization_mismatch', context);
  }
  checks.organization_binding = true;

  if (typeof opts.expectedProofIssuedAt !== 'string') {
    return fail('authority_proof_time_anchor_required', context);
  }
  // The proof's signed time is a claim by its signer. It becomes load-bearing
  // only when a separately supplied relying-party time anchor is strict and
  // byte-for-byte equal to that claim.
  if (!Number.isFinite(authorityInstantMs(opts.expectedProofIssuedAt))
      || !Number.isFinite(authorityInstantMs(proof?.issued_at))) {
    return fail('authority_proof_time_anchor_invalid', context);
  }
  if (typeof proof?.issued_at !== 'string'
      || proof.issued_at !== opts.expectedProofIssuedAt) {
    return fail('authority_proof_time_anchor_mismatch', context);
  }
  checks.proof_time_anchor = true;

  const binding = proof?.authority_document;
  if (!exactObject(binding, ['head_digest', 'head_seq', 'issuer_kid'])
      || !DIGEST_RE.test(binding.head_digest || '')
      || !Number.isSafeInteger(binding.head_seq)
      || binding.head_seq < 0
      || binding.head_seq >= docs.length
      || !ISSUER_KID_RE.test(binding.issuer_kid || '')) {
    return fail('authority_proof_document_binding_missing_or_malformed', context);
  }
  const boundDocument = docs[binding.head_seq];
  if (docCoreDigest(boundDocument) !== binding.head_digest) {
    return fail('authority_proof_document_head_mismatch', context);
  }
  checks.proof_document_binding = true;

  const registryIssuerId = opts.expectedRegistryIssuerId;
  if (!isStableAuthorityIdentifier(registryIssuerId)
      || !isStableAuthorityIdentifier(proof?.registry_issuer_id)
      || proof?.registry_issuer_id !== registryIssuerId) {
    return fail('authority_registry_issuer_mismatch', context);
  }
  const boundEntry = boundDocument.issuer_keys.find((entry) => entry.kid === binding.issuer_kid);
  if (!boundEntry || boundEntry.registry_issuer_id !== registryIssuerId) {
    return fail('authority_registry_issuer_mismatch', context);
  }
  checks.registry_issuer_binding = true;

  const resolved = resolveIssuerKeyAt(docs, binding.issuer_kid, opts.expectedProofIssuedAt);
  if (!resolved
      || resolved.kid !== binding.issuer_kid
      || resolved.doc_seq !== binding.head_seq
      || resolved.key !== boundEntry.key
      || resolved.key !== proof?.signature?.public_key
      || resolved.registry_issuer_id !== registryIssuerId) {
    return fail('authority_proof_key_unresolvable', context);
  }
  checks.issuer_key_resolved = true;

  if (!resolved.usages.includes('authority_proof_issuer')) {
    return fail('authority_proof_key_wrong_usage', context);
  }
  checks.issuer_key_usage = true;

  if (!signature.verified) {
    return fail(signature.reason || 'authority_proof_invalid', {
      ...context,
      proof_digest: signature.proof_digest,
    });
  }
  if (!DIGEST_RE.test(opts.expectRegistryHead || '')
      || !Number.isSafeInteger(opts.expectMinEpoch)
      // Number.isSafeInteger's lib type is `(number: unknown) => boolean`, not a
      // user-defined type guard, so TS does not narrow opts.expectMinEpoch here even
      // though the runtime check above already proved it is a defined safe integer.
      || /** @type {number} */ (opts.expectMinEpoch) < 0) {
    return fail('registry_snapshot_pins_required', {
      ...context,
      proof_digest: signature.proof_digest,
    });
  }
  if (proof.registry_head !== opts.expectRegistryHead) {
    return fail('registry_head_mismatch', {
      ...context,
      proof_digest: signature.proof_digest,
    });
  }
  checks.registry_head = true;
  // opts.expectMinEpoch was already proved a defined safe integer by the
  // expectMinEpoch guard above (the function would have returned otherwise);
  // TS just can't carry that fact across the earlier non-predicate check.
  if (!(Number.isSafeInteger(proof.registry_epoch)
      && proof.registry_epoch >= /** @type {number} */ (opts.expectMinEpoch))) {
    return fail('stale_registry', {
      ...context,
      proof_digest: signature.proof_digest,
    });
  }
  checks.epoch_fresh = true;

  return {
    verified: true,
    issuer_accepted: true,
    // Compatibility alias: "accepted" is issuer acceptance only.
    accepted: true,
    authority_evaluated: false,
    delegation_evaluated: false,
    checks,
    document_head: documentHead,
    proof_document_head: binding.head_digest,
    bootstrap_digest: bootstrapDigest,
    registry_issuer_id: registryIssuerId,
    proof_digest: signature.proof_digest,
    key_id: binding.issuer_kid,
    limitations: [
      'Issuer acceptance is not a decision that the grant authorizes an action.',
      'Grant scope, limits, validity, revocation freshness, and delegation require separate evaluation.',
      'Authority-registry membership requires independently verified snapshot or inclusion evidence.',
    ],
  };
}

export default { verifyAuthorityProofViaDocument };
