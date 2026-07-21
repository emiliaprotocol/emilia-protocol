/**
 * EP Build / Binary Attestation — EP-BUILD-ATTESTATION-v1
 *
 * Closes DoD-audit GAP 5 (build/binary attestation) at the SOFTWARE level. The
 * chain a defense buyer needs is:
 *
 *   pinned source commit
 *      └─(reproducible build)─▶ deterministic binary hash H
 *            └─(append to transparency log)─▶ leaf L, inclusion proof, root R
 *                  └─(TPM 2.0 quote)─▶ "the machine that runs H measured H into a PCR"
 *                        └─(verifier)─▶ H matches source AND is logged AND is what runs
 *
 * This module implements and CAN VERIFY the first three links offline:
 *   1. leaf_binding   — the log leaf is bound to THIS {source_commit, binary_hash}
 *                       (a leaf can't be lifted from another build).
 *   2. log_inclusion  — the leaf is included under the claimed EP-MERKLE-v2 root
 *                       (reuses verifyMerkleAnchor from @emilia-protocol/verify).
 *   3. rebuild        — OPTIONAL live link: given a rebuild function, the binary
 *                       hash equals the deterministic build of the pinned source.
 *                       See attestation/reproducible-rebuild.mjs for the real one.
 *
 * The FOURTH link is optional TPM 2.0 quote evidence. This record verifier keeps
 * the deployment's TPM policy injected; the strict repository adapter lives in
 * tpm-quote-verifier.js. Physical hardware, AK/EK enrollment, measured boot,
 * known-good PCR policy, and manufacturer trust remain deployment inputs. See
 * attestation/STAGING.md for the exact evidence boundary.
 *
 * Design notes:
 *   - Pure and dependency-light: the record verifier does NOT shell out to npm or
 *     git. The live rebuild is INJECTED (opts.rebuild) so this file stays a pure
 *     offline verifier; the reproducible build lives in reproducible-rebuild.mjs.
 *   - Fail-closed: any malformed record, mismatched leaf, broken proof, or failed
 *     rebuild yields { valid: false } with a machine-readable reason. Nothing here
 *     throws on adversarial input.
 *   - Crypto/canonicalization is REUSED from @emilia-protocol/verify, not
 *     re-implemented: canonicalize() for the leaf preimage and verifyMerkleAnchor()
 *     (v2, 0x00 leaf / 0x01 branch domain separation) for inclusion.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import { canonicalize, verifyMerkleAnchor, MERKLE_V2_ALG } from '../packages/verify/index.js';

export const BUILD_ATTESTATION_VERSION = 'EP-BUILD-ATTESTATION-v1';
export const ATTESTATION_SUBJECT_VERSION = 'EP-BUILD-ATTESTATION-SUBJECT-v1';
export const TPM_QUOTE_FORMAT = 'EP-TPM-QUOTE-v1';

const HEX64 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;

function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * The canonical SUBJECT the transparency-log leaf commits to. This is what binds
 * a log entry to one exact (source commit, binary artifact) pair. Changing any
 * field changes the leaf, so an attacker cannot reuse another build's inclusion
 * proof for a different binary or a different source commit.
 *
 * @param {object} record - an EP-BUILD-ATTESTATION-v1 record
 * @returns {object} the canonical subject object (pre-canonicalization)
 */
export function attestationSubject(record: Record<string, any>): Record<string, any> {
  return {
    '@subject': ATTESTATION_SUBJECT_VERSION,
    source_commit: record.source.commit,
    package_path: record.source.package_path,
    artifact_filename: record.artifact.filename,
    artifact_sha256: record.artifact.sha256,
  };
}

/**
 * EP-MERKLE-v2 leaf hash of the attestation subject:
 *   SHA-256(0x00 || canonicalJSON(subject)) -> hex.
 * The 0x00 leaf prefix (vs the 0x01 branch prefix used by verifyMerkleAnchor's
 * v2 pairing) is the same domain separation the receipt anchor uses, so a leaf
 * can never be confused with an interior node.
 *
 * @param {object} subject - the object returned by attestationSubject()
 * @returns {string} hex leaf hash
 */
export function attestationLeafHash(subject: Record<string, any>): string {
  const preimage = Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalize(subject), 'utf8')]);
  return sha256Hex(preimage);
}

function structuralError(record: any): string | null {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return 'record must be a JSON object';
  if (record['@version'] !== BUILD_ATTESTATION_VERSION) return `record @version must be ${BUILD_ATTESTATION_VERSION}`;

  const s = record.source;
  if (!s || typeof s !== 'object' || Array.isArray(s)) return 'record.source must be an object';
  if (typeof s.commit !== 'string' || !GIT_SHA.test(s.commit)) return 'record.source.commit must be a 40-hex git sha';
  if (typeof s.package_path !== 'string' || s.package_path.trim() === '') return 'record.source.package_path must be a non-empty string';

  const a = record.artifact;
  if (!a || typeof a !== 'object' || Array.isArray(a)) return 'record.artifact must be an object';
  if (typeof a.filename !== 'string' || a.filename.trim() === '') return 'record.artifact.filename must be a non-empty string';
  if (typeof a.sha256 !== 'string' || !HEX64.test(a.sha256)) return 'record.artifact.sha256 must be a 64-hex digest';
  if (!Number.isInteger(a.bytes) || a.bytes < 0) return 'record.artifact.bytes must be a non-negative integer';

  const l = record.log_entry;
  if (!l || typeof l !== 'object' || Array.isArray(l)) return 'record.log_entry must be an object';
  if (l.alg !== MERKLE_V2_ALG) return `record.log_entry.alg must be ${MERKLE_V2_ALG}`;
  if (typeof l.leaf_hash !== 'string' || !HEX64.test(l.leaf_hash)) return 'record.log_entry.leaf_hash must be a 64-hex digest';
  if (typeof l.merkle_root !== 'string' || !HEX64.test(l.merkle_root)) return 'record.log_entry.merkle_root must be a 64-hex digest';
  if (!Array.isArray(l.merkle_proof)) return 'record.log_entry.merkle_proof must be an array';

  return null;
}

interface TpmQuoteResult {
  supported: boolean;
  ok: boolean;
  reason: string;
  pcrDigest?: string;
}

/**
 * TPM 2.0 verifier boundary.
 *
 * A real implementation verifies that a TPM Attestation Key (AK) signed a
 * TPM2_Quote over a PCR set whose value equals the measurement of the running
 * binary, with the record's nonce for freshness, and that the AK chains to an
 * Endorsement Key credential the buyer trusts. NONE of that is possible in a
 * CI/dev environment without deployment-owned trust inputs. This function
 * therefore refuses by default unless a strict verifier is injected.
 *
 * The interface is defined so a defense buyer can drop in a hardware-backed
 * verifier (e.g. tpm2-tools / go-attestation) without changing the record
 * format or the surrounding chain.
 *
 * @param {object} _quote - an EP-TPM-QUOTE-v1 object
 * @param {object} [opts]
 * @param {(quote: object) => {ok: boolean, reason?: string, pcrDigest?: string}} [opts.hardwareVerifier]
 *        Injected real verifier. Provided only where TPM hardware exists.
 * @returns {{ supported: boolean, ok: boolean, reason: string, pcrDigest?: string }}
 */
export function verifyTpmQuote(_quote: any, opts: { hardwareVerifier?: (quote: any) => { ok: boolean; reason?: string; pcrDigest?: string } } = {}): TpmQuoteResult {
  if (typeof opts.hardwareVerifier === 'function') {
    const r = opts.hardwareVerifier(_quote);
    return {
      supported: true,
      ok: r.ok === true,
      reason: r.ok === true ? 'tpm-quote-verified-by-injected-hardware-verifier' : (r.reason || 'tpm-quote-rejected'),
      ...(r.pcrDigest ? { pcrDigest: r.pcrDigest } : {}),
    };
  }
  return {
    supported: false,
    ok: false,
    reason: 'tpm-hardware-required: no TPM 2.0 verifier and deployment trust policy were supplied (see attestation/STAGING.md)',
  };
}

function tpmQuoteStructureError(q: any): string | null {
  if (!q || typeof q !== 'object' || Array.isArray(q)) return 'tpm_quote must be an object';
  if (q['@format'] !== TPM_QUOTE_FORMAT) return `tpm_quote.@format must be ${TPM_QUOTE_FORMAT}`;
  for (const field of ['quoted', 'signature', 'ak_public', 'nonce']) {
    if (typeof q[field] !== 'string' || q[field].trim() === '') return `tpm_quote.${field} must be a non-empty string`;
  }
  return null;
}

interface RebuildLink {
  status: string;
  reason?: string;
  built_source_commit?: string;
  claimed_source_commit?: string;
  built_sha256?: string;
  claimed_sha256?: string;
  source_commit?: string;
  sha256?: string;
}

interface BuildAttestationLinks {
  record_shape: boolean;
  leaf_binding: boolean;
  log_inclusion: boolean | { status: string; checkpoint_root_matched: boolean };
  rebuild: RebuildLink;
  tpm_quote: { status: string; reason?: string };
}

interface BuildAttestationResult {
  valid: boolean;
  complete: boolean;
  links: BuildAttestationLinks;
  reason?: string;
}

/**
 * Verify an EP build/binary attestation record, fail-closed.
 *
 * Links and their meaning:
 *   - record_shape:  structural validity of the record.
 *   - leaf_binding:  log_entry.leaf_hash == leafHash(subject(source, artifact)).
 *                    Proves the logged leaf is THIS source+binary, not another.
 *   - log_inclusion: the leaf reconstructs the claimed EP-MERKLE-v2 root.
 *   - rebuild:       (only when opts.rebuild is supplied) the deterministic build
 *                    of source.commit/package_path hashes to artifact.sha256.
 *                    Without a rebuild fn this link is reported 'not_checked' and
 *                    `complete` is false: the record's provenance chain is proven
 *                    up to the log, but "binary == build of source" was not run.
 *   - tpm_quote:     (only when record.tpm_quote is present) reported via
 *                    verifyTpmQuote. Absent hardware, status is 'hardware_required'
 *                    and it NEVER contributes a passing verdict.
 *
 * `valid` is true iff every link that was actually CHECKED passed. `complete` is
 * true iff the rebuild link was checked (the full source→binary→log chain ran).
 * A TPM quote never makes `complete` true here (that needs hardware).
 *
 * @param {object} record - EP-BUILD-ATTESTATION-v1
 * @param {object} [opts]
 * @param {(source: {commit: string, package_path: string}) => {source_commit: string, sha256: string, filename?: string, bytes?: number}} [opts.rebuild]
 *        Live reproducible-build function. It MUST report the checked-out source
 *        commit it actually built. Injected so this verifier stays pure.
 * @param {(quote: object) => {ok: boolean, reason?: string, pcrDigest?: string}} [opts.tpmHardwareVerifier]
 *        Real TPM verifier, only where hardware exists.
 * @returns {{ valid: boolean, complete: boolean, links: object, reason?: string }}
 */
export function verifyBuildAttestation(
  record: any,
  opts: {
    rebuild?: (source: { commit: string; package_path: string }) => any;
    tpmHardwareVerifier?: (quote: any) => { ok: boolean; reason?: string; pcrDigest?: string };
  } = {},
): BuildAttestationResult {
  const links: BuildAttestationLinks = {
    record_shape: false,
    leaf_binding: false,
    log_inclusion: false,
    rebuild: { status: 'not_checked' },
    tpm_quote: { status: 'absent' },
  };

  const shapeErr = structuralError(record);
  if (shapeErr) {
    return { valid: false, complete: false, links, reason: shapeErr };
  }
  links.record_shape = true;

  // Link 1: the leaf is bound to this exact source+binary.
  const expectedLeaf = attestationLeafHash(attestationSubject(record));
  if (record.log_entry.leaf_hash !== expectedLeaf) {
    return {
      valid: false,
      complete: false,
      links,
      reason: `leaf_binding_failed: log_entry.leaf_hash does not commit to this {source, artifact} (expected ${expectedLeaf})`,
    };
  }
  links.leaf_binding = true;

  // Link 2: the leaf is included under the claimed EP-MERKLE-v2 root.
  const included = verifyMerkleAnchor(
    record.log_entry.leaf_hash,
    record.log_entry.merkle_proof,
    record.log_entry.merkle_root,
    { v2: true },
  );
  if (!included) {
    return { valid: false, complete: false, links, reason: 'log_inclusion_failed: leaf does not reconstruct the claimed merkle_root' };
  }
  links.log_inclusion = true;

  // Optional interior check: if a signed checkpoint is carried, its root must
  // equal the inclusion root (defense buyer separately verifies the checkpoint
  // signature + witness quorum via @emilia-protocol/verify).
  if (record.log_entry.checkpoint && typeof record.log_entry.checkpoint === 'object') {
    if (record.log_entry.checkpoint.root_hash !== record.log_entry.merkle_root) {
      return { valid: false, complete: false, links, reason: 'checkpoint_root_mismatch: checkpoint.root_hash != log_entry.merkle_root' };
    }
    links.log_inclusion = { status: 'included', checkpoint_root_matched: true };
  }

  // Link 3 (optional, live): binary hash == deterministic build of pinned source.
  let complete = false;
  if (typeof opts.rebuild === 'function') {
    let rebuilt;
    try {
      rebuilt = opts.rebuild({ commit: record.source.commit, package_path: record.source.package_path });
    } catch (e) {
      return { valid: false, complete: false, links: { ...links, rebuild: { status: 'error', reason: String(e && e.message || e) } }, reason: 'rebuild_error' };
    }
    if (!rebuilt || typeof rebuilt.sha256 !== 'string' || !HEX64.test(rebuilt.sha256)) {
      links.rebuild = { status: 'error', reason: 'rebuild did not return a 64-hex sha256' };
      return { valid: false, complete: false, links, reason: 'rebuild_error' };
    }
    if (typeof rebuilt.source_commit !== 'string' || !GIT_SHA.test(rebuilt.source_commit)) {
      links.rebuild = { status: 'error', reason: 'rebuild did not report the checked-out source_commit' };
      return { valid: false, complete: false, links, reason: 'rebuild_source_unverified' };
    }
    if (rebuilt.source_commit !== record.source.commit) {
      links.rebuild = {
        status: 'source_mismatch',
        built_source_commit: rebuilt.source_commit,
        claimed_source_commit: record.source.commit,
      };
      return {
        valid: false,
        complete: false,
        links,
        reason: 'rebuild_source_mismatch: checked-out source is not record.source.commit',
      };
    }
    if (rebuilt.sha256 !== record.artifact.sha256) {
      links.rebuild = { status: 'mismatch', built_sha256: rebuilt.sha256, claimed_sha256: record.artifact.sha256 };
      return { valid: false, complete: true, links, reason: 'rebuild_mismatch: binary hash is not the deterministic build of the pinned source' };
    }
    links.rebuild = {
      status: 'matched',
      source_commit: rebuilt.source_commit,
      sha256: rebuilt.sha256,
    };
    complete = true;
  }

  // Link 4 (optional, hardware-gated): TPM quote.
  if (record.tpm_quote !== undefined) {
    const qErr = tpmQuoteStructureError(record.tpm_quote);
    if (qErr) {
      return { valid: false, complete, links: { ...links, tpm_quote: { status: 'malformed', reason: qErr } }, reason: qErr };
    }
    const tpm = verifyTpmQuote(record.tpm_quote, { hardwareVerifier: opts.tpmHardwareVerifier });
    links.tpm_quote = tpm.supported
      ? { status: tpm.ok ? 'verified' : 'rejected', reason: tpm.reason }
      : { status: 'hardware_required', reason: tpm.reason };
    // A present-but-hardware-required quote does not fail the software chain, but
    // an explicitly REJECTED quote (a real verifier said no) is fail-closed.
    if (tpm.supported && !tpm.ok) {
      return { valid: false, complete, links, reason: `tpm_quote_rejected: ${tpm.reason}` };
    }
  }

  return { valid: true, complete, links };
}
