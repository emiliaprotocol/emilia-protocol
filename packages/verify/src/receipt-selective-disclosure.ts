// SPDX-License-Identifier: Apache-2.0
/**
 * EP-SD-v1 — selective-disclosure presentation of EP authorization receipts.
 *
 * A holder presents a receipt to an auditor, insurer, or regulator proving
 * that an authorized approval bound one exact action (CAID intact, receipt
 * signature intact, evidence-grade fields visible) WITHOUT revealing the
 * business content of undisclosed fields.
 *
 * Construction (SD-JWT-style salted-digest disclosure; no new cryptography):
 *
 *   ISSUANCE (disclosure-ready): before signing, each designated-disclosable
 *   field's value in the payload is REPLACED by a salted commitment slot
 *   "ep-sd-commit:sha256:<hex>", and the signed payload carries a
 *   `disclosure` block naming the committed paths. The issuer's Ed25519
 *   signature is computed over the canonical bytes of THAT payload, so the
 *   signed bytes already are the redacted view. The issuer hands the holder
 *   the openings ({path, salt, value}) outside the signed body.
 *
 *   PRESENTATION: the holder forwards the signed receipt UNCHANGED plus any
 *   subset of openings and an audience/nonce binding. No signature is ever
 *   re-created; every presentation reuses the one issuer signature.
 *
 *   VERIFICATION: the verifier (a) verifies the issuer signature over the
 *   receipt exactly as any EP-RECEIPT-v1 verifier does — all signed bytes are
 *   present because undisclosed fields are commitments, not gaps — and
 *   (b) recomputes each disclosed opening's commitment and compares it to the
 *   slot embedded in the signed payload. The commitment binds the field PATH
 *   as well as the salt and value, so an opening cannot be swapped across
 *   fields.
 *
 * REAL CONSTRAINT, stated plainly: an EP-RECEIPT-v1 signature is Ed25519 over
 * the full canonical payload bytes. A verifier therefore needs every signed
 * byte. A receipt whose business fields were signed in PLAINTEXT cannot have
 * those fields hidden later while the signature still verifies — there is no
 * way around this without changing the signature scheme. Selective disclosure
 * under this profile requires DISCLOSURE-READY ISSUANCE (commitments inside
 * the signed body). Already-issued plaintext receipts remain fully verifiable
 * and fully presentable, but only in full; they are not retrofittable into
 * redacted presentations, and this module refuses them with
 * `missing_disclosure_block` rather than pretending otherwise.
 *
 * Honest residuals (see also the staged -01 prose):
 *   - STRUCTURE LEAKAGE: the verifier learns which fields exist and which
 *     were withheld (the signed `disclosure.paths` list is visible).
 *   - LINKABILITY: two presentations of the same receipt share the same
 *     signature bytes and commitment digests and are trivially linkable.
 *     This profile does not claim unlinkability (that is BBS territory).
 *   - GUESSABILITY WITHOUT SALT: a digest over a low-entropy value alone is
 *     an oracle. Salts (>= 128 bits) are therefore mandatory per field, and
 *     an opening without one is refused by construction.
 *   - Audience/nonce binding without a pinned holder key prevents a verifier
 *     from ACCEPTING a presentation bound to someone else's audience/nonce;
 *     it does not prove possession. Pin a holder key (holder_proof) where
 *     possession matters.
 *
 * VERIFIED vs ACCEPTED: every check here is cryptographic verification.
 * Whether the issuer key belongs to a trusted issuer, whether the receipt is
 * current/unrevoked, and whether the disclosure suffices for a reliance
 * purpose are ACCEPTANCE decisions that remain with the relying party.
 *
 * All failures are structured refusals with named reasons; hostile input must
 * never crash the verifier.
 */

import crypto, { type KeyObject } from 'node:crypto';

import { canonicalizeStrictJson, isStrictCanonicalJson } from './strict-json.js';
import { verifyReceipt } from './index.js';

type Obj = Record<string, unknown>;

export const EP_SD_VERSION = 'EP-SD-v1';
export const EP_SD_PRESENTATION_VERSION = 'EP-SD-PRESENTATION-v1';
export const EP_SD_COMMIT_DOMAIN = 'EP-SD-COMMIT-v1';
export const EP_SD_BINDING_DOMAIN = 'EP-SD-BINDING-v1';
/** Prefix marking a committed (redacted) slot inside a signed payload. */
export const EP_SD_COMMIT_MARKER_PREFIX = 'ep-sd-commit:';

/** Minimum salt entropy: 128 bits, per-field, mandatory. */
export const EP_SD_MIN_SALT_BYTES = 16;

const MAX_DISCLOSABLE_PATHS = 64;
const MAX_PATH_SEGMENTS = 8;
const MAX_PATH_LENGTH = 256;

const COMMIT_SLOT_RE = /^ep-sd-commit:sha256:[0-9a-f]{64}$/;
const PATH_SEGMENT_RE = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
// Mirrors the (unexported) CAID grammar in aeb-adapter-contract.ts. Keep the
// two in sync; the contract file is the governing definition.
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const RFC3339_OFFSET_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * The closed non-redactable set. A path equal to, above, or below any of
 * these can never be designated disclosable: hiding the CAID or the
 * evidence-grade fields would turn "this exact action was approved with this
 * evidence" into "something was approved somehow", which is exactly the
 * laundered-authority failure the presentation-binding work exists to refuse.
 */
export const NON_REDACTABLE_PATHS: readonly string[] = Object.freeze([
  'caid',
  'action.caid',
  'action.action_type',
  'action_digest',
  'canonical_action_digest',
  'evidence_grade',
  'verification_status',
  'signoffs',
  'required_approvals',
  'disclosure',
]);

export interface SdOpening {
  /** Base64url salt decoding to at least EP_SD_MIN_SALT_BYTES bytes. */
  salt: string;
  /** The original field value (strict canonical JSON domain). */
  value: unknown;
}

export type SdOpenings = Record<string, SdOpening>;

export interface SdBinding {
  audience: string;
  nonce: string;
  created_at: string;
}

export interface SdHolderProof {
  /** Holder Ed25519 public key, base64url SPKI DER. */
  public_key: string;
  /** Ed25519 signature over the 32-byte presentation binding digest. */
  signature: string;
}

export interface SdPresentation {
  '@version': typeof EP_SD_PRESENTATION_VERSION;
  /** The signed disclosure-ready receipt document, byte-for-byte unmodified. */
  receipt: Obj;
  /** Disclosed openings, sorted by path, each opening one committed slot. */
  disclosed: Array<{ path: string; salt: string; value: unknown }>;
  binding: SdBinding;
  holder_proof?: SdHolderProof;
}

export interface SdRefusal {
  ok: false;
  /** Sorted, de-duplicated named refusal reasons (never empty). */
  refusals: string[];
}

export interface SdPrepareSuccess {
  ok: true;
  /** The disclosure-ready payload to sign (commitment slots + disclosure block). */
  payload: Obj;
  /** Full opening set for the holder. Not part of the signed body. */
  openings: SdOpenings;
}

export interface SdPresentSuccess {
  ok: true;
  presentation: SdPresentation;
}

export interface SdVerifyResult {
  ok: boolean;
  refusals: string[];
  checks: {
    presentation_structure: boolean;
    receipt_signature: boolean;
    disclosure_block: boolean;
    non_redactable_set: boolean;
    commitments: boolean;
    openings: boolean;
    binding: boolean;
    /** null when no holder proof was presented and none was required. */
    holder_proof: boolean | null;
  };
  caid: string | null;
  /** path -> disclosed value; only populated on ok. */
  disclosed: Record<string, unknown> | null;
  /** Committed paths NOT opened in this presentation (structure leakage is explicit). */
  undisclosed_paths: string[];
  decision_scope: {
    establishes: string;
    does_not_establish: string;
  };
}

const DECISION_SCOPE = Object.freeze({
  establishes: 'cryptographic verification: issuer signature over the disclosure-ready payload, '
    + 'disclosed openings against their signed commitments, and the audience/nonce binding',
  does_not_establish: 'acceptance under a pinned trust root, issuer trustworthiness, currency or '
    + 'revocation, holder possession (unless a holder key is pinned), or anything about the values '
    + 'of undisclosed fields beyond their committed existence',
});

// ─── primitives ──────────────────────────────────────────────────────────────

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function sha256Bytes(input: string): Buffer {
  return crypto.createHash('sha256').update(input, 'utf8').digest();
}

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function canonicalBase64url(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0
      || !B64URL_RE.test(value) || value.length % 4 === 1) return false;
  try {
    return Buffer.from(value, 'base64url').toString('base64url') === value;
  } catch {
    return false;
  }
}

function refuse(reasons: Iterable<string>): SdRefusal {
  return { ok: false, refusals: [...new Set(reasons)].sort() };
}

function validPath(path: string): boolean {
  if (typeof path !== 'string' || path.length === 0 || path.length > MAX_PATH_LENGTH) return false;
  const segments = path.split('.');
  if (segments.length > MAX_PATH_SEGMENTS) return false;
  return segments.every((segment) => PATH_SEGMENT_RE.test(segment));
}

/** True when a and b are equal or one is a dot-path prefix of the other. */
function pathsOverlap(a: string, b: string): boolean {
  return a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`);
}

function nonRedactableConflict(path: string): boolean {
  return NON_REDACTABLE_PATHS.some((reserved) => pathsOverlap(path, reserved));
}

function getPath(root: Obj, path: string): { found: boolean; value: unknown } {
  let current: unknown = root;
  for (const segment of path.split('.')) {
    if (!isRecord(current) || !Object.hasOwn(current, segment)) return { found: false, value: undefined };
    current = current[segment];
  }
  return { found: true, value: current };
}

function setPath(root: Obj, path: string, value: unknown): void {
  const segments = path.split('.');
  let current: Obj = root;
  for (const segment of segments.slice(0, -1)) current = current[segment] as Obj;
  current[segments[segments.length - 1]] = value;
}

/**
 * Salted, path-bound, domain-separated commitment over one field value.
 * "sha256:<hex>" over the canonical bytes of the commitment structure. The
 * path inside the committed structure is what defeats swapped-opening attacks.
 */
export function sdCommitmentDigest(path: string, salt: string, value: unknown): string {
  return `sha256:${sha256Hex(canonicalizeStrictJson({
    domain: EP_SD_COMMIT_DOMAIN,
    path,
    salt,
    value,
  }))}`;
}

function commitSlot(path: string, salt: string, value: unknown): string {
  return `${EP_SD_COMMIT_MARKER_PREFIX}${sdCommitmentDigest(path, salt, value)}`;
}

/**
 * The 32-byte digest a presentation binding commits to: the exact receipt
 * bytes, the exact disclosed set, and the verifier-chosen audience and nonce.
 */
export function sdPresentationBindingDigest(
  receipt: Obj,
  disclosed: SdPresentation['disclosed'],
  binding: SdBinding,
): Buffer {
  return sha256Bytes(canonicalizeStrictJson({
    domain: EP_SD_BINDING_DOMAIN,
    receipt_digest: `sha256:${sha256Hex(canonicalizeStrictJson(receipt))}`,
    disclosed_digest: `sha256:${sha256Hex(canonicalizeStrictJson(disclosed))}`,
    audience: binding.audience,
    nonce: binding.nonce,
    created_at: binding.created_at,
  }));
}

// Deep scan for commitment-marker strings. Reports every string value whose
// bytes begin with the marker prefix, with a display path ("a.b[2].c") used
// only in refusal reasons.
function scanMarkerStrings(value: unknown, path: string, hits: Array<{ path: string; value: string }>): void {
  if (typeof value === 'string') {
    if (value.startsWith(EP_SD_COMMIT_MARKER_PREFIX)) hits.push({ path, value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => scanMarkerStrings(entry, `${path}[${index}]`, hits));
    return;
  }
  if (isRecord(value)) {
    for (const [key, member] of Object.entries(value)) {
      scanMarkerStrings(member, path === '' ? key : `${path}.${key}`, hits);
    }
  }
}

// ─── issuance preparation ────────────────────────────────────────────────────

/**
 * Prepare a payload for disclosure-ready issuance. Runs BEFORE signing: the
 * returned payload (commitment slots + signed `disclosure` block) is what the
 * issuer signs as an ordinary EP-RECEIPT-v1 payload; the returned openings go
 * to the holder outside the signed body. This function never signs and never
 * re-signs.
 *
 * `salts` may pin per-path salts (conformance vectors use fixed seeds);
 * omitted salts are drawn fresh from the CSPRNG. Salt reuse across fields is
 * refused here and again at verification.
 */
export function prepareSelectiveDisclosure(
  payload: unknown,
  disclosablePaths: readonly string[],
  salts: Record<string, string> = {},
): SdPrepareSuccess | SdRefusal {
  try {
    if (!isRecord(payload) || !isStrictCanonicalJson(payload)) return refuse(['malformed_payload']);
    if (Object.hasOwn(payload, 'disclosure')) return refuse(['disclosure_block_present']);
    if (!Array.isArray(disclosablePaths) || disclosablePaths.length === 0
        || disclosablePaths.length > MAX_DISCLOSABLE_PATHS) {
      return refuse(['malformed_path_list']);
    }
    if (!isRecord(salts) || !isStrictCanonicalJson(salts)) return refuse(['malformed_salts']);

    // A payload that already carries marker-prefixed strings would make
    // committed slots ambiguous with data; refuse rather than guess.
    const markerHits: Array<{ path: string; value: string }> = [];
    scanMarkerStrings(payload, '', markerHits);
    if (markerHits.length > 0) {
      return refuse(markerHits.map((hit) => `marker_collision:${hit.path}`));
    }

    const reasons: string[] = [];
    const seen = new Set<string>();
    for (const path of disclosablePaths) {
      if (!validPath(path)) { reasons.push(`invalid_path:${String(path).slice(0, 64)}`); continue; }
      if (seen.has(path)) { reasons.push(`duplicate_path:${path}`); continue; }
      seen.add(path);
      if (nonRedactableConflict(path)) { reasons.push(`non_redactable_path:${path}`); continue; }
      if (!getPath(payload, path).found) reasons.push(`unknown_path:${path}`);
    }
    // Overlapping designations (a field and its own subfield) double-commit
    // the same bytes; refuse the ambiguity.
    const sorted = [...seen].sort();
    for (let i = 0; i < sorted.length; i += 1) {
      for (let j = i + 1; j < sorted.length; j += 1) {
        if (pathsOverlap(sorted[i], sorted[j])) reasons.push(`overlapping_paths:${sorted[i]}:${sorted[j]}`);
      }
    }
    if (reasons.length > 0) return refuse(reasons);

    const openings: SdOpenings = {};
    const saltValues = new Set<string>();
    const prepared = JSON.parse(canonicalizeStrictJson(payload)) as Obj;
    for (const path of sorted) {
      const provided = Object.hasOwn(salts, path) ? salts[path] : undefined;
      const salt = provided === undefined
        ? crypto.randomBytes(EP_SD_MIN_SALT_BYTES).toString('base64url')
        : provided;
      if (!canonicalBase64url(salt)) { reasons.push(`salt_invalid:${path}`); continue; }
      if (Buffer.from(salt, 'base64url').length < EP_SD_MIN_SALT_BYTES) {
        reasons.push(`salt_too_short:${path}`);
        continue;
      }
      if (saltValues.has(salt)) { reasons.push('salt_reuse'); continue; }
      saltValues.add(salt);
      const { value } = getPath(prepared, path);
      openings[path] = { salt, value };
      setPath(prepared, path, commitSlot(path, salt, value));
    }
    if (reasons.length > 0) return refuse(reasons);

    prepared.disclosure = {
      '@version': EP_SD_VERSION,
      alg: 'sha256',
      paths: sorted,
    };
    return { ok: true, payload: prepared, openings };
  } catch {
    return refuse(['internal_refusal']);
  }
}

// ─── presentation creation (holder side) ─────────────────────────────────────

export interface SdHolderKey {
  privateKey: KeyObject;
  publicKeySpkiB64u: string;
}

/**
 * Build a presentation from a signed disclosure-ready receipt: forward the
 * receipt unchanged, attach the chosen subset of openings, and bind the
 * presentation to one audience and nonce. Refuses to stage a presentation
 * whose openings do not match the signed commitments, so a holder cannot
 * accidentally ship a broken or mismatched disclosure.
 */
export function createSelectiveDisclosurePresentation(
  receipt: unknown,
  openings: SdOpenings,
  disclosePaths: readonly string[],
  binding: SdBinding,
  opts: { holder?: SdHolderKey } = {},
): SdPresentSuccess | SdRefusal {
  try {
    if (!isRecord(receipt) || !isStrictCanonicalJson(receipt)) return refuse(['malformed_receipt']);
    const payload = (receipt as Obj).payload;
    if (!isRecord(payload)) return refuse(['malformed_receipt']);
    const block = payload.disclosure;
    if (!isRecord(block) || block['@version'] !== EP_SD_VERSION || !Array.isArray(block.paths)) {
      return refuse(['missing_disclosure_block']);
    }
    if (!isRecord(binding) || !nonEmptyString(binding.audience) || !nonEmptyString(binding.nonce)
        || !nonEmptyString(binding.created_at) || !RFC3339_OFFSET_RE.test(binding.created_at)) {
      return refuse(['binding_missing']);
    }
    if (!Array.isArray(disclosePaths)) return refuse(['malformed_path_list']);

    const declared = new Set(block.paths.filter((p): p is string => typeof p === 'string'));
    const reasons: string[] = [];
    const disclosed: SdPresentation['disclosed'] = [];
    const seen = new Set<string>();
    for (const path of disclosePaths) {
      if (typeof path !== 'string' || !declared.has(path)) {
        reasons.push(`undeclared_disclosure:${String(path).slice(0, 64)}`);
        continue;
      }
      if (seen.has(path)) { reasons.push(`duplicate_disclosure:${path}`); continue; }
      seen.add(path);
      const opening = isRecord(openings) ? openings[path] : undefined;
      if (!isRecord(opening) || !nonEmptyString(opening.salt)) {
        reasons.push(`opening_missing:${path}`);
        continue;
      }
      const slot = getPath(payload, path);
      if (!slot.found || slot.value !== commitSlot(path, opening.salt as string, opening.value)) {
        reasons.push(`digest_mismatch:${path}`);
        continue;
      }
      disclosed.push({ path, salt: opening.salt as string, value: opening.value });
    }
    if (reasons.length > 0) return refuse(reasons);
    disclosed.sort((a, b) => (a.path < b.path ? -1 : 1));

    const presentation: SdPresentation = {
      '@version': EP_SD_PRESENTATION_VERSION,
      receipt: receipt as Obj,
      disclosed,
      binding: { audience: binding.audience, nonce: binding.nonce, created_at: binding.created_at },
    };
    if (opts.holder) {
      const digest = sdPresentationBindingDigest(presentation.receipt, disclosed, presentation.binding);
      const signature = crypto.sign(null, digest, opts.holder.privateKey).toString('base64url');
      presentation.holder_proof = { public_key: opts.holder.publicKeySpkiB64u, signature };
    }
    return { ok: true, presentation };
  } catch {
    return refuse(['internal_refusal']);
  }
}

// ─── verification (relying-party side) ───────────────────────────────────────

export interface SdVerifyExpectation {
  /** The verifier's OWN audience identifier. Required. */
  audience: string;
  /** The verifier's OWN fresh nonce for this exchange. Required. */
  nonce: string;
  /** Paths that must be readable (plaintext or disclosed) for this purpose. */
  requiredPaths?: readonly string[];
  /** Pin a holder key to require and verify possession (holder_proof). */
  holderPublicKeySpkiB64u?: string;
}

function verifyEd25519OverDigest(signatureB64u: string, digest: Buffer, publicKeySpkiB64u: string): boolean {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki',
    });
    if (keyObject.asymmetricKeyType !== 'ed25519') return false;
    return crypto.verify(null, digest, keyObject, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

/**
 * Verify a selective-disclosure presentation. Fail-closed: every failure is a
 * named refusal in `refusals`; hostile input never throws. All checks are
 * VERIFICATION; acceptance stays with the caller (see decision_scope).
 */
export function verifySelectiveDisclosurePresentation(
  presentation: unknown,
  issuerPublicKeySpkiB64u: string,
  expected: SdVerifyExpectation,
): SdVerifyResult {
  const checks: SdVerifyResult['checks'] = {
    presentation_structure: false,
    receipt_signature: false,
    disclosure_block: false,
    non_redactable_set: false,
    commitments: false,
    openings: false,
    binding: false,
    holder_proof: null,
  };
  const result = (refusals: string[], extras: Partial<SdVerifyResult> = {}): SdVerifyResult => ({
    ok: refusals.length === 0,
    refusals: [...new Set(refusals)].sort(),
    checks,
    caid: null,
    disclosed: null,
    undisclosed_paths: [],
    decision_scope: DECISION_SCOPE,
    ...extras,
  });

  try {
    if (!isRecord(expected) || !nonEmptyString(expected.audience) || !nonEmptyString(expected.nonce)) {
      return result(['verifier_expectation_missing']);
    }

    // 1. Structure gate over the complete presentation.
    if (!isRecord(presentation) || !isStrictCanonicalJson(presentation)) {
      return result(['malformed_presentation']);
    }
    const pres = presentation as Obj;
    if (pres['@version'] !== EP_SD_PRESENTATION_VERSION) return result(['unsupported_version']);
    if (!isRecord(pres.receipt) || !Array.isArray(pres.disclosed) || !isRecord(pres.binding)) {
      return result(['malformed_presentation']);
    }
    checks.presentation_structure = true;

    // 2. Issuer signature over the disclosure-ready receipt: the standard
    //    EP-RECEIPT-v1 check, unchanged — the signed bytes are all present.
    const receiptResult = verifyReceipt(pres.receipt, issuerPublicKeySpkiB64u);
    if (receiptResult.valid !== true) return result(['receipt_signature_invalid']);
    checks.receipt_signature = true;

    const payload = (pres.receipt as Obj).payload as Obj;

    // 3. The signed disclosure block.
    const block = payload.disclosure;
    if (block === undefined) return result(['missing_disclosure_block']);
    if (!isRecord(block) || block['@version'] !== EP_SD_VERSION || block.alg !== 'sha256'
        || !Array.isArray(block.paths) || block.paths.length === 0
        || block.paths.length > MAX_DISCLOSABLE_PATHS
        || !block.paths.every((p): p is string => typeof p === 'string' && validPath(p))
        || [...block.paths].sort().join(' ') !== block.paths.join(' ')
        || new Set(block.paths).size !== block.paths.length) {
      return result(['malformed_disclosure_block']);
    }
    checks.disclosure_block = true;
    const declaredPaths = block.paths as string[];

    // 4. The closed non-redactable set, enforced against the SIGNED block —
    //    an issuer (or forger) that designated a reserved path is refused.
    const reserved = declaredPaths.filter((path) => nonRedactableConflict(path));
    if (reserved.length > 0) {
      return result(reserved.map((path) => `non_redactable_path:${path}`));
    }
    // CAID intact and syntactically valid: this is what makes the redacted
    // presentation still mean "this exact action".
    const caidCandidate = getPath(payload, 'caid').found
      ? getPath(payload, 'caid').value
      : getPath(payload, 'action.caid').value;
    if (caidCandidate === undefined) return result(['missing_caid']);
    if (typeof caidCandidate !== 'string' || !CAID_RE.test(caidCandidate)) {
      return result(['caid_malformed']);
    }
    checks.non_redactable_set = true;
    const caid = caidCandidate;

    // 5. Commitment-slot accounting: every declared path holds a well-formed
    //    slot, and no marker string hides anywhere undeclared.
    const commitmentReasons: string[] = [];
    const slotByPath = new Map<string, string>();
    for (const path of declaredPaths) {
      const slot = getPath(payload, path);
      if (!slot.found || typeof slot.value !== 'string' || !COMMIT_SLOT_RE.test(slot.value)) {
        commitmentReasons.push(`missing_commitment:${path}`);
        continue;
      }
      slotByPath.set(path, slot.value);
    }
    const markerHits: Array<{ path: string; value: string }> = [];
    scanMarkerStrings(payload, '', markerHits);
    for (const hit of markerHits) {
      if (!slotByPath.has(hit.path)) commitmentReasons.push(`undeclared_commitment:${hit.path}`);
    }
    if (commitmentReasons.length > 0) return result(commitmentReasons, { caid });
    checks.commitments = true;

    // 6. Openings: path declared, salt real, digest recomputes. The path
    //    inside the commitment makes a cross-field swap a digest_mismatch.
    const openingReasons: string[] = [];
    const disclosedValues: Record<string, unknown> = {};
    const seenPaths = new Set<string>();
    const seenSalts = new Set<string>();
    for (const entry of pres.disclosed as unknown[]) {
      if (!isRecord(entry) || typeof entry.path !== 'string') {
        openingReasons.push('malformed_disclosure_entry');
        continue;
      }
      const path = entry.path;
      if (!slotByPath.has(path)) { openingReasons.push(`undeclared_disclosure:${path.slice(0, 64)}`); continue; }
      if (seenPaths.has(path)) { openingReasons.push(`duplicate_disclosure:${path}`); continue; }
      seenPaths.add(path);
      const salt = entry.salt;
      if (!nonEmptyString(salt)) { openingReasons.push(`missing_salt:${path}`); continue; }
      if (!canonicalBase64url(salt)) { openingReasons.push(`salt_invalid:${path}`); continue; }
      if (Buffer.from(salt, 'base64url').length < EP_SD_MIN_SALT_BYTES) {
        openingReasons.push(`salt_too_short:${path}`);
        continue;
      }
      if (seenSalts.has(salt)) { openingReasons.push('salt_reuse'); continue; }
      seenSalts.add(salt);
      if (slotByPath.get(path) !== commitSlot(path, salt, entry.value)) {
        openingReasons.push(`digest_mismatch:${path}`);
        continue;
      }
      disclosedValues[path] = entry.value;
    }
    const undisclosedPaths = declaredPaths.filter((path) => !seenPaths.has(path));
    if (openingReasons.length > 0) {
      return result(openingReasons, { caid, undisclosed_paths: undisclosedPaths });
    }
    checks.openings = true;

    // 7. Verifier policy: required fields must be readable for this purpose.
    const requiredReasons: string[] = [];
    for (const path of expected.requiredPaths ?? []) {
      if (typeof path !== 'string' || !validPath(path)) {
        requiredReasons.push(`invalid_path:${String(path).slice(0, 64)}`);
        continue;
      }
      if (Object.hasOwn(disclosedValues, path)) continue;
      const direct = getPath(payload, path);
      const isPlainlyReadable = direct.found
        && !(typeof direct.value === 'string' && direct.value.startsWith(EP_SD_COMMIT_MARKER_PREFIX));
      if (!isPlainlyReadable) requiredReasons.push(`undisclosed_required_field:${path}`);
    }
    if (requiredReasons.length > 0) {
      return result(requiredReasons, { caid, undisclosed_paths: undisclosedPaths });
    }

    // 8. Audience/nonce binding: a presentation bound to someone else's
    //    audience or an unexpected nonce is refused, not partially accepted.
    const binding = pres.binding as Obj;
    const bindingReasons: string[] = [];
    if (!nonEmptyString(binding.audience) || !nonEmptyString(binding.nonce)
        || !nonEmptyString(binding.created_at) || !RFC3339_OFFSET_RE.test(binding.created_at as string)) {
      bindingReasons.push('binding_missing');
    } else {
      if (binding.audience !== expected.audience) bindingReasons.push('binding_audience_mismatch');
      if (binding.nonce !== expected.nonce) bindingReasons.push('binding_nonce_mismatch');
    }
    if (bindingReasons.length > 0) {
      return result(bindingReasons, { caid, undisclosed_paths: undisclosedPaths });
    }
    checks.binding = true;

    // 9. Holder proof: required and pinned, or verified-if-present. Without a
    //    pinned key a verifying holder_proof is VERIFIED, not ACCEPTED.
    const holderProof = pres.holder_proof;
    if (expected.holderPublicKeySpkiB64u !== undefined || holderProof !== undefined) {
      if (!isRecord(holderProof) || !nonEmptyString(holderProof.public_key)
          || !nonEmptyString(holderProof.signature)) {
        return result(['holder_proof_missing'], { caid, undisclosed_paths: undisclosedPaths });
      }
      if (expected.holderPublicKeySpkiB64u !== undefined
          && holderProof.public_key !== expected.holderPublicKeySpkiB64u) {
        return result(['holder_proof_key_mismatch'], { caid, undisclosed_paths: undisclosedPaths });
      }
      const digest = sdPresentationBindingDigest(
        pres.receipt as Obj,
        pres.disclosed as SdPresentation['disclosed'],
        {
          audience: binding.audience as string,
          nonce: binding.nonce as string,
          created_at: binding.created_at as string,
        },
      );
      if (!verifyEd25519OverDigest(holderProof.signature as string, digest, holderProof.public_key as string)) {
        return result(['holder_proof_invalid'], { caid, undisclosed_paths: undisclosedPaths });
      }
      checks.holder_proof = true;
    }

    return result([], { caid, disclosed: disclosedValues, undisclosed_paths: undisclosedPaths });
  } catch {
    return result(['internal_refusal']);
  }
}
