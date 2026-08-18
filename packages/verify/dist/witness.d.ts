/**
 * @emilia-protocol/verify — WITNESS COSIGNATURE verification (EP-WITNESS-v1)
 *
 * Step 3 of the transparency layer (see docs/security/TRANSPARENCY-LAYER-DESIGN.md
 * and consistency.js). A transparency-log operator signs its own checkpoint
 * {tree_size, root_hash, log_key_id, ...}. A single operator signature does NOT
 * make a split view (equivocation) detectable: the operator can sign two
 * internally-consistent but divergent heads and show each to a different
 * verifier. An INDEPENDENT WITNESS re-signs the SAME committed checkpoint bytes.
 * When several independent witnesses each cosign whatever head they observed,
 * two verifiers who later gossip their witness cosignatures can detect that the
 * log presented divergent heads at the same tree_size.
 *
 * WHAT A WITNESS COSIGNATURE PROVES
 *   "I, witness <witness_id>, observed a checkpoint claiming this tree_size and
 *    this root_hash under this log_key_id, and I attest to having seen exactly
 *    these committed bytes."
 *
 * WHAT IT DOES *NOT* PROVE (honesty)
 *   - It does NOT vouch for the log's honesty or that the log is append-only. A
 *     witness signs the bytes it was shown; it does not re-derive the tree.
 *   - It does NOT establish CURRENT validity. A cosignature attests to a head as
 *     OBSERVED at cosign time only; currency needs a fresh signed head / online
 *     check, exactly as for the log's own signature.
 *   - A SINGLE witness detects nothing. Equivocation is only detectable when
 *     multiple INDEPENDENT witnesses cosign and their views are later compared
 *     (gossip). requireWitnessQuorum() enforces the "multiple distinct pinned
 *     witnesses agree on ONE head" half of that; cross-view gossip is the
 *     deployment's job.
 *
 * DOMAIN SEPARATION (critical)
 *   The log signs   Ed25519( null, SHA-256( canonicalize(signedCheckpoint) ) ).
 *   A witness signs  Ed25519( null, SHA-256( WITNESS_DOMAIN_TAG || canonicalize(signedCheckpoint) ) ).
 *   `signedCheckpoint` is the checkpoint with its own `log_signature` removed —
 *   i.e. the identical committed bytes the log signed. Prepending the domain tag
 *   to the pre-image means a witness cosignature and a log signature are
 *   computed over DIFFERENT bytes and can never be confused or replayed for one
 *   another, even if (by misconfiguration) the same key were pinned in both
 *   roles. Byte-identical convention used by witness/server.mjs.
 *
 * KEY / HASH ENCODING (matches index.js exactly)
 *   - Public keys: base64url-encoded SPKI DER, verified with crypto.verify(null,…).
 *   - Signatures:  base64url.
 *   - Hashes in the checkpoint: "sha256:<hex>" or bare hex; compared prefix-stripped.
 *
 * FAIL-CLOSED
 *   Every check refuses on missing / malformed / unrecognized input and never
 *   silently passes. An unknown or unpinned witness key refuses. A signature over
 *   different bytes refuses. A cosignature presented for a different checkpoint
 *   (different tree_size / root_hash / log_key_id than the one being verified)
 *   refuses. The k-of-n helper refuses on fewer than k DISTINCT pinned witnesses.
 *
 * This module imports canonicalize() from index.js so the witness and every other
 * signed-material computation in the package share one canonicalization source of
 * truth. It adds NO new canonicalization.
 *
 * @license Apache-2.0
 */
import { type AgilityOptions } from './pq-signature-agility.js';
export declare const WITNESS_VERSION = "EP-WITNESS-v1";
/**
 * Domain-separation tag prepended to the SHA-256 pre-image a witness signs.
 * A UTF-8 label with a trailing 0x00 so it can never be a prefix of the
 * canonical JSON that follows (canonical JSON begins with '{' 0x7b, never 0x00).
 * The log's own signature has NO such prefix, so the two pre-images are disjoint.
 */
export declare const WITNESS_DOMAIN_TAG = "EP-WITNESS-COSIGN-v1\0";
export interface WitnessCheckpoint {
    tree_size?: unknown;
    root_hash?: unknown;
    log_key_id?: unknown;
    [key: string]: unknown;
}
export interface WitnessCosignature {
    witness_id?: unknown;
    signature?: unknown;
    alg?: unknown;
    tree_size?: unknown;
    root_hash?: unknown;
    log_key_id?: unknown;
    [key: string]: unknown;
}
export interface PinnedWitnessKey {
    witness_id?: unknown;
    public_key?: unknown;
    [key: string]: unknown;
}
export declare function witnessSigningDigest(checkpoint: unknown): Buffer | null;
/**
 * Verify a single witness cosignature over a checkpoint.
 *
 * @param {object} checkpoint  the log checkpoint {tree_size, root_hash, log_key_id, ...}.
 *   May or may not still carry `log_signature` — it is stripped before hashing,
 *   so a witness cosignature is over the same committed bytes the log signed.
 * @param {object} cosignature  {
 *     witness_id: string,        // stable id of the cosigning witness
 *     signature: string,         // base64url Ed25519 over witnessSigningDigest(checkpoint)
 *     tree_size?: number,        // OPTIONAL echo of the head the witness cosigned
 *     root_hash?: string,        //   ... used to refuse a cosignature reused for a
 *     log_key_id?: string,       //   different checkpoint (fail-closed when echoed)
 *     alg?: string,              // OPTIONAL, must equal 'EP-WITNESS-v1' when present
 *   }
 * @param {{witness_id: string, public_key: string}} pinnedWitnessKey  the ONE
 *   witness the caller trusts for this cosignature: a stable witness_id plus its
 *   base64url SPKI-DER Ed25519 public key. An unknown / unpinned witness refuses.
 * @returns {{verified: boolean, witness_id: string|null, reason?: string}}
 */
export declare function verifyWitnessCosignature(checkpoint: WitnessCheckpoint | null | undefined, cosignature: WitnessCosignature | null | undefined, pinnedWitnessKey: PinnedWitnessKey | null | undefined): {
    verified: boolean;
    witness_id: string | null;
    reason?: string;
};
/**
 * Require >= k DISTINCT pinned witnesses to have validly cosigned the SAME head.
 *
 * Detects the "not enough independent observers agree on one head" condition:
 * accepts iff at least `k` cosignatures verify, each from a DIFFERENT pinned
 * witness_id, all over the ONE checkpoint passed in. Duplicate witness_ids count
 * ONCE (a single witness cannot satisfy a k-of-n threshold by cosigning twice).
 * Cosignatures that fail verification, name an unpinned witness, or reference a
 * different head are ignored (they do not count toward k) and recorded in
 * `reasons` for diagnostics.
 *
 * HONESTY: this proves k distinct trusted witnesses attest to ONE head. It does
 * NOT by itself detect that the log showed a DIFFERENT head to someone else —
 * that cross-view comparison (gossip) is the deployment's responsibility. This
 * helper is the local, single-view half of the check.
 *
 * @param {object} checkpoint  the ONE checkpoint head all witnesses must have cosigned.
 * @param {object[]} cosignatures  candidate witness cosignatures (see verifyWitnessCosignature).
 * @param {Array<{witness_id:string, public_key:string}>} pinnedWitnessKeys  the set of
 *   trusted witnesses. Entries with a duplicate or missing witness_id are dropped.
 * @param {number} k  threshold; must be an integer >= 1.
 * @returns {{ ok: boolean, met: number, required: number,
 *   witness_ids: string[], reasons: string[] }}
 *   `met` is the number of DISTINCT pinned witnesses that validly cosigned this
 *   head; `witness_ids` lists them. Fail-closed: bad inputs return ok:false.
 */
export declare function requireWitnessQuorum(checkpoint: WitnessCheckpoint | null | undefined, cosignatures: unknown, pinnedWitnessKeys: unknown, k: number): {
    required: number;
    ok: boolean;
    met: number;
    witness_ids: string[];
    reasons: string[];
};
/**
 * Applies the EP-REVOCATION-v2 template (packages/verify/src/revocation.ts)
 * to the witness cosignature. Five moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the cosignature (`signature` string -> `signatures` array), which is a
 *    wire-format change, so it takes a new `alg` marker (EP-WITNESS-v1 ->
 *    EP-WITNESS-v2) rather than an optional field grown on v1. The v1
 *    verifier, verifyWitnessCosignature() above, is untouched and refuses a
 *    v2 cosignature TWO independent ways before any crypto runs: its own
 *    `cosignature.alg !== undefined && cosignature.alg !== WITNESS_VERSION`
 *    check refuses on the alg marker, and its
 *    `typeof cosignature.signature !== 'string'` check refuses on shape,
 *    because a v2 cosignature carries `signatures` (plural) and has no
 *    top-level `signature` string at all. A deployed v1 verifier must never
 *    accept a hybrid cosignature on the strength of the one leg it happens to
 *    understand, and it must not crash; both guards above are what make that
 *    true, independently of each other.
 *
 * 2. SET SHAPE. The v2 cosignature is `{witness_id, alg: WITNESS_V2_VERSION,
 *    required_algorithms: [...], signatures: [{alg,sig,key_id?}, ...],
 *    tree_size?, root_hash?, log_key_id?}` -- `signatures` mirrors
 *    EP-SIG-AGILITY-v1's AgileSignature shape verbatim, one entry per
 *    algorithm, in the registered order. Unlike EP-REVOCATION-v2, the v2
 *    cosignature carries NO per-leg key material of its own: exactly like
 *    v1, a witness's keys (both the Ed25519 half and, now, the ML-DSA-65
 *    half) are pinned entirely out of band via pinnedWitnessKeyV2, never
 *    self-asserted in the cosignature.
 *
 * 3. ANTI-STRIPPING BYTES. witnessSigningDigestV2() is the sibling of
 *    witnessSigningDigest() above: it hashes a NEW, distinct domain tag
 *    (WITNESS_DOMAIN_TAG_V2) prepended to canonicalize(committed checkpoint +
 *    required_algorithms), so a v1 digest and a v2 digest can never collide
 *    even for byte-identical checkpoints, and the required algorithm SET is
 *    baked into what both legs sign. Narrow the set or strip a leg after
 *    signing and the surviving signature no longer verifies, because the
 *    bytes changed. The verifier always recomputes this digest from the
 *    REGISTERED set (WITNESS_V2_REQUIRED_ALGORITHMS) and the checkpoint it
 *    holds -- never from cosignature.required_algorithms, which is checked
 *    structurally but never trusted for what bytes to verify against.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous and completely unmodified.
 *    verifyWitnessCosignatureV2() is a separate, ASYNC entry point (ML-DSA
 *    verification is async), and verifyWitnessCosignatureStatement() routes a
 *    cosignature of either version to its own verifier by inspecting `alg`,
 *    mirroring verifyRevocationStatement().
 *
 * 5. NAMED REFUSALS. verifyWitnessCosignatureV2() returns
 *    {verified, witness_id, reason?} like v1, extended with a
 *    `checks: Record<string,boolean>` object covering the independent gates
 *    (version, algorithm_set, legs_present, key_material,
 *    echoed_head_consistent, signature_set_valid). Nothing throws on
 *    cosignature/checkpoint/key content; crypto calls are wrapped in
 *    try/catch. A missing or unavailable ML-DSA backend surfaces through
 *    verifyAgileSignatureSet's 'pq_backend_unavailable' reason as a named
 *    refusal on signature_set_valid, never a silent pass on the classical leg
 *    alone.
 *
 * HONEST BOUNDARIES. Everything the v1 header says still holds: a v2
 * cosignature proves the witness observed exactly these committed bytes; it
 * does not vouch for the log's honesty, does not establish current validity,
 * and a single witness (of either version) detects no equivocation --
 * requireWitnessQuorum() is deliberately left v1-only and out of scope here
 * (multiple DISTINCT witnesses, not multiple algorithms from one witness).
 */
export declare const WITNESS_V2_VERSION = "EP-WITNESS-v2";
/** The registered required algorithm set, in canonical order. */
export declare const WITNESS_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/**
 * Domain-separation tag for EP-WITNESS-v2, distinct from WITNESS_DOMAIN_TAG
 * (v1) so a v1 and v2 digest over the same checkpoint can never collide, even
 * by misconfiguration. Same trailing-0x00 convention as v1: canonical JSON
 * always begins with '{' (0x7b), never 0x00, so the tag can never be a prefix
 * of the JSON that follows.
 */
export declare const WITNESS_DOMAIN_TAG_V2 = "EP-WITNESS-COSIGN-v2\0";
export interface WitnessV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface WitnessCosignatureV2 {
    witness_id?: unknown;
    alg?: unknown;
    required_algorithms?: unknown;
    signatures?: unknown;
    tree_size?: unknown;
    root_hash?: unknown;
    log_key_id?: unknown;
    [key: string]: unknown;
}
/** A v2 witness pin: BOTH public halves, pinned out of band. */
export interface PinnedWitnessKeyV2 {
    witness_id?: unknown;
    /** Ed25519 base64url SPKI DER. */
    public_key?: unknown;
    /** ML-DSA-65 base64url of the raw 1952-byte public key. */
    pq_public_key?: unknown;
    [key: string]: unknown;
}
export interface WitnessVerifyV2Result {
    verified: boolean;
    witness_id: string | null;
    reason?: string;
    checks: Record<string, boolean>;
}
/**
 * The digest BOTH legs sign for EP-WITNESS-v2: SHA-256 of the v2 domain tag
 * followed by canonicalize(committed checkpoint + required_algorithms), so
 * the algorithm set is cryptographically committed alongside the checkpoint
 * bytes. Recomputed independently by the verifier from the checkpoint it
 * holds and the REGISTERED set -- never from a presented one. Throws if
 * `requiredAlgorithms` is not exactly the registered EP-WITNESS-v2 set
 * (mirrors revocationV2SignedPayload's guard); pass the registered constant
 * itself when reconstructing bytes for comparison against a narrowed claim.
 */
export declare function witnessSigningDigestV2(checkpoint: unknown, requiredAlgorithms?: readonly string[]): Buffer | null;
/**
 * verifyWitnessCosignatureV2 -- FAIL-CLOSED hybrid witness check. Never
 * throws on caller input. Every gating check must be true; any one false
 * yields verified:false, and a v2 cosignature NEVER verifies on one leg
 * alone.
 */
export declare function verifyWitnessCosignatureV2(checkpoint: WitnessCheckpoint | null | undefined, cosignature: WitnessCosignatureV2 | null | undefined, pinnedWitnessKeyV2: PinnedWitnessKeyV2 | null | undefined, options?: AgilityOptions): Promise<WitnessVerifyV2Result>;
/**
 * Route a cosignature of EITHER version to its own verifier. v1 cosignatures
 * get the exact v1 verdict (sync, called through this async wrapper); v2
 * cosignatures get the hybrid check. `pinnedWitnessKeyV2` carries both halves
 * ({witness_id, public_key, pq_public_key}); its {witness_id, public_key}
 * shape is exactly what the v1 verifier expects, so it is reused as-is for
 * the v1 path without a second pin object.
 */
export declare function verifyWitnessCosignatureStatement(checkpoint: WitnessCheckpoint | null | undefined, cosignature: WitnessCosignature | WitnessCosignatureV2 | null | undefined, pinnedWitnessKeyV2: PinnedWitnessKeyV2 | null | undefined, options?: AgilityOptions): Promise<WitnessVerifyV2Result | {
    verified: boolean;
    witness_id: string | null;
    reason?: string;
}>;
export interface WitnessV2Signer {
    /** Ed25519 private key. */
    privateKey: import('crypto').KeyObject;
    /** Ed25519 public key, base64url SPKI DER. */
    publicKeyB64u: string;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    pqSecretKey: Uint8Array | string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
    pqPublicKeyB64u: Uint8Array | string;
}
export interface BuildWitnessCosignatureV2Args {
    checkpoint: WitnessCheckpoint;
    witness_id: string;
    signer: WitnessV2Signer;
    /** ML-DSA-65 FIPS 204 deterministic variant; conformance vectors only. */
    deterministic?: boolean;
}
/**
 * buildWitnessCosignatureV2 -- produce an EP-WITNESS-v2 cosignature over
 * `checkpoint`, signed under BOTH registered algorithms over the ONE digest
 * that COMMITS to the required algorithm set (witnessSigningDigestV2).
 *
 * THROWS rather than emit a half-hybrid cosignature: issuer-side misuse is a
 * programming error, and an unavailable ML-DSA backend makes signAgileSet
 * throw, so a cosignature missing the PQ leg is never produced.
 */
export declare function buildWitnessCosignatureV2({ checkpoint, witness_id: witnessId, signer, deterministic, }: BuildWitnessCosignatureV2Args): Promise<WitnessCosignatureV2>;
//# sourceMappingURL=witness.d.ts.map