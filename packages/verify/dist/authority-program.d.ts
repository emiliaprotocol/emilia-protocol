import { type AgileSigningKey, type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
type VerificationCallback = (context: Readonly<Obj>) => unknown;
export declare const AUTHORITY_PROGRAM_VERSION = "EP-AUTHORITY-PROGRAM-v1";
export declare const AUTHORITY_PROGRAM_DOMAIN = "EP-AUTHORITY-PROGRAM-v1\0";
export declare const AUTHORITY_STAGE_RECEIPT_VERSION = "EP-AUTHORITY-STAGE-RECEIPT-v1";
export declare const AUTHORITY_STAGE_RECEIPT_DOMAIN = "EP-AUTHORITY-STAGE-RECEIPT-v1\0";
export declare const AUTHORITY_PROGRAM_RESULT_VERSION = "EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1";
/** Digest of the exact signed authority-program envelope. */
export declare function authorityProgramDigest(program: unknown): string;
/** Digest of the exact signed immutable stage receipt. */
export declare function authorityStageReceiptDigest(receipt: unknown): string;
/**
 * Derive each stage's immediate predecessor stage IDs from a recursive
 * series/parallel expression. Arbitrary DAG edges are never accepted.
 */
export declare function deriveAuthorityProgramPredecessors(expression: unknown): Record<string, string[]>;
export declare function verifyAuthorityProgram(program: unknown, stageReceipts: unknown, options?: {
    programPin?: Obj;
    stageKeys?: Obj;
    verifyAec?: VerificationCallback;
    verifyAom?: VerificationCallback;
    verifyCapabilityNarrowing?: VerificationCallback;
    verifyParallelAllocation?: VerificationCallback;
    verifyRootActionBinding?: VerificationCallback;
}): Obj;
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to BOTH signed
 * artifact types this module verifies:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, a wire-format change, so each artifact takes a new `@version`
 *    (EP-AUTHORITY-PROGRAM-v1 -> -v2, EP-AUTHORITY-STAGE-RECEIPT-v1 -> -v2).
 *    verifyAuthorityProgram() above is untouched: validProgramEnvelope and
 *    validStageReceipt still require the v1 `@version` markers, so a v2
 *    program or receipt refuses on `invalid_program_envelope` /
 *    `invalid_stage_receipt` BEFORE any signature inspection, and never
 *    throws.
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }). Neither v1 nor v2 embeds public key material in
 *    the proof itself -- verification always looks the key up from the
 *    relying-party-pinned `programPin` / `stageKeys`, exactly as v1 does; v2
 *    only widens each pin to carry BOTH halves (`public_key`, `pq_public_key`).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (signingBytesV2 below, alongside the existing domain tag and
 *    the unsigned body). Drop the ML-DSA leg and narrow `required_algorithms`
 *    and the surviving Ed25519 signature no longer verifies, because the
 *    bytes changed.
 * 4. V1 COMPATIBILITY. v1 programs and receipts keep verifying, unchanged,
 *    through verifyAuthorityProgram (which stays synchronous). v2 verification
 *    is ASYNC (ML-DSA verification is async), so it is a SEPARATE entry point
 *    (verifyAuthorityProgramV2); verifyAuthorityProgramAny() routes on the
 *    program's `@version` for callers holding a mixed bag. The v1 verifier is
 *    never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named `reason`; nothing
 *    throws on caller input (mirroring v1's `failure()` helper). An absent
 *    ML-DSA backend surfaces as a refused signature check, never a skipped
 *    check and never a pass on the classical leg alone.
 *
 * HONEST BOUNDARIES carry over unchanged from v1: this module deliberately has
 * no store, clock, scheduler, transition API, threshold grammar, execution
 * path, revocation mutation, reconciliation, or policy evaluation --
 * `freshness_proven`, `revocation_checked`, and `execution_proven` are always
 * `false`. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * v2 does NOT retroactively protect programs or receipts already issued under
 * v1.
 */
export declare const AUTHORITY_PROGRAM_V2_VERSION = "EP-AUTHORITY-PROGRAM-v2";
export declare const AUTHORITY_STAGE_RECEIPT_V2_VERSION = "EP-AUTHORITY-STAGE-RECEIPT-v2";
export declare const AUTHORITY_PROGRAM_V2_RESULT_VERSION = "EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v2";
/** The registered required algorithm set, in canonical order. */
export declare const AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** v2 pin: BOTH public halves for one signer, keyed the same way v1's pins are. */
export interface AuthorityV2KeyPin {
    public_key: string;
    pq_public_key: string;
}
/** Digest of the exact signed v2 authority-program envelope. */
export declare function authorityProgramDigestV2(program: unknown): string;
/** Digest of the exact signed immutable v2 stage receipt. */
export declare function authorityStageReceiptDigestV2(receipt: unknown): string;
interface AuthorityProgramV2Options {
    programPin?: Obj;
    stageKeys?: Obj;
    verifyAec?: VerificationCallback;
    verifyAom?: VerificationCallback;
    verifyCapabilityNarrowing?: VerificationCallback;
    verifyParallelAllocation?: VerificationCallback;
    verifyRootActionBinding?: VerificationCallback;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}
/** Public, fail-closed hybrid entry point. Never throws on caller input. */
export declare function verifyAuthorityProgramV2(program: unknown, stageReceipts: unknown, options?: AuthorityProgramV2Options): Promise<Obj>;
/** Route a program of EITHER version to its own verifier, on `program['@version']`. */
export declare function verifyAuthorityProgramAny(program: unknown, stageReceipts: unknown, options?: Parameters<typeof verifyAuthorityProgram>[2] & AuthorityProgramV2Options): Promise<Obj>;
/**
 * Sign a v2 program envelope (relying-party issuance helper; not exercised by
 * verification). Throws on issuer misuse; there is no caller/attacker input to
 * fail-close over on the signing side.
 */
export declare function signAuthorityProgramV2(body: Omit<Obj, '@version' | 'proof'>, organizationId: string, keyId: string, signers: AgileSigningKey[], options?: AgilityOptions): Promise<Obj>;
/** Sign a v2 stage receipt. See signAuthorityProgramV2 for the issuance boundary note. */
export declare function signAuthorityStageReceiptV2(body: Omit<Obj, '@version' | 'proof'>, keyId: string, signers: AgileSigningKey[], options?: AgilityOptions): Promise<Obj>;
export {};
//# sourceMappingURL=authority-program.d.ts.map