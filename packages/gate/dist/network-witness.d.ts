/**
 * Independent, privacy-minimized observation evidence for EMILIA Gate.
 *
 * A network witness is deliberately NOT an enforcement point. It can prove a
 * pinned sensor observed bytes associated with an action digest at a named
 * capture point. It cannot prove the action was authorized, blocked, executed,
 * or physically completed. Keeping that boundary in the artifact prevents a
 * passive TAP from being marketed as a firewall.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const NETWORK_WITNESS_VERSION = "EP-GATE-NETWORK-WITNESS-v1";
export declare const NETWORK_WITNESS_V2_VERSION = "EP-GATE-NETWORK-WITNESS-v2";
export declare const NETWORK_WITNESS_ACCEPTANCE_VERSION = "EP-GATE-NETWORK-WITNESS-ACCEPTANCE-v1";
export declare const NETWORK_WITNESS_ACCEPTANCE_V2_VERSION = "EP-GATE-NETWORK-WITNESS-ACCEPTANCE-v2";
export declare const NETWORK_WITNESS_DOMAIN = "EP-GATE-NETWORK-WITNESS-v1\0";
export declare const NETWORK_WITNESS_V2_DOMAIN = "EP-GATE-NETWORK-WITNESS-v2\0";
/** The registered required algorithm set for the hybrid witness, canonical order. */
export declare const NETWORK_WITNESS_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export declare const NETWORK_WITNESS_EVENTS: readonly string[];
type NetworkWitnessChecks = {
    shape: boolean;
    pin: boolean;
    signature: boolean;
    action_binding: boolean;
    freshness: boolean;
    config_binding: boolean;
};
type NetworkWitnessVerifyFailure = {
    verified: false;
    accepted: false;
    reason: string;
    checks: NetworkWitnessChecks;
    statement_digest?: undefined;
    stream_id?: undefined;
    sequence?: undefined;
    action_digest?: undefined;
    event?: undefined;
    observed_at?: undefined;
    witness_id?: undefined;
    capture_point_id?: undefined;
    limitation?: undefined;
};
type NetworkWitnessVerifySuccess = {
    verified: true;
    accepted: true;
    reason: null;
    statement_digest: string;
    stream_id: string;
    sequence: number;
    action_digest: string;
    event: string;
    observed_at: string;
    witness_id: string;
    capture_point_id: string;
    checks: NetworkWitnessChecks;
    limitation: string;
};
type NetworkWitnessVerifyResult = NetworkWitnessVerifyFailure | NetworkWitnessVerifySuccess;
type NetworkWitnessVerifyOptions = {
    pinnedWitnesses?: any[];
    expectedActionDigest?: string;
    expectedEvent?: string;
    now?: number;
    maxAgeSec?: number;
    maxFutureSkewSec?: number;
};
type NetworkWitnessAcceptanceOptions = {
    allowEphemeralStore?: boolean;
    expectedStatementDigest?: string;
    expectedActionDigest?: string;
    expectedEvent?: string;
    now?: number;
    maxAgeSec?: number;
    maxFutureSkewSec?: number;
};
interface NetworkWitnessSequenceStore {
    durable: boolean;
    advance: (streamId: string, sequence: number, statementDigest: string) => Promise<{
        accepted: boolean;
        reason: string | null;
    }>;
}
type NetworkWitnessAcceptOptions = NetworkWitnessVerifyOptions & {
    sequenceStore?: NetworkWitnessSequenceStore;
    allowEphemeralStore?: boolean;
};
export declare function networkWitnessDigest(statement: any): string;
/** Duplicate-key-safe parser for an untrusted serialized witness artifact. */
export declare function parseNetworkWitnessStatement(raw: any, { maxBytes }?: {
    maxBytes?: number | undefined;
}): any;
/** Create a signed observation. The public key is intentionally not embedded. */
export declare function signNetworkWitnessStatement(input: any, privateKey: any): Readonly<{
    signature: Readonly<{
        algorithm: "Ed25519";
        key_id: any;
        statement_digest: string;
        signature_b64u: string;
    }>;
    '@version': string;
    witness: {
        id: any;
        key_id: any;
        capture_point_id: any;
    };
    observation: {
        byte_count?: any;
        flow_digest?: any;
        sequence: any;
        observed_at: any;
        event: any;
        direction: any;
        action_digest: any;
    };
    deployment: {
        attestation_ref?: any;
        config_digest: any;
    };
    privacy: {
        payload_captured: boolean;
    };
    limitations: string[];
}>;
/**
 * Offline signature and context verification. This function never throws on a
 * presenter-controlled statement. Sequence consumption is a separate online
 * operation performed by acceptNetworkWitnessStatement.
 */
export declare function verifyNetworkWitnessStatement(statement: any, options?: NetworkWitnessVerifyOptions): NetworkWitnessVerifyResult;
export declare function createMemoryWitnessSequenceStore(): {
    durable: boolean;
    advance(streamId: any, sequence: any, statementDigest: any): Promise<{
        accepted: boolean;
        reason: string;
    } | {
        accepted: boolean;
        reason: null;
    }>;
    snapshot(): any[];
};
/**
 * Validate an ingestion result supplied through a relying-party-trusted option.
 * This does not authenticate presenter-controlled JSON; callers must never move
 * an untrusted bundle field into this trust channel.
 */
export declare function validateTrustedNetworkWitnessAcceptance(result: any, options?: NetworkWitnessAcceptanceOptions): {
    verified: boolean;
    accepted: boolean;
    consumed: boolean;
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    consumed: boolean;
    reason: null;
    acceptance_version: string;
    statement_digest: any;
    stream_id: any;
    sequence: any;
    action_digest: any;
    event: any;
    observed_at: any;
    witness_id: any;
    capture_point_id: any;
    sequence_store_durable: boolean;
};
/** Verify and atomically advance a witness stream for online ingestion. */
export declare function acceptNetworkWitnessStatement(statement: any, options?: NetworkWitnessAcceptOptions): Promise<any>;
type NetworkWitnessV2VerifyOptions = NetworkWitnessVerifyOptions & AgilityOptions;
type NetworkWitnessV2AcceptOptions = NetworkWitnessV2VerifyOptions & {
    sequenceStore?: NetworkWitnessSequenceStore;
    allowEphemeralStore?: boolean;
};
interface NetworkWitnessV2Keys {
    edPrivateKey: crypto.KeyLike;
    /** ML-DSA-65 raw secret key (4032 bytes) as Uint8Array or base64url string. */
    pqPrivateKey: Uint8Array | string;
}
export declare function networkWitnessV2Digest(statement: any): string;
/**
 * Create a hybrid signed observation. Reference: "PATTERN: the reference hybrid
 * migration" in docs/protocol/pq-hybrid-program.md. VERSION BUMP, not a field
 * bump; the required algorithm set is committed into the signed bytes; ASYNC
 * because ML-DSA signing is async. The public keys are intentionally not
 * embedded (identified-but-not-trusted; the relying party pins both halves).
 */
export declare function signNetworkWitnessStatementV2(input: any, keys: NetworkWitnessV2Keys, options?: AgilityOptions): Promise<Readonly<{
    proof: Readonly<{
        profile: "EP-GATE-NETWORK-WITNESS-v2";
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        key_id: any;
        statement_digest: string;
        signatures: (import("@emilia-protocol/verify/pq-signature-agility").AgileSignature | undefined)[];
    }>;
    '@version': string;
    witness: {
        id: any;
        key_id: any;
        capture_point_id: any;
    };
    observation: {
        byte_count?: any;
        flow_digest?: any;
        sequence: any;
        observed_at: any;
        event: any;
        direction: any;
        action_digest: any;
    };
    deployment: {
        attestation_ref?: any;
        config_digest: any;
    };
    privacy: {
        payload_captured: boolean;
    };
    limitations: string[];
}>>;
/**
 * Offline hybrid signature and context verification. FAIL-CLOSED: never throws
 * on a presenter-controlled statement, and a v2 statement NEVER verifies on one
 * leg alone. Both legs verify over bytes rebuilt from the PRESENTED body and the
 * REGISTERED algorithm set, under the PINNED Ed25519 + ML-DSA-65 keys. See
 * "PATTERN: the reference hybrid migration" in docs/protocol/pq-hybrid-program.md.
 */
export declare function verifyNetworkWitnessStatementV2(statement: any, options?: NetworkWitnessV2VerifyOptions): Promise<any>;
/** Verify and atomically advance a witness stream for a hybrid (v2) statement. */
export declare function acceptNetworkWitnessStatementV2(statement: any, options?: NetworkWitnessV2AcceptOptions): Promise<any>;
declare const _default: {
    NETWORK_WITNESS_VERSION: string;
    NETWORK_WITNESS_V2_VERSION: string;
    NETWORK_WITNESS_ACCEPTANCE_VERSION: string;
    NETWORK_WITNESS_ACCEPTANCE_V2_VERSION: string;
    NETWORK_WITNESS_EVENTS: readonly string[];
    parseNetworkWitnessStatement: typeof parseNetworkWitnessStatement;
    networkWitnessDigest: typeof networkWitnessDigest;
    networkWitnessV2Digest: typeof networkWitnessV2Digest;
    signNetworkWitnessStatement: typeof signNetworkWitnessStatement;
    verifyNetworkWitnessStatement: typeof verifyNetworkWitnessStatement;
    signNetworkWitnessStatementV2: typeof signNetworkWitnessStatementV2;
    verifyNetworkWitnessStatementV2: typeof verifyNetworkWitnessStatementV2;
    acceptNetworkWitnessStatement: typeof acceptNetworkWitnessStatement;
    acceptNetworkWitnessStatementV2: typeof acceptNetworkWitnessStatementV2;
    validateTrustedNetworkWitnessAcceptance: typeof validateTrustedNetworkWitnessAcceptance;
    createMemoryWitnessSequenceStore: typeof createMemoryWitnessSequenceStore;
};
export default _default;
//# sourceMappingURL=network-witness.d.ts.map