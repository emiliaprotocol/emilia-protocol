export declare const EG1_VERSION = "EG-1";
/**
 * Mint a GENUINE WebAuthn ECDSA-P256 device signoff over an authorization
 * context — the same structure @emilia-protocol/verify verifyWebAuthnSignoff
 * checks. This is what earns a receipt its class_a tier: a real per-signer
 * assertion, not a self-asserted `outcome` string. Used to build the Class-A and
 * quorum evidence the EG-1 harness embeds so the Gate can CRYPTOGRAPHICALLY
 * credit the tier.
 * @param {{ actionHash?: string, approver?: string, issuedAtMs?: number, nonce?: string, prevContextHash?: string }} [opts]
 */
export declare function mintDeviceSignoff({ actionHash, approver, issuedAtMs, nonce, prevContextHash, }?: {
    actionHash?: string;
    approver?: string;
    issuedAtMs?: number;
    nonce?: string;
    prevContextHash?: string;
}): {
    signoff: {
        '@type': string;
        context: {
            prev_context_hash?: string | undefined;
            ep_version: string;
            context_type: string;
            action_hash: string | undefined;
            policy: string;
            nonce: string;
            approver: string | undefined;
            initiator: string;
            issued_at: string;
            expires_at: string;
        };
        webauthn: {
            authenticator_data: string;
            client_data_json: string;
            signature: string;
        };
        approver_public_key: string;
    };
    approver_public_key: string;
    context: {
        prev_context_hash?: string | undefined;
        ep_version: string;
        context_type: string;
        action_hash: string | undefined;
        policy: string;
        nonce: string;
        approver: string | undefined;
        initiator: string;
        issued_at: string;
        expires_at: string;
    };
};
/**
 * Mint a GENUINE EP-QUORUM-v1 evidence document: N distinct humans, each on a
 * distinct device key, each with a real WebAuthn assertion bound to the SAME
 * action_hash, within a window. verifyQuorum returns valid for it. This is what
 * earns a receipt its `quorum` tier — never a bare {signers,threshold} block.
 * @param {{ actionHash?: string, threshold?: number, approvers?: Array<{ role: string, approver: string }>, issuedAtMs?: number }} [opts]
 */
export declare function mintQuorumEvidence({ actionHash, threshold, approvers, issuedAtMs, }?: {
    actionHash?: string;
    threshold?: number;
    approvers?: Array<{
        role: string;
        approver: string;
    }>;
    issuedAtMs?: number;
}): {
    '@type': string;
    action_hash: string | undefined;
    policy: {
        mode: string;
        required: number;
        approvers: {
            role: string;
            approver: string;
        }[];
        distinct_humans: boolean;
        window_sec: number;
    };
    members: {
        role: string;
        approver_public_key: string;
        signoff: {
            '@type': string;
            context: {
                prev_context_hash?: string | undefined;
                ep_version: string;
                context_type: string;
                action_hash: string | undefined;
                policy: string;
                nonce: string;
                approver: string | undefined;
                initiator: string;
                issued_at: string;
                expires_at: string;
            };
            webauthn: {
                authenticator_data: string;
                client_data_json: string;
                signature: string;
            };
        };
    }[];
};
export declare const EG1_DEFAULT_SELECTOR: Readonly<{
    protocol: "mcp";
    tool: "release_payment";
}>;
export declare const EG1_DEFAULT_ACTION: Readonly<{
    action_type: "payment.release";
    amount_usd: 40000;
    currency: "USD";
    payment_instruction_id: "pi_eg1_40000";
    beneficiary_account_hash: "sha256:eg1-beneficiary";
}>;
export declare const EG1_CHECKS: readonly {
    id: string;
    title: string;
}[];
/**
 * Create an EG-1 harness: a throwaway issuer key + a receipt minter for the
 * scenarios. Configure the subject's gate to trust `publicKey` for the run.
 */
export declare function createEg1Harness({ now, action, idPrefix, }?: {
    now?: () => number;
    action?: Record<string, unknown>;
    idPrefix?: string;
}): {
    publicKey: string;
    approverKeys: {
        'ep:key:eg1:class-a': {
            approver_id: string;
            public_key: string;
            key_class: string;
        };
        'ep:key:eg1:class-a-2': {
            approver_id: string;
            public_key: string;
            key_class: string;
        };
        'ep:key:eg1:controller': {
            approver_id: string;
            public_key: string;
            key_class: string;
        };
    };
    quorumPolicy: {
        mode: string;
        required: number;
        distinct_humans: boolean;
        window_sec: number;
        approvers: {
            role: string;
            approver: string;
        }[];
    };
    mint: ({ outcome, quorum, fakeQuorum, tamper, extra, }?: {
        outcome?: "allow" | "allow_with_signoff";
        quorum?: {
            threshold?: number;
            signers?: any[];
        } | null;
        fakeQuorum?: boolean;
        tamper?: Record<string, any> | null;
        extra?: Record<string, any>;
    }) => {
        '@version': string;
        payload: {
            receipt_id: string;
            subject: string;
            issuer: string;
            created_at: string;
            claim: Record<string, any>;
            quorum?: any;
            assurance_proof?: any;
            signoff?: any;
            approver_public_key?: string;
        };
        signature: {
            algorithm: string;
            value: string;
        };
    };
    action: Record<string, unknown>;
    actionHash: string;
    now: () => number;
    rpId: string;
    allowedOrigins: string[];
};
/**
 * Adapt an @emilia-protocol/gate instance into an EG-1 `invoke`. The gate must
 * have been built trusting the harness public key. Uses gate.run() so the
 * execution proof + reliance packet are produced on the allowed path.
 */
export declare function makeGateInvoke(gate: any, { selector, action }?: {
    selector?: Readonly<{
        protocol: "mcp";
        tool: "release_payment";
    }> | undefined;
    action?: Readonly<{
        action_type: "payment.release";
        amount_usd: 40000;
        currency: "USD";
        payment_instruction_id: "pi_eg1_40000";
        beneficiary_account_hash: "sha256:eg1-beneficiary";
    }> | undefined;
}): ({ receipt, observedAction }: {
    receipt: any;
    observedAction: any;
}) => Promise<{
    allowed: boolean;
    status: any;
    reason: any;
    decisionHash?: undefined;
    execution?: undefined;
    packet?: undefined;
} | {
    allowed: boolean;
    status: number;
    reason: any;
    decisionHash: any;
    execution: any;
    packet: any;
}>;
/**
 * Drive a subject through the eight EG-1 checks and return a JSON report.
 * @param {object} [o]
 * @param {(scenario:object)=>Promise<object>} [o.invoke] the integration under test
 * @param {object} [o.harness] from createEg1Harness()
 * @param {object} [o.action] the high-risk action (defaults to the harness action)
 */
export declare function runEg1({ invoke, harness, action, }?: {
    invoke?: (scenario: {
        receipt: any;
        observedAction: any;
    }) => Promise<{
        allowed: boolean;
        status?: number | null;
        reason?: string | null;
        decisionHash?: string | null;
        execution?: {
            authorizes_decision?: string | null;
        } | null;
        packet?: {
            verdict?: string | null;
        } | null;
    }>;
    harness?: ReturnType<typeof createEg1Harness>;
    action?: Record<string, any>;
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: number;
        total: number;
    };
    checks: any[];
    generated_at: string;
}>;
declare const _default: {
    EG1_VERSION: string;
    EG1_CHECKS: readonly {
        id: string;
        title: string;
    }[];
    EG1_DEFAULT_ACTION: Readonly<{
        action_type: "payment.release";
        amount_usd: 40000;
        currency: "USD";
        payment_instruction_id: "pi_eg1_40000";
        beneficiary_account_hash: "sha256:eg1-beneficiary";
    }>;
    EG1_DEFAULT_SELECTOR: Readonly<{
        protocol: "mcp";
        tool: "release_payment";
    }>;
    createEg1Harness: typeof createEg1Harness;
    makeGateInvoke: typeof makeGateInvoke;
    runEg1: typeof runEg1;
    mintDeviceSignoff: typeof mintDeviceSignoff;
    mintQuorumEvidence: typeof mintQuorumEvidence;
};
export default _default;
//# sourceMappingURL=eg1-conformance.d.ts.map