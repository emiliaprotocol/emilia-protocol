import { type AebAdapter, type AebDigest, type AebPinnedProfile } from './aeb-adapter-contract.js';
type Obj = Record<string, any>;
export declare const FIDO_AP2_SOURCE_REVISION = "google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
export declare const FIDO_AP2_EVIDENCE_VERSION = "EP-FIDO-AP2-EVIDENCE-v1";
export declare const FIDO_AP2_AEB_ADAPTER_ID = "fido-ap2:webauthn-human-authorization";
export declare const FIDO_AP2_AEB_ADAPTER_VERSION = "1";
export declare const FIDO_AP2_AEB_CONFIG_VERSION = "EP-FIDO-AP2-AEB-CONFIG-v1";
export declare const FIDO_AP2_AEB_TRUST_ROOT_VERSION = "EP-FIDO-AP2-P256-ROOT-v1";
export declare const FIDO_AP2_CAID_MAPPING_VERSION = "EP-FIDO-AP2-CAID-MAPPING-v1";
export declare const FIDO_AP2_CAID_MAPPER_ID = "mapper:fido-ap2-closed-payment-v1";
export declare const FIDO_AP2_CAID_PROFILE_ID = "profile:fido-ap2-closed-payment-v1";
export declare const FIDO_AP2_ACTION_TYPE = "payment.purchase.1";
export declare const FIDO_AP2_NATIVE_PROTOCOL_ID = "ap2:v0.2-closed-checkout-payment";
export declare const FIDO_AP2_SOURCE_BYTES_DOMAIN = "EP-FIDO-AP2-CANONICAL-TOKEN-v1";
export interface FidoAp2NativeSourceBindingInput {
    /** Exact canonical SdJwtMandate.serialized values returned by AP2 v0.2. */
    checkout_mandate_token: string;
    payment_mandate_token: string;
    /** Disclosure-resolved payloads returned by the same successful native verification. */
    checkout_mandate_payload: unknown;
    payment_mandate_payload: unknown;
}
export interface FidoAp2NativeSourceBinding {
    source_revision: typeof FIDO_AP2_SOURCE_REVISION;
    checkout_mandate_token_digest: AebDigest;
    payment_mandate_token_digest: AebDigest;
    checkout_mandate_payload_digest: AebDigest;
    payment_mandate_payload_digest: AebDigest;
    checkout_hash_algorithm: 'sha-256' | 'sha-384' | 'sha-512';
    native_artifact_digest: AebDigest;
}
/**
 * Commit the exact token bytes, resolved payloads, and checkout hash algorithm
 * accepted by one successful native AP2 verification.
 *
 * Token identity remains byte-exact. Payloads use the strict AEB JSON domain;
 * together the two commitments prevent token/object splicing.
 */
export declare function createFidoAp2NativeSourceBinding(input: FidoAp2NativeSourceBindingInput): FidoAp2NativeSourceBinding;
export declare const FIDO_AP2_CAID_ACTION_DEFINITIONS: readonly Readonly<{
    action_type: "payment.purchase.1";
    required_fields: readonly (Readonly<{
        name: "checkout_mandate_digest";
        type: "digest";
    }> | Readonly<{
        name: "payment_mandate_digest";
        type: "digest";
    }> | Readonly<{
        name: "checkout_payload_jwt_digest";
        type: "digest";
    }> | Readonly<{
        name: "transaction_id";
        type: "string";
    }> | Readonly<{
        name: "amount_minor";
        type: "integer";
    }> | Readonly<{
        name: "currency";
        type: "string";
    }> | Readonly<{
        name: "payee_id";
        type: "string";
    }> | Readonly<{
        name: "payee_name";
        type: "string";
    }> | Readonly<{
        name: "payee_website_digest";
        type: "digest";
    }> | Readonly<{
        name: "pisp_digest";
        type: "digest";
    }> | Readonly<{
        name: "payment_instrument_id";
        type: "string";
    }> | Readonly<{
        name: "payment_instrument_type";
        type: "string";
    }> | Readonly<{
        name: "payment_instrument_description_digest";
        type: "digest";
    }> | Readonly<{
        name: "risk_data_digest";
        type: "digest";
    }> | Readonly<{
        name: "execution";
        type: "enum";
        values: readonly string[];
    }> | Readonly<{
        name: "source_expires_at";
        type: "timestamp";
    }>)[];
    optional_fields: readonly never[];
}>[];
/**
 * Closed descriptor for the native AP2-to-CAID projection implementation.
 *
 * Keep the descriptor separate from its pinned digest so importing the public
 * package barrel never executes AEB hashing while the AEB/evidence-chain
 * module cycle is still being initialized. A conformance test re-derives the
 * literal and refuses descriptor drift.
 */
export declare const FIDO_AP2_CAID_RESOLVER_DESCRIPTOR: Readonly<{
    mapper_id: "mapper:fido-ap2-closed-payment-v1";
    version: "1";
    source_revision: "google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
    projection: "ap2-v0.2-closed-checkout-payment-immediate-v1";
    action_type: "payment.purchase.1";
    suite: "jcs-sha256";
    definitions: readonly Readonly<{
        action_type: "payment.purchase.1";
        required_fields: readonly (Readonly<{
            name: "checkout_mandate_digest";
            type: "digest";
        }> | Readonly<{
            name: "payment_mandate_digest";
            type: "digest";
        }> | Readonly<{
            name: "checkout_payload_jwt_digest";
            type: "digest";
        }> | Readonly<{
            name: "transaction_id";
            type: "string";
        }> | Readonly<{
            name: "amount_minor";
            type: "integer";
        }> | Readonly<{
            name: "currency";
            type: "string";
        }> | Readonly<{
            name: "payee_id";
            type: "string";
        }> | Readonly<{
            name: "payee_name";
            type: "string";
        }> | Readonly<{
            name: "payee_website_digest";
            type: "digest";
        }> | Readonly<{
            name: "pisp_digest";
            type: "digest";
        }> | Readonly<{
            name: "payment_instrument_id";
            type: "string";
        }> | Readonly<{
            name: "payment_instrument_type";
            type: "string";
        }> | Readonly<{
            name: "payment_instrument_description_digest";
            type: "digest";
        }> | Readonly<{
            name: "risk_data_digest";
            type: "digest";
        }> | Readonly<{
            name: "execution";
            type: "enum";
            values: readonly string[];
        }> | Readonly<{
            name: "source_expires_at";
            type: "timestamp";
        }>)[];
        optional_fields: readonly never[];
    }>[];
}>;
export declare const FIDO_AP2_CAID_RESOLVER_DIGEST: AebDigest;
export type FidoAp2SignCountPolicy = 'above-enrollment-and-one-time' | 'not-relied-upon';
/** Project only the pinned AP2 v0.2 closed CheckoutMandate/PaymentMandate subset. */
export declare function projectFidoAp2PaymentAction(input: unknown): Obj;
/** Return the one immutable mapping profile implemented by this bridge. */
export declare function createFidoAp2PinnedProfile(): AebPinnedProfile;
/** Build the fixed bridge. No presenter-controlled constructor options exist. */
export declare function createFidoAp2AebAdapter(): AebAdapter;
export {};
//# sourceMappingURL=fido-ap2-bridge.d.ts.map