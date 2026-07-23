import { type AebAdapter } from './aeb-adapter-contract.js';
export declare const AEB_NATIVE_CAID_MAPPING_VERSION = "AEB-NATIVE-CAID-MAPPING-v1";
export declare const AEB_NATIVE_CAID_MAPPER_ID = "mapper:aeb-native-add-action-type-v1";
export declare const AGENTROA_AEB_ADAPTER_ID = "native:agentroa";
export declare const AGENTROA_AEB_ADAPTER_VERSION = "1";
export declare const AGENTROA_AEB_CONFIG_VERSION = "AEB-AGENTROA-CONFIG-v1";
export declare const AGENTROA_AEB_TRUST_ROOT_VERSION = "AEB-AGENTROA-ED25519-ROOT-v1";
export declare const ORPRG_AEB_ADAPTER_ID = "native:orprg-json-jcs";
export declare const ORPRG_AEB_ADAPTER_VERSION = "1";
export declare const ORPRG_AEB_CONFIG_VERSION = "AEB-ORPRG-CONFIG-v1";
export declare const ORPRG_AEB_TRUST_ROOT_VERSION = "AEB-ORPRG-ED25519-ROOT-v1";
/** Build the fixed AgentROA native adapter. All mutable policy comes from AEB pins. */
export declare function createAgentRoaAebAdapter(): AebAdapter;
/**
 * Build the fixed ORPRG native adapter.
 *
 * Native inspection can establish VERIFIED/ACCEPTED evidence, but never final
 * ORPRG ALLOW. Gate must atomically reserve and consume the adapter's native
 * replay_unit before execution.
 */
export declare function createOrprgAebAdapter(): AebAdapter;
//# sourceMappingURL=aeb-native-adapters.d.ts.map