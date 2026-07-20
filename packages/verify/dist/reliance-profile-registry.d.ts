import { RELIANCE_PROFILE_VERSION } from './reliance.js';
type Obj = Record<string, any>;
interface RegistryOptions {
    pinnedRegistryKeys?: Obj[];
    expectProfileId?: string;
    expectMinEpoch?: number;
}
export declare const PROFILE_REGISTRY_VERSION = "EP-RELIANCE-PROFILE-REGISTRY-v1";
export declare const PROFILE_REGISTRY_DOMAIN = "EP-RELIANCE-PROFILE-REGISTRY-v1\0";
/** Digest of the signed entry body, excluding the signature envelope. */
export declare function profileRegistryEntryDigest(entry: Obj): string;
/**
 * Sign a reliance profile into a registry entry. `privateKey` is a Node
 * Ed25519 KeyObject held by the REGISTRAR (never in this repo).
 * @returns {object} the signed EP-RELIANCE-PROFILE-REGISTRY-v1 entry
 */
export declare function signRelianceProfileEntry({ registry_id, profile_id, profile, registry_epoch, issued_at }: Obj, privateKey: any): Obj;
/**
 * Verify a registry entry against pinned registrar keys.
 * @param {object} entry
 * @param {object} [opts]
 * @param {Array<{registry_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectProfileId]
 * @param {number} [opts.expectMinEpoch]
 * @returns {{verified:boolean, accepted:boolean, profile:(object|null), checks:object, reason?:string, entry_digest?:string, key_id?:string, registry_id?:string, profile_id?:string, registry_epoch?:number}}
 */
export declare function verifyRelianceProfileEntry(entry: Obj, opts?: RegistryOptions): {
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    key_id?: undefined;
    registry_id?: undefined;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: any;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    key_id: string;
    registry_id: string;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: any;
    checks: Record<string, boolean>;
    key_id: string;
    registry_id: string;
    profile_id: any;
    registry_epoch: any;
    entry_digest: string;
    reason?: undefined;
};
export { RELIANCE_PROFILE_VERSION };
//# sourceMappingURL=reliance-profile-registry.d.ts.map