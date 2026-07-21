/**
 * EMILIA Gate — signer-roster sync from an enterprise IdP (EP-GATE-ROSTER-v1).
 *
 * The boring key story: WHO may approve is an HR fact, not a crypto fact. This
 * module turns a SCIM-like IdP export into a versioned signer roster and
 * reconciles a key registry (key-registry.js) against it, so a deprovisioned
 * employee STOPS being an acceptable approver on the next sync. Fail closed:
 *   - only `active === true` users' keys are ever pinned; anything else
 *     (false, missing, truthy-but-not-boolean) never pins;
 *   - a user absent from the import — offboarded, or silently dropped by a
 *     broken IdP export — has every previously pinned key revoked;
 *   - a kid claimed by two principals (or carrying two different key
 *     materials) is CONTESTED: it pins nothing and is revoked if present;
 *   - an import that would leave ZERO active signers requires an explicit
 *     `allowEmpty` acknowledgment, so an empty/broken IdP response cannot
 *     silently mass-revoke every approver.
 *
 * importRoster/diffRoster are pure (inputs in, artifact out; `importedAt` is
 * the caller-supplied clock). applyRosterToRegistry mutates the given registry
 * through its real API: key-registry CAN express revocation (`revoke(kid, at)`,
 * hard and fail-closed), so reconciliation performs it directly and the
 * returned `revoked` list is the exact set of revocations performed.
 */
export declare const ROSTER_VERSION = "EP-GATE-ROSTER-v1";
/**
 * Import a SCIM-like IdP user export into a signer roster.
 * @param {Array<{id:string, userName:string, active:boolean, emails?:any, keys?:Array<{kid:string, publicKey:string}>}>} idpUsers
 * @param {object} [o]
 * @param {string} [o.source]        IdP provenance, e.g. 'scim:okta:acme' (required)
 * @param {string|number} [o.importedAt]  import time (ISO or ms); the caller's clock
 * @param {boolean} [o.allowEmpty=false]  acknowledge an import with zero active signers
 * @returns {{version:string, source:string, imported_at:string, signers:Array<{principal:string, kid:string, publicKey:string, active:boolean}>, integrity_warnings:object[]}}
 */
export declare function importRoster(idpUsers: any, { source, importedAt, allowEmpty, }?: {
    source?: string;
    importedAt?: string | number;
    allowEmpty?: boolean;
}): {
    version: string;
    source: string;
    imported_at: string;
    signers: {
        principal: string;
        kid: string;
        publicKey: string;
        active: boolean;
    }[];
    integrity_warnings: Record<string, any>[];
};
/**
 * Diff two rosters at the principal level.
 * `removed`/`deactivated` carry the PREVIOUS roster's kids — the revocation
 * candidates; `added` carries the next roster's kids.
 * @returns {{added:Array<{principal:string,kids:string[]}>, removed:Array<{principal:string,kids:string[]}>, deactivated:Array<{principal:string,kids:string[]}>}}
 */
export declare function diffRoster(previous: any, next: any): {
    added: {
        principal: string;
        kids: string[];
    }[];
    removed: {
        principal: string;
        kids: string[];
    }[];
    deactivated: {
        principal: string;
        kids: string[];
    }[];
};
/**
 * Reconcile a key registry (createKeyRegistry) against a roster:
 *   - PIN each ACTIVE, uncontested signer's key not already present;
 *   - REVOKE every registry kid not owned by an active roster signer — absent
 *     or inactive means deprovisioned. The registry passed here must therefore
 *     be DEDICATED to roster-managed approver keys.
 * key-registry's API DOES express revocation (revoke(kid, at) — hard,
 * fail-closed), so revocations are performed directly; `revoked` is the exact
 * set performed, returned for the caller's evidence trail.
 * A kid the registry has EVER revoked is never re-pinned (a rehire gets a new
 * key; revoked key material stays dead).
 * @param {object} roster    an EP-GATE-ROSTER-v1 roster
 * @param {object} registry  createKeyRegistry() instance (add/revoke/status)
 * @param {object} [o]
 * @param {string|number} [o.revokedAt=roster.imported_at]  revocation timestamp
 * @returns {{pinned:Array<{principal:string,kid:string}>, already_pinned:string[], revoked:Array<{kid:string,revoked_at:string|number,reason:string}>, refused:Array<{principal:string,kid:string,reason:string}>}}
 */
export declare function applyRosterToRegistry(roster: any, registry: any, { revokedAt }?: {
    revokedAt?: string | number;
}): {
    pinned: {
        principal: string;
        kid: string;
    }[];
    already_pinned: string[];
    revoked: {
        kid: string;
        revoked_at: string | number;
        reason: string;
    }[];
    refused: {
        principal: string;
        kid: string;
        reason: string;
    }[];
};
declare const _default: {
    ROSTER_VERSION: string;
    importRoster: typeof importRoster;
    diffRoster: typeof diffRoster;
    applyRosterToRegistry: typeof applyRosterToRegistry;
};
export default _default;
//# sourceMappingURL=roster.d.ts.map