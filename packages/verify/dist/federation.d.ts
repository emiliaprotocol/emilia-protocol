/**
 * @emilia-protocol/verify — Federation (PIP-006)
 *
 * Operator-B cross-operator verification client.
 *
 * PIP-006 defines the minimal contract that lets an EP-RECEIPT-v1 issued by
 * Operator A be verified by an independent Operator B using only A's published
 * discovery surfaces — no shared database, no central authority, no trust in
 * A's policy decisions. This module is the relying-party (Operator B) side of
 * that contract.
 *
 * Cross-operator semantics (PIP-006 §"Cross-operator semantics"). Given a
 * receipt from Operator A, Operator B MUST:
 *   1. Resolve A's verification key from A's /.well-known/ep-keys.json
 *      (current key, or a historical key if the receipt predates a rotation).
 *   2. Verify the Ed25519 signature over the canonical receipt payload.
 *   3. Confirm the receipt is not in A's revocation set.
 *   4. Apply B's *local* trust policy to the verified receipt.
 *
 * This module performs steps 1–3 and returns the evidence, and it enforces the
 * decisive part of step 4: a receipt is only ever `accepted` when the relying
 * party has independently, out-of-band, pinned the issuing operator.
 *
 * TRUST ANCHOR — fail closed. `verified` and `accepted` are DIFFERENT verdicts:
 *   - `verified` = the signature checks out against a key the receipt's own
 *     discovery surface advertises. This proves the payload was signed by
 *     whoever controls `signature.signer`'s key — nothing more.
 *   - `accepted` = the relying party trusts that signer. This decision MUST be
 *     anchored in a caller-supplied, out-of-band trust source (a pinned issuer
 *     allowlist and/or an expectedSigner and/or a pinned key set). It is NEVER
 *     derived solely from fields the receipt carries.
 *
 * The receipt-carried `signature.signer` and `signature.key_discovery` are
 * ATTACKER-CONTROLLED. An attacker can mint a receipt with their own key, host
 * a matching ep-keys.json at a URL they control, and point key_discovery there.
 * Such a receipt will `verify` (its signature is internally consistent) but it
 * must NEVER `accept` unless the relying party has already pinned that issuer.
 *
 * PINNING THE ID IS NOT ENOUGH — PIN THE KEY SOURCE. A bare signer-id pin does
 * not authenticate WHERE the verifying key comes from. The receipt still names
 * the discovery URL, so an attacker who sets `signature.signer` to a pinned id
 * and points `key_discovery` at their own ep-keys.json (advertising THEIR key
 * under the pinned id) would otherwise verify-and-accept — laundering trust
 * through a pinned string. To close this, a pin MUST bind the key SOURCE for
 * that signer: an expected discovery origin/URL and/or a pinned public key. A
 * receipt-supplied key_discovery is honored ONLY when its origin matches what
 * the relying party pinned for that signer (online), and a matched key is
 * accepted ONLY when it is the pinned key, if one was pinned (online + offline).
 * A caller-supplied opts.keyDiscoveryUrl is the relying party's OWN choice and
 * needs no such origin match. A receipt-carried key_discovery URL is at most a
 * *hint*: it is only fetched when the signer is pinned AND its origin is bound,
 * and every such fetch is routed through an SSRF guard (see assertSafeFetchUrl).
 *
 * "Federation enables receipt portability. It does not enable trust
 * laundering." — PIP-006.
 *
 * Zero runtime dependencies. Works fully offline when the caller supplies the
 * discovery document and revocation set. Online verification requires a
 * caller-provided resolver + pinned transport boundary; a plain injected or
 * global fetch cannot prevent DNS rebinding and is never treated as safe.
 *
 * @license Apache-2.0
 */
type Obj = Record<string, any>;
interface FederationStatusVerifierContext {
    receiptId: string;
    signer: string | null;
    verifyUrl: string;
}
interface FederationStatusVerifierResult {
    authenticated?: unknown;
    target_bound?: unknown;
    fresh?: unknown;
    revoked?: unknown;
}
interface FederationPinnedFetchContext {
    hostname: string;
    approvedAddresses: readonly string[];
}
interface FederationPinnedFetchResult {
    response: any;
    connectedAddress: string;
}
interface FederationNetworkBoundary {
    resolveAddresses: (hostname: string, context: {
        signal?: AbortSignal;
    }) => readonly string[] | Promise<readonly string[]>;
    fetchPinned: (url: string, init: RequestInit, context: FederationPinnedFetchContext) => FederationPinnedFetchResult | Promise<FederationPinnedFetchResult>;
}
interface FederationOpts {
    revokedReceiptIds?: Set<string> | string[];
    expectedSigner?: string;
    trustedIssuers?: any;
    /** @deprecated Plain fetch cannot enforce DNS resolution pinning and is rejected online. */
    fetchImpl?: any;
    networkBoundary?: FederationNetworkBoundary;
    timeoutMs?: number;
    keyDiscoveryUrl?: string;
    verifyUrlBase?: string;
    statusVerifier?: (status: unknown, context: FederationStatusVerifierContext) => FederationStatusVerifierResult | Promise<FederationStatusVerifierResult>;
}
interface FederationResult {
    accepted: boolean;
    verified: boolean;
    revoked: boolean;
    trusted: boolean;
    signer: string | null;
    keyMatched: 'current' | 'historical' | null;
    checks: Record<string, boolean>;
    error?: string;
    fetched?: Obj;
    revocation_confirmed?: boolean;
    revocation_status?: string;
}
/** @typedef {import('./index.js').IssuerPin} IssuerPin */
/**
 * Resolve the candidate verification keys an operator advertises for a signer.
 *
 * An ep-keys.json discovery document advertises a `keys` map of currently-valid
 * signing keys and, for rotation safety (PIP-006 §"Security considerations" →
 * Key rotation), an optional `historical_keys` map of retired-but-still-
 * verifiable keys. A receipt signed before a rotation must remain verifiable,
 * so we return current keys first and historical keys after, in that order.
 *
 * @param {object} discoveryDoc - parsed /.well-known/ep-keys.json
 * @param {string} signerId - the issuing operator's entity_id (receipt.signature.signer)
 * @returns {Array<{ public_key: string, status: 'current'|'historical', algorithm: string, retired_at?: string }>}
 */
export declare function resolveOperatorKeys(discoveryDoc: Obj, signerId: string): Array<{
    public_key: string;
    status: 'current' | 'historical';
    algorithm: string;
    retired_at?: string;
}>;
/**
 * Verify a federated receipt fully offline.
 *
 * The caller supplies the issuing operator's discovery document (its
 * ep-keys.json) and, optionally, that operator's revocation set. No network
 * access is performed. This is the deterministic core that the online path and
 * the conformance harness both build on.
 *
 * TRUST IS OUT-OF-BAND. `accepted` is only ever true when the caller has pinned
 * the issuing operator via `opts.trustedIssuers` and/or `opts.expectedSigner`.
 * With no pin supplied, a cryptographically-`verified` receipt is still
 * `accepted: false` — the receipt's own `signature.signer` can be anything an
 * attacker chooses, so it can never, by itself, establish trust.
 *
 * @param {object} receipt - EP-RECEIPT-v1 document. MUST carry
 *   `signature.signer` (issuing operator entity_id) per PIP-006.
 * @param {object} discoveryDoc - the issuing operator's parsed ep-keys.json
 * @param {object} [opts]
 * @param {Set<string>|string[]} [opts.revokedReceiptIds] - operator A's revocation set
 * @param {string} [opts.expectedSigner] - if set, the receipt's signer MUST equal this
 *   (this is itself a pin: matching it authorizes acceptance)
 * @param {Set<string>|string[]|Record<string,IssuerPin>} [opts.trustedIssuers] -
 *   out-of-band allowlist of federation issuer entity_ids the relying party
 *   trusts. Acceptance REQUIRES the signer to be in this set (or to equal
 *   expectedSigner). Entries may be bare id strings, or an object map from
 *   signer id → pin binding ({ key_discovery, keyDiscoveryOrigin, publicKey,
 *   publicKeys }). A pin binding pins the KEY SOURCE, not just the id: when a
 *   pinned public key is supplied here, the matched verifying key MUST be one
 *   of the pinned keys or acceptance fails closed.
 * @returns {{
 *   accepted: boolean,
 *   verified: boolean,
 *   revoked: boolean,
 *   trusted: boolean,
 *   signer: string|null,
 *   keyMatched: 'current'|'historical'|null,
 *   checks: object,
 *   error?: string,
 * }}
 */
export declare function verifyFederatedReceiptOffline(receipt: Obj, discoveryDoc: Obj, opts?: FederationOpts): FederationResult;
declare function pinnedPublicKeysFor(signer: string, opts: FederationOpts): Set<string> | null;
declare function pinnedDiscoveryOriginFor(signer: string, opts: FederationOpts): {
    bound: boolean;
    origin: string | null;
};
declare function originOf(value: unknown): string | null;
/**
 * Verify a federated receipt against a live operator, fetching its discovery
 * and revocation surfaces.
 *
 * The receipt's `signature.key_discovery` URL (PIP-006 §"Federation contract")
 * is the operator's ep-keys.json location. Revocation is checked against the
 * operator's verifier-of-record endpoint (`/api/verify/{receipt_id}`). Its JSON
 * response is untrusted input: HTTP success and `revoked: false` are not proof
 * of current status. Acceptance requires a relying-party configured
 * `statusVerifier` to authenticate the response and confirm exact target binding
 * plus freshness. Cryptographic verification and live acceptance are
 * deliberately separate: an unavailable or untrusted status result does not
 * erase a valid signature (`verified` may remain true), but it MUST prevent a
 * live acceptance decision (`accepted` remains false).
 *
 * FAIL CLOSED + SSRF-GUARDED. The receipt-supplied `key_discovery` URL is
 * attacker-controlled. It is fetched ONLY when the relying party has pinned the
 * signer AND bound that signer's key SOURCE (an expected discovery origin/URL,
 * via the object-map form of opts.trustedIssuers). A bare signer-id pin does
 * NOT authenticate the key source: an attacker could set signature.signer to a
 * pinned id and point key_discovery at their own ep-keys.json advertising their
 * key under that id — verifying, but laundering trust. So a receipt-supplied
 * key_discovery whose origin is not explicitly bound to the pinned signer is
 * refused (fail closed). The receipt URL's origin must match the pinned origin.
 * A caller-supplied opts.keyDiscoveryUrl override is the relying party's OWN
 * choice — it is the source of truth and is always honored (still SSRF-guarded),
 * needing no origin match. Every fetch of a URL that could be influenced by the
 * receipt (key discovery, discovery-advertised verify_url_template) is routed
 * through two gates: assertSafeFetchUrl performs https/credential/literal-host
 * checks, then opts.networkBoundary resolves every address, rejects the entire
 * answer set unless every address is public, and fetches through a transport
 * pinned to that approved set. Redirects are disabled (redirect:manual).
 *
 * @param {object} receipt - EP-RECEIPT-v1 with signature.signer + signature.key_discovery
 * @param {object} [opts]
 * @param {object} opts.networkBoundary - required online resolver + pinned
 *   transport. resolveAddresses(hostname) MUST return every A/AAAA address.
 *   fetchPinned(url, init, { hostname, approvedAddresses }) MUST connect directly
 *   to one approved address without re-resolving, preserve hostname-based TLS
 *   SNI/Host handling, and return { response, connectedAddress }.
 * @param {typeof fetch} [opts.fetchImpl] - deprecated and rejected as an online
 *   transport when no networkBoundary is supplied; plain fetch is DNS-rebindable
 * @param {number} [opts.timeoutMs=5000]
 * @param {string} [opts.keyDiscoveryUrl] - relying-party override of the key_discovery URL
 * @param {string} [opts.verifyUrlBase] - relying-party override base for the revocation check
 * @param {Set<string>|string[]|Record<string,IssuerPin>} [opts.trustedIssuers] - out-of-band
 *   issuer allowlist (required for acceptance). To honor a RECEIPT-supplied
 *   key_discovery, use the object-map form and bind the signer's key source:
 *   { [signerId]: { key_discovery|keyDiscoveryOrigin, publicKey?|publicKeys? } }.
 *   A bare-id pin authorizes acceptance only when the caller supplies its own
 *   opts.keyDiscoveryUrl; it will NOT fetch a receipt-supplied URL (fail closed).
 * @param {string} [opts.expectedSigner] - out-of-band single-issuer pin (id only;
 *   like a bare-id trustedIssuers entry, it does not bind the key source, so it
 *   does not by itself authorize fetching a receipt-supplied key_discovery)
 * @param {Function} [opts.statusVerifier] - relying-party configured verifier for
 *   the fetched status document. It receives `(status, { receiptId, signer,
 *   verifyUrl })` and MUST return explicit `authenticated: true`,
 *   `target_bound: true`, `fresh: true`, and boolean `revoked`. Absence,
 *   exceptions, malformed output, or any non-true trust check fails closed.
 * @returns {Promise<ReturnType<typeof verifyFederatedReceiptOffline> & { fetched: object, revocation_confirmed?: boolean, revocation_status?: string }>}
 */
export declare function verifyFederatedReceipt(receipt: Obj, opts?: FederationOpts): Promise<FederationResult>;
export declare function assertSafeFetchUrl(value: unknown, _opts?: FederationOpts): {
    ok: boolean;
    error?: string;
};
declare function isBlockedHostname(host: string): boolean;
declare function isPrivateIPv4(host: string): boolean;
declare function isPrivateIPv6(host: string): boolean;
export declare const _internals: {
    assertSafeFetchUrl: typeof assertSafeFetchUrl;
    isPrivateIPv4: typeof isPrivateIPv4;
    isPrivateIPv6: typeof isPrivateIPv6;
    isBlockedHostname: typeof isBlockedHostname;
    pinnedDiscoveryOriginFor: typeof pinnedDiscoveryOriginFor;
    pinnedPublicKeysFor: typeof pinnedPublicKeysFor;
    originOf: typeof originOf;
};
export {};
//# sourceMappingURL=federation.d.ts.map