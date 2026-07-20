type AnyRecord = Record<string, any>;
/**
 * @typedef {Object} PlayIntegrityVerifierOptions
 * @property {(token: string) => Promise<any>} [decodeToken]
 * @property {string} [packageName]
 * @property {Array<string>} [certificateDigests]
 * @property {boolean} [requireLicensed]
 * @property {boolean} [requireStrongIntegrity]
 * @property {boolean} [requireNoCaptureOrControl]
 * @property {boolean} [requirePlayProtect]
 * @property {Array<number|string>} [allowedVersionCodes]
 * @property {number|string|null} [minimumSdkVersion]
 * @property {number} [maxTokenAgeMs]
 * @property {() => number} [clock]
 */
/**
 * Adapt the official Google decodeIntegrityToken response into the closed
 * result consumed by verifyMobileCeremony. `decodeToken` owns OAuth and the
 * server-to-server Google call; this function owns the relying party's pins.
 *
 * @param {PlayIntegrityVerifierOptions} [options]
 */
export declare function createPlayIntegrityAttestationVerifier({ decodeToken, packageName, certificateDigests, requireLicensed, requireStrongIntegrity, requireNoCaptureOrControl, requirePlayProtect, allowedVersionCodes, minimumSdkVersion, maxTokenAgeMs, clock, }?: AnyRecord): (input?: AnyRecord) => Promise<AnyRecord>;
/**
 * @typedef {Object} AppleAppAttestVerifierOptions
 * @property {(input: { assertionObject: Buffer, clientDataHash: Buffer, expectedBinding: unknown, appId: string, keyId: string, environment: string }) => Promise<any>} [verifyAssertion]
 * @property {string} [appId]
 * @property {string} [attestationKeyId]
 * @property {string} [environment]
 * @property {{ advance: (keyId: string, counter: number) => Promise<boolean> }} [counterStore]
 */
/**
 * Adapt an App Attest cryptographic verifier. `verifyAssertion` MUST validate
 * the Apple certificate/credential chain and assertion signature against the
 * enrolled App Attest public key. This adapter pins application identity,
 * request bytes, environment, and the monotonic App Attest counter.
 *
 * @param {AppleAppAttestVerifierOptions} [options]
 */
export declare function createAppleAppAttestVerifier({ verifyAssertion, appId, attestationKeyId, environment, counterStore, }?: AnyRecord): (input?: AnyRecord) => Promise<AnyRecord>;
declare const _default: {
    createPlayIntegrityAttestationVerifier: typeof createPlayIntegrityAttestationVerifier;
    createAppleAppAttestVerifier: typeof createAppleAppAttestVerifier;
};
export default _default;
//# sourceMappingURL=attestation.d.ts.map