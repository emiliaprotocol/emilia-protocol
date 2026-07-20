type AnyRecord = Record<string, any>;
export declare const MOBILE_ENROLLMENT_CHALLENGE_VERSION = "EP-MOBILE-ENROLLMENT-CHALLENGE-v1";
export declare const MOBILE_ENROLLMENT_VERSION = "EP-MOBILE-ENROLLMENT-v1";
export declare const MOBILE_ANDROID_KEY_BINDING_VERSION = "EP-MOBILE-ANDROID-KEY-BINDING-v1";
export declare function buildMobileEnrollmentBinding(challenge: AnyRecord): AnyRecord;
/**
 * @param {{ challengeRequestHash?: string, keyId?: string, publicKeySpki?: string }} [params]
 */
export declare function buildMobileAndroidKeyBinding({ challengeRequestHash, keyId, publicKeySpki }?: AnyRecord): AnyRecord;
/**
 * Enrollment is deliberately adapter-driven. The WebAuthn adapter must perform
 * full registration attestation verification and return an ES256/P-256 SPKI.
 * The platform adapter must verify App Attest or Play Integrity enrollment
 * evidence against the exact platform_request_hash.
 */
/**
 * @typedef {object} MobileEnrollmentServiceOptions
 * @property {{ register: (challenge: any) => Promise<boolean>, consume: (challenge: any) => Promise<boolean>, durable?: boolean }} [challengeStore]
 * @property {{ enrollAtomically: (args: any) => Promise<boolean>, durable?: boolean }} [directory]
 * @property {(args: any) => Promise<any>} [verifyPasskeyRegistration]
 * @property {(args: any) => Promise<any>} [verifyPlatformEnrollment]
 * @property {(args: any) => Promise<boolean>} [authorizeEnrollment]
 * @property {() => string} [clock]
 * @property {number} [ttlMs]
 * @property {number} [enrollmentValidityMs]
 * @property {boolean} [allowEphemeral]
 */
/**
 * @param {MobileEnrollmentServiceOptions} [params]
 */
export declare function createMobileEnrollmentService({ challengeStore, directory, verifyPasskeyRegistration, verifyPlatformEnrollment, authorizeEnrollment, clock, ttlMs, enrollmentValidityMs, allowEphemeral, }?: AnyRecord): AnyRecord;
declare const _default: {
    MOBILE_ENROLLMENT_CHALLENGE_VERSION: string;
    MOBILE_ENROLLMENT_VERSION: string;
    MOBILE_ANDROID_KEY_BINDING_VERSION: string;
    buildMobileEnrollmentBinding: typeof buildMobileEnrollmentBinding;
    buildMobileAndroidKeyBinding: typeof buildMobileAndroidKeyBinding;
    createMobileEnrollmentService: typeof createMobileEnrollmentService;
};
export default _default;
//# sourceMappingURL=enrollment.d.ts.map