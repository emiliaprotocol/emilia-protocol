import { createAppleAppAttestVerifier, createPlayIntegrityAttestationVerifier } from './attestation.js';
import { createGovernmentMobileController } from './government.js';
import { createMobileHttpHandler } from './http.js';
import { MOBILE_PRESENTATION_VERSION, normalizeControlledMobilePresentation, normalizeMobilePresentation, projectMobileAction, validControlledMobilePresentation, validMobilePresentation } from './presentation.js';
import { buildMobileAndroidKeyBinding, buildMobileEnrollmentBinding, createMobileEnrollmentService, MOBILE_ANDROID_KEY_BINDING_VERSION, MOBILE_ENROLLMENT_CHALLENGE_VERSION, MOBILE_ENROLLMENT_VERSION } from './enrollment.js';
import { MOBILE_ACTION_CAID_TYPE, MOBILE_ACTION_CAID_PATTERN, buildMobileActionIdentity, mobileActionFingerprint, verifyMobileActionIdentity } from './action-identity.js';
type AnyRecord = Record<string, any>;
export declare const MOBILE_CHALLENGE_VERSION = "EP-MOBILE-CHALLENGE-v2";
export declare const MOBILE_CEREMONY_VERSION = "EP-MOBILE-CEREMONY-v1";
export declare const MOBILE_PROFILE_VERSION = "EP-MOBILE-RELIANCE-PROFILE-v1";
export declare const MOBILE_ATTESTATION_BINDING_VERSION = "EP-MOBILE-ATTESTATION-BINDING-v1";
export declare const MOBILE_ACK_VERSION = "EP-MOBILE-ACK-v1";
export declare const MOBILE_EXECUTION_RECORD_VERSION = "EP-MOBILE-EXECUTION-RECORD-v1";
export { MOBILE_ACTION_CAID_TYPE, MOBILE_ACTION_CAID_PATTERN, buildMobileActionIdentity, mobileActionFingerprint, verifyMobileActionIdentity, MOBILE_PRESENTATION_VERSION, normalizeControlledMobilePresentation, normalizeMobilePresentation, projectMobileAction, validControlledMobilePresentation, validMobilePresentation, };
export { createPlayIntegrityAttestationVerifier, createAppleAppAttestVerifier };
export { createGovernmentMobileController };
export { createMobileHttpHandler };
export { buildMobileAndroidKeyBinding, buildMobileEnrollmentBinding, createMobileEnrollmentService, MOBILE_ANDROID_KEY_BINDING_VERSION, MOBILE_ENROLLMENT_CHALLENGE_VERSION, MOBILE_ENROLLMENT_VERSION, };
export declare const MOBILE_VERDICTS: readonly string[];
export declare function hashCanonical(value: any): string;
export declare function mobileProfileHash(profile: AnyRecord): string;
/**
 * @param {Object} [params]
 * @param {string} [params.profileId]
 * @param {string} [params.rpId]
 * @param {string[]} [params.allowedOrigins]
 * @param {{ios: string[], android: string[]}} [params.acceptedApps]
 * @param {any[]} [params.enrollments]
 * @param {boolean} [params.attestationRequired]
 * @param {boolean} [params.hardwareBackedRequired]
 * @param {boolean} [params.strongIntegrityRequired]
 * @param {number} [params.maxChallengeAgeMs]
 * @param {string} [params.counterPolicy]
 * @returns {Object}
 */
export declare function createMobileRelianceProfile({ profileId, rpId, allowedOrigins, acceptedApps, enrollments, attestationRequired, hardwareBackedRequired, strongIntegrityRequired, maxChallengeAgeMs, counterPolicy, }?: AnyRecord): AnyRecord;
/**
 * @param {Object} [params]
 * @param {string} [params.actionHash]
 * @param {string} [params.actionReference]
 * @param {string} [params.actionCaid]
 * @param {string} [params.actionDigest]
 * @param {(string|null)} [params.policyId]
 * @param {(string|null)} [params.policyHash]
 * @param {string} [params.initiatorId]
 * @param {string} [params.approverId]
 * @param {number} [params.approverIndex]
 * @param {number} [params.requiredApprovals]
 * @param {string} [params.nonce]
 * @param {string} [params.issuedAt]
 * @param {string} [params.expiresAt]
 * @param {string} [params.decision]
 * @param {string} [params.displayHash]
 * @param {string} [params.profileHash]
 * @param {string} [params.platform]
 * @param {string} [params.appId]
 * @param {string} [params.deviceKeyId]
 * @param {string} [params.credentialId]
 * @param {string} [params.attestationKeyId]
 * @returns {Object}
 */
export declare function buildMobileAuthorizationContext({ actionHash, actionReference, actionCaid, actionDigest, policyId, policyHash, initiatorId, approverId, approverIndex, requiredApprovals, nonce, issuedAt, expiresAt, decision, displayHash, profileHash, platform, appId, deviceKeyId, credentialId, attestationKeyId, }?: AnyRecord): AnyRecord;
export declare function buildMobileAttestationBinding(challenge: AnyRecord): AnyRecord;
/**
 * @param {Object} [params]
 * @param {*} [params.action]
 * @param {string} [params.actionReference]
 * @param {*} [params.policy]
 * @param {(string|null)} [params.policyId]
 * @param {string} [params.initiatorId]
 * @param {string} [params.approverId]
 * @param {number} [params.approverIndex]
 * @param {number} [params.requiredApprovals]
 * @param {string} [params.decision]
 * @param {*} [params.presentation]
 * @param {string} [params.platform]
 * @param {string} [params.appId]
 * @param {string} [params.deviceKeyId]
 * @param {*} [params.profile]
 * @param {string} [params.issuedAt]
 * @param {string} [params.expiresAt]
 * @param {string} [params.challengeId]
 * @param {string} [params.nonce]
 * @returns {Object}
 */
export declare function createMobileChallenge({ action, actionReference, policy, policyId, initiatorId, approverId, approverIndex, requiredApprovals, decision, presentation, platform, appId, deviceKeyId, profile, issuedAt, expiresAt, challengeId, nonce, }?: AnyRecord): AnyRecord;
/**
 * Pure verification. It does not establish that the challenge was registered
 * or unused; use createMobileCeremonyService for durable one-time processing.
 * @param {Object} [params]
 * @param {*} [params.challenge]
 * @param {*} [params.response]
 * @param {*} [params.profile]
 * @param {string} [params.now]
 * @param {MobileCallback} [params.attestationVerifier]
 * @returns {Promise<MobileCeremonyResult>}
 */
export declare function verifyMobileCeremony({ challenge, response, profile, now, attestationVerifier, }?: AnyRecord): Promise<AnyRecord>;
export declare function toClassASignoff(response: AnyRecord): AnyRecord;
/**
 * Durable service boundary. Registration and consumption use the exact
 * AE-CHALLENGE body, so any changed action, profile, display, or expiry is a
 * different body and cannot consume the registered challenge.
 * @param {Object} [params]
 * @param {MobileChallengeStore} [params.challengeStore]
 * @param {MobileAuditLog} [params.auditLog]
 * @param {MobileCallback} [params.attestationVerifier]
 * @param {(MobileCounterStore|null)} [params.counterStore]
 * @param {(MobileCallback|null)} [params.commitDecision]
 * @param {() => string} [params.clock]
 * @param {boolean} [params.allowEphemeral]
 * @returns {Object}
 */
export declare function createMobileCeremonyService({ challengeStore, auditLog, attestationVerifier, counterStore, commitDecision, clock, allowEphemeral, }?: AnyRecord): AnyRecord;
/**
 * @param {Object} [params]
 * @param {MobileCeremonyResult} [params.result]
 * @param {(string|null)} [params.receiptId]
 * @param {string} [params.recordedAt]
 * @param {*} [params.signerPrivateKey]
 * @param {string} [params.signerKeyId]
 * @returns {Object}
 */
export declare function createMobileAck({ result, receiptId, recordedAt, signerPrivateKey, signerKeyId }?: AnyRecord): AnyRecord;
export declare function verifyMobileAck(ack: AnyRecord, publicKeySpkiB64u: string): boolean;
/**
 * Sign the operator's runtime statement after the durable ceremony service has
 * consumed the challenge and appended its atomic audit record. This statement
 * is deliberately separate from the Class-A signoff: its signature proves what
 * the operator attested, not that Apple/Google, storage, or physical execution
 * can be independently reconstructed offline.
 * @param {Object} [params]
 * @param {*} [params.challenge]
 * @param {MobileCeremonyResult} [params.result]
 * @param {string} [params.receiptId]
 * @param {string} [params.recordedAt]
 * @param {*} [params.signerPrivateKey]
 * @param {string} [params.signerKeyId]
 * @returns {Object}
 */
export declare function createMobileExecutionRecord({ challenge, result, receiptId, recordedAt, signerPrivateKey, signerKeyId, }?: AnyRecord): AnyRecord;
/** Verify only the execution-record signature and closed wire shape. */
export declare function verifyMobileExecutionRecord(record: AnyRecord, publicKeySpkiB64u: string): boolean;
declare const _default: {
    MOBILE_CHALLENGE_VERSION: string;
    MOBILE_CEREMONY_VERSION: string;
    MOBILE_PROFILE_VERSION: string;
    MOBILE_ATTESTATION_BINDING_VERSION: string;
    MOBILE_ACK_VERSION: string;
    MOBILE_EXECUTION_RECORD_VERSION: string;
    MOBILE_PRESENTATION_VERSION: string;
    MOBILE_VERDICTS: readonly string[];
    MOBILE_ACTION_CAID_TYPE: string;
    MOBILE_ACTION_CAID_PATTERN: RegExp;
    hashCanonical: typeof hashCanonical;
    buildMobileActionIdentity: typeof buildMobileActionIdentity;
    mobileActionFingerprint: typeof mobileActionFingerprint;
    verifyMobileActionIdentity: typeof verifyMobileActionIdentity;
    mobileProfileHash: typeof mobileProfileHash;
    createMobileRelianceProfile: typeof createMobileRelianceProfile;
    projectMobileAction: typeof projectMobileAction;
    normalizeControlledMobilePresentation: typeof normalizeControlledMobilePresentation;
    normalizeMobilePresentation: typeof normalizeMobilePresentation;
    validControlledMobilePresentation: typeof validControlledMobilePresentation;
    validMobilePresentation: typeof validMobilePresentation;
    buildMobileAuthorizationContext: typeof buildMobileAuthorizationContext;
    buildMobileAttestationBinding: typeof buildMobileAttestationBinding;
    createMobileChallenge: typeof createMobileChallenge;
    verifyMobileCeremony: typeof verifyMobileCeremony;
    createMobileCeremonyService: typeof createMobileCeremonyService;
    toClassASignoff: typeof toClassASignoff;
    createMobileAck: typeof createMobileAck;
    verifyMobileAck: typeof verifyMobileAck;
    createMobileExecutionRecord: typeof createMobileExecutionRecord;
    verifyMobileExecutionRecord: typeof verifyMobileExecutionRecord;
    createPlayIntegrityAttestationVerifier: typeof createPlayIntegrityAttestationVerifier;
    createAppleAppAttestVerifier: typeof createAppleAppAttestVerifier;
    createGovernmentMobileController: typeof createGovernmentMobileController;
    createMobileHttpHandler: typeof createMobileHttpHandler;
    buildMobileEnrollmentBinding: typeof buildMobileEnrollmentBinding;
    buildMobileAndroidKeyBinding: typeof buildMobileAndroidKeyBinding;
    createMobileEnrollmentService: typeof createMobileEnrollmentService;
    MOBILE_ANDROID_KEY_BINDING_VERSION: string;
    MOBILE_ENROLLMENT_CHALLENGE_VERSION: string;
    MOBILE_ENROLLMENT_VERSION: string;
};
export default _default;
//# sourceMappingURL=index.d.ts.map