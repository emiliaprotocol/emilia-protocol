export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type MobilePlatform = 'ios' | 'android';
export type MobileDecision = 'approved' | 'denied';

export interface MobileEnrollment {
  device_key_id: string;
  credential_id: string;
  public_key_spki: string;
  approver_id: string;
  platform: MobilePlatform;
  app_id: string;
  attestation_key_id: string;
  platform_public_key?: string | null;
  status?: 'active' | 'revoked';
  valid_from: string;
  valid_to: string;
  sign_count: number;
}

export interface MobilePresentation {
  '@version': 'EP-MOBILE-PRESENTATION-v1';
  title: string;
  summary: string;
  risk: string;
  consequence: string;
  material_fields: Record<string, string>;
}

export interface MobileRelianceProfile {
  '@version': 'EP-MOBILE-RELIANCE-PROFILE-v1';
  profile_id: string;
  profile_hash: string;
  rp_id: string;
  allowed_origins: string[];
  accepted_apps: { ios: string[]; android: string[] };
  requirements: {
    attestation_required: boolean;
    hardware_backed_required: boolean;
    strong_integrity_required: boolean;
    max_challenge_age_ms: number;
    counter_policy: 'ignore' | 'monotonic_if_nonzero' | 'registration_baseline';
  };
  enrollments: MobileEnrollment[];
}

export interface MobileChallenge {
  '@version': 'AE-CHALLENGE-v1';
  challenge_profile: 'EP-MOBILE-CHALLENGE-v1';
  challenge_id: string;
  nonce: string;
  action: Record<string, JsonValue>;
  action_hash: string;
  profile_hash: string;
  authorization_context: Record<string, JsonValue>;
  webauthn: {
    rp_id: string;
    challenge: string;
    credential_ids: string[];
    user_verification: 'required';
    timeout_ms: number;
  };
  presentation: MobilePresentation;
  attestation: {
    required: boolean;
    format: 'apple-app-attest' | 'play-integrity-standard';
    binding: Record<string, JsonValue>;
    request_hash: string;
  };
  issued_at: string;
  expires_at: string;
}

export interface MobileCeremonyResponse {
  '@version': 'EP-MOBILE-CEREMONY-v1';
  challenge_id: string;
  nonce: string;
  platform: MobilePlatform;
  app_id: string;
  device_key_id: string;
  credential_id: string;
  attestation_key_id: string;
  decision: MobileDecision;
  display_hash: string;
  signoff: {
    context: Record<string, JsonValue>;
    webauthn: {
      authenticator_data: string;
      client_data_json: string;
      signature: string;
    };
  };
  attestation: { format: string; token: string; device_key_signature?: string };
}

export interface MobileVerificationResult {
  valid: boolean;
  verdict: string;
  decision: MobileDecision | null;
  reason: string | null;
  checks: Record<string, boolean>;
  context_hash?: string;
  sign_count?: number | null;
  approver_id?: string;
  device_key_id?: string;
  class_a?: Record<string, JsonValue>;
  audit_record?: unknown;
}

export interface MobileEvidenceRecord extends Record<string, JsonValue> {
  seq: number;
  prev_hash: string;
  record_id: string;
  hash: string;
}

export interface MobileAttestationResult {
  valid: boolean;
  request_hash?: string;
  app_id?: string;
  attestation_key_id?: string;
  platform?: MobilePlatform;
  hardware_backed?: boolean;
  strong_integrity?: boolean;
  platform_public_key?: string;
  [key: string]: unknown;
}

export type MobileAttestationVerifier = (input: {
  format: string;
  token: string;
  expected_request_hash: string;
  expected_binding: Record<string, JsonValue>;
  expected_app_id: string;
  expected_attestation_key_id: string;
  device_key_signature?: string;
  platform: MobilePlatform;
}) => Promise<MobileAttestationResult> | MobileAttestationResult;

export const MOBILE_CHALLENGE_VERSION: 'EP-MOBILE-CHALLENGE-v1';
export const MOBILE_CEREMONY_VERSION: 'EP-MOBILE-CEREMONY-v1';
export const MOBILE_PROFILE_VERSION: 'EP-MOBILE-RELIANCE-PROFILE-v1';
export const MOBILE_ATTESTATION_BINDING_VERSION: 'EP-MOBILE-ATTESTATION-BINDING-v1';
export const MOBILE_ACK_VERSION: 'EP-MOBILE-ACK-v1';
export const MOBILE_EXECUTION_RECORD_VERSION: 'EP-MOBILE-EXECUTION-RECORD-v1';
export const MOBILE_PRESENTATION_VERSION: 'EP-MOBILE-PRESENTATION-v1';
export const MOBILE_ANDROID_KEY_BINDING_VERSION: 'EP-MOBILE-ANDROID-KEY-BINDING-v1';
export const MOBILE_ENROLLMENT_CHALLENGE_VERSION: 'EP-MOBILE-ENROLLMENT-CHALLENGE-v1';
export const MOBILE_ENROLLMENT_VERSION: 'EP-MOBILE-ENROLLMENT-v1';
export const MOBILE_VERDICTS: readonly string[];

export function hashCanonical(value: JsonValue): string;
export function mobileProfileHash(profile: MobileRelianceProfile | Omit<MobileRelianceProfile, 'profile_hash'>): string;
export function createMobileRelianceProfile(input: {
  profileId: string;
  rpId: string;
  allowedOrigins: string[];
  acceptedApps: { ios: string[]; android: string[] };
  enrollments: MobileEnrollment[];
  attestationRequired?: boolean;
  hardwareBackedRequired?: boolean;
  strongIntegrityRequired?: boolean;
  maxChallengeAgeMs?: number;
  counterPolicy?: 'ignore' | 'monotonic_if_nonzero' | 'registration_baseline';
}): MobileRelianceProfile;
export function buildMobileAuthorizationContext(input: Record<string, unknown>): Record<string, JsonValue>;
export function buildMobileAttestationBinding(challenge: MobileChallenge): Record<string, JsonValue>;
export function createMobileChallenge(input: {
  action: Record<string, JsonValue>;
  policy?: JsonValue;
  policyId?: string | null;
  initiatorId: string;
  approverId: string;
  decision: MobileDecision;
  presentation: MobilePresentation;
  platform: MobilePlatform;
  appId: string;
  deviceKeyId: string;
  profile: MobileRelianceProfile;
  issuedAt: string;
  expiresAt: string;
  challengeId?: string;
  nonce?: string;
}): MobileChallenge;
export function verifyMobileCeremony(input: {
  challenge: MobileChallenge;
  response: MobileCeremonyResponse;
  profile: MobileRelianceProfile;
  now: string;
  attestationVerifier: MobileAttestationVerifier;
}): Promise<MobileVerificationResult>;
export function toClassASignoff(response: MobileCeremonyResponse): Record<string, JsonValue>;

export interface MobileCeremonyService {
  issue(input: Parameters<typeof createMobileChallenge>[0]): Promise<{ ok: boolean; verdict: string; challenge: MobileChallenge | null }>;
  verifyAndConsume(input: { challenge: MobileChallenge; response: MobileCeremonyResponse; profile: MobileRelianceProfile }): Promise<MobileVerificationResult>;
}

export function createMobileCeremonyService(input: {
  challengeStore: { durable?: boolean; register(challenge: MobileChallenge): Promise<boolean>; consume(challenge: MobileChallenge): Promise<boolean> };
  auditLog: { durable?: boolean; strict?: boolean; record(event: Record<string, unknown>): Promise<unknown> };
  attestationVerifier: MobileAttestationVerifier;
  counterStore?: { advance(key: string, value: number): Promise<boolean> } | null;
  commitDecision?: ((input: {
    challenge: MobileChallenge;
    result: MobileVerificationResult;
    auditEntry: Record<string, JsonValue>;
  }) => Promise<false | { committed: true; audit_record: MobileEvidenceRecord }>) | null;
  clock?: () => string;
  allowEphemeral?: boolean;
}): MobileCeremonyService;

export function createPlayIntegrityAttestationVerifier(input: {
  decodeToken(token: string): Promise<Record<string, unknown>>;
  packageName: string;
  certificateDigests: string[];
  requireLicensed?: boolean;
  requireStrongIntegrity?: boolean;
  requireNoCaptureOrControl?: boolean;
  maxTokenAgeMs?: number;
  clock?: () => number;
}): MobileAttestationVerifier;

export function createAppleAppAttestVerifier(input: {
  verifyAssertion(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  appId: string;
  attestationKeyId: string;
  environment?: 'development' | 'production';
  counterStore: { advance(key: string, value: number): Promise<boolean> };
}): MobileAttestationVerifier;

export function buildMobileEnrollmentBinding(challenge: Record<string, unknown>): Record<string, JsonValue>;
export function buildMobileAndroidKeyBinding(input: {
  challengeRequestHash: string;
  keyId: string;
  publicKeySpki: string;
}): Record<string, JsonValue>;
export function normalizeMobilePresentation(
  value: Record<string, JsonValue>,
  options?: { allowUnversioned?: boolean },
): MobilePresentation;
export function validMobilePresentation(value: unknown): boolean;
export function createMobileEnrollmentService(input: {
  challengeStore: {
    durable?: boolean;
    register(challenge: Record<string, unknown>): Promise<boolean>;
    consume(challenge: Record<string, unknown>): Promise<boolean>;
  };
  directory: {
    durable?: boolean;
    enrollAtomically(record: { enrollment: MobileEnrollment; event: Record<string, unknown> }): Promise<boolean>;
  };
  verifyPasskeyRegistration(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  verifyPlatformEnrollment(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  authorizeEnrollment(input: Record<string, unknown>): Promise<boolean> | boolean;
  clock?: () => string;
  ttlMs?: number;
  enrollmentValidityMs?: number;
  allowEphemeral?: boolean;
}): {
  issue(input: Record<string, unknown>): Promise<{ ok: boolean; verdict: string; challenge: Record<string, unknown> | null }>;
  complete(input: Record<string, unknown>): Promise<{ ok: boolean; verdict: string; reason: string | null; enrollment: MobileEnrollment | null }>;
};

export function createGovernmentMobileController(input: {
  service: MobileCeremonyService;
  profiles: Map<string, MobileRelianceProfile>;
  resolveRequest(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  authorize(input: Record<string, unknown>): Promise<boolean> | boolean;
  registerChallenge?: ((input: Record<string, unknown>) => Promise<boolean>) | null;
}): {
  issue(request: Record<string, unknown>, caller?: unknown): Promise<{ ok: boolean; verdict: string; challenge: MobileChallenge | null }>;
  verify(presentation: { challenge: MobileChallenge; response: MobileCeremonyResponse }, caller?: unknown): Promise<MobileVerificationResult>;
};

export function createMobileHttpHandler(input: {
  controller: ReturnType<typeof createGovernmentMobileController>;
  enrollmentService: ReturnType<typeof createMobileEnrollmentService>;
  authenticate(request: Request): Promise<unknown> | unknown;
  resolveEnrollmentIdentity(input: { caller: unknown; approver_id: string }): Promise<{ userName: string; displayName: string }> | { userName: string; displayName: string };
  enrollmentConfig: { rpId: string; origin?: string; origins?: { ios: string; android: string } };
  maxBodyBytes?: number;
  routePrefix?: string;
}): (request: Request) => Promise<Response>;

export function createMobileAck(input: Record<string, unknown>): Record<string, unknown>;
export function verifyMobileAck(ack: Record<string, unknown>, publicKeySpkiB64u: string): boolean;
export function createMobileExecutionRecord(input: {
  challenge: MobileChallenge;
  result: MobileVerificationResult;
  receiptId: string;
  recordedAt: string;
  signerPrivateKey: unknown;
  signerKeyId: string;
}): Record<string, unknown>;
export function verifyMobileExecutionRecord(
  record: Record<string, unknown>,
  publicKeySpkiB64u: string,
): boolean;
