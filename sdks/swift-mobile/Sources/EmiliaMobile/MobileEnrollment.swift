// SPDX-License-Identifier: Apache-2.0
import Foundation

public struct EmiliaMobileEnrollmentChallenge: Sendable, Codable, Equatable {
    public struct User: Sendable, Codable, Equatable {
        public let id: String
        public let name: String
        public let displayName: String

        enum CodingKeys: String, CodingKey {
            case id, name
            case displayName = "display_name"
        }
    }

    public let version: String
    public let challengeProfile: String
    public let challengeID: String
    public let enrollmentID: String
    public let nonce: String
    public let challenge: String
    public let approverID: String
    public let platform: String
    public let appID: String
    public let rpID: String
    public let origin: String
    public let user: User
    public let enrollmentValidTo: String
    public let platformBinding: EmiliaJSONValue
    public let platformRequestHash: String
    public let issuedAt: String
    public let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case version = "@version"
        case challengeProfile = "challenge_profile"
        case challengeID = "challenge_id"
        case enrollmentID = "enrollment_id"
        case nonce, challenge
        case approverID = "approver_id"
        case platform
        case appID = "app_id"
        case rpID = "rp_id"
        case origin, user
        case enrollmentValidTo = "enrollment_valid_to"
        case platformBinding = "platform_binding"
        case platformRequestHash = "platform_request_hash"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
    }
}

public struct EmiliaPasskeyRegistration: Sendable, Equatable {
    public let credentialID: Data
    public let clientDataJSON: Data
    public let attestationObject: Data

    public init(credentialID: Data, clientDataJSON: Data, attestationObject: Data) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
    }
}

public protocol EmiliaPasskeyRegistrationProvider: Sendable {
    func registration(
        rpID: String,
        challenge: Data,
        userID: Data,
        userName: String,
        displayName: String
    ) async throws -> EmiliaPasskeyRegistration
}

public struct EmiliaPlatformEnrollment: Sendable, Equatable {
    public let format: String
    public let attestationKeyID: String
    public let token: Data

    public init(format: String, attestationKeyID: String, token: Data) {
        self.format = format
        self.attestationKeyID = attestationKeyID
        self.token = token
    }
}

public protocol EmiliaPlatformEnrollmentProvider: Sendable {
    func enrollment(requestHash: Data) async throws -> EmiliaPlatformEnrollment
}

public struct EmiliaMobileEnrollmentResponse: Sendable, Codable, Equatable {
    public let version = "EP-MOBILE-ENROLLMENT-v1"
    public let enrollmentID: String
    public let approverID: String
    public let platform: String
    public let appID: String
    public let platformRequestHash: String
    public let attestationKeyID: String
    public let requestedValidTo: String
    public let passkeyRegistration: PasskeyRegistration
    public let platformAttestation: PlatformAttestation

    public struct PasskeyRegistration: Sendable, Codable, Equatable {
        public let id: String
        public let rawID: String
        public let type = "public-key"
        public let response: Response

        public struct Response: Sendable, Codable, Equatable {
            public let clientDataJSON: String
            public let attestationObject: String

            enum CodingKeys: String, CodingKey {
                case clientDataJSON
                case attestationObject
            }
        }

        enum CodingKeys: String, CodingKey {
            case id, type, response
            case rawID = "rawId"
        }
    }

    public struct PlatformAttestation: Sendable, Codable, Equatable {
        public let format: String
        public let token: String
    }

    enum CodingKeys: String, CodingKey {
        case version = "@version"
        case enrollmentID = "enrollment_id"
        case approverID = "approver_id"
        case platform
        case appID = "app_id"
        case platformRequestHash = "platform_request_hash"
        case attestationKeyID = "attestation_key_id"
        case requestedValidTo = "requested_valid_to"
        case passkeyRegistration = "passkey_registration"
        case platformAttestation = "platform_attestation"
    }
}

public actor EmiliaMobileEnrollmentCoordinator {
    private let passkeys: any EmiliaPasskeyRegistrationProvider
    private let platformEnrollment: any EmiliaPlatformEnrollmentProvider
    private let platform: String
    private let appID: String

    public init(
        passkeys: any EmiliaPasskeyRegistrationProvider,
        platformEnrollment: any EmiliaPlatformEnrollmentProvider,
        platform: String = "ios",
        appID: String
    ) {
        self.passkeys = passkeys
        self.platformEnrollment = platformEnrollment
        self.platform = platform
        self.appID = appID
    }

    public func perform(
        challengeData: Data,
        now: Date = Date()
    ) async throws -> EmiliaMobileEnrollmentResponse {
        let decoder = JSONDecoder()
        let challenge: EmiliaMobileEnrollmentChallenge
        do { challenge = try decoder.decode(EmiliaMobileEnrollmentChallenge.self, from: challengeData) }
        catch { throw EmiliaMobileError.malformedChallenge("enrollment challenge JSON could not be decoded") }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard challenge.version == "AE-CHALLENGE-v1",
              challenge.challengeProfile == "EP-MOBILE-ENROLLMENT-CHALLENGE-v1",
              challenge.challengeID == challenge.enrollmentID,
              challenge.platform == platform,
              challenge.appID == appID,
              let issued = formatter.date(from: challenge.issuedAt),
              let expires = formatter.date(from: challenge.expiresAt),
              let validTo = formatter.date(from: challenge.enrollmentValidTo),
              issued <= now, now <= expires, validTo > now,
              let registrationChallenge = Data(emiliaBase64URL: challenge.challenge),
              let userID = Data(emiliaBase64URL: challenge.user.id)
        else { throw EmiliaMobileError.malformedChallenge("enrollment challenge is invalid or expired") }

        let expectedBinding = EmiliaJSONValue.object([
            "@version": .string("EP-MOBILE-ENROLLMENT-CHALLENGE-v1"),
            "enrollment_id": .string(challenge.enrollmentID),
            "challenge": .string(challenge.challenge),
            "approver_id": .string(challenge.approverID),
            "platform": .string(challenge.platform),
            "app_id": .string(challenge.appID),
            "rp_id": .string(challenge.rpID),
            "origin": .string(challenge.origin),
            "enrollment_valid_to": .string(challenge.enrollmentValidTo),
            "issued_at": .string(challenge.issuedAt),
            "expires_at": .string(challenge.expiresAt),
        ])
        guard challenge.platformBinding == expectedBinding else { throw EmiliaMobileError.contextMismatch }
        let requestHash = try EmiliaCanonicalJSON.sha256(expectedBinding)
        guard requestHash.emiliaBase64URL == challenge.platformRequestHash else {
            throw EmiliaMobileError.contextMismatch
        }

        async let platformResult = platformEnrollment.enrollment(requestHash: requestHash)
        async let passkey = passkeys.registration(
            rpID: challenge.rpID,
            challenge: registrationChallenge,
            userID: userID,
            userName: challenge.user.name,
            displayName: challenge.user.displayName
        )
        let (integrity, credential) = try await (platformResult, passkey)
        let credentialID = credential.credentialID.emiliaBase64URL
        return EmiliaMobileEnrollmentResponse(
            enrollmentID: challenge.enrollmentID,
            approverID: challenge.approverID,
            platform: platform,
            appID: appID,
            platformRequestHash: challenge.platformRequestHash,
            attestationKeyID: integrity.attestationKeyID,
            requestedValidTo: challenge.enrollmentValidTo,
            passkeyRegistration: .init(
                id: credentialID,
                rawID: credentialID,
                response: .init(
                    clientDataJSON: credential.clientDataJSON.emiliaBase64URL,
                    attestationObject: credential.attestationObject.emiliaBase64URL
                )
            ),
            platformAttestation: .init(
                format: integrity.format,
                token: integrity.token.emiliaBase64URL
            )
        )
    }
}
