// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Foundation

public enum EmiliaMobileError: Error, Equatable {
    case malformedChallenge(String)
    case actionMismatch
    case displayMismatch
    case decisionMismatch
    case contextMismatch
    case unsupportedPlatform
    case nonCanonicalJSON
    case unavailable(String)
}

public enum EmiliaMobileDecision: String, Sendable, Codable, Equatable {
    case approved
    case denied
}

public struct EmiliaWebAuthnRequest: Sendable, Codable, Equatable {
    public let rpID: String
    public let challenge: String
    public let credentialIDs: [String]
    public let userVerification: String
    public let timeoutMS: Int64

    public init(
        rpID: String,
        challenge: String,
        credentialIDs: [String],
        userVerification: String,
        timeoutMS: Int64
    ) {
        self.rpID = rpID
        self.challenge = challenge
        self.credentialIDs = credentialIDs
        self.userVerification = userVerification
        self.timeoutMS = timeoutMS
    }

    enum CodingKeys: String, CodingKey {
        case rpID = "rp_id"
        case challenge
        case credentialIDs = "credential_ids"
        case userVerification = "user_verification"
        case timeoutMS = "timeout_ms"
    }
}

public struct EmiliaAttestationRequest: Sendable, Codable, Equatable {
    public let required: Bool
    public let format: String
    public let binding: EmiliaJSONValue
    public let requestHash: String

    public init(required: Bool, format: String, binding: EmiliaJSONValue, requestHash: String) {
        self.required = required
        self.format = format
        self.binding = binding
        self.requestHash = requestHash
    }

    enum CodingKeys: String, CodingKey {
        case required, format, binding
        case requestHash = "request_hash"
    }
}

public struct EmiliaMobileChallenge: Sendable, Codable, Equatable {
    public static let supportedProfile = "EP-MOBILE-CHALLENGE-v2"

    public let version: String
    public let challengeProfile: String
    public let challengeID: String
    public let nonce: String
    public let action: EmiliaJSONValue
    public let actionHash: String
    public let profileHash: String
    public let authorizationContext: EmiliaJSONValue
    public let webauthn: EmiliaWebAuthnRequest
    public let presentation: EmiliaJSONValue
    public let attestation: EmiliaAttestationRequest
    public let issuedAt: String
    public let expiresAt: String

    public init(
        version: String,
        challengeProfile: String,
        challengeID: String,
        nonce: String,
        action: EmiliaJSONValue,
        actionHash: String,
        profileHash: String,
        authorizationContext: EmiliaJSONValue,
        webauthn: EmiliaWebAuthnRequest,
        presentation: EmiliaJSONValue,
        attestation: EmiliaAttestationRequest,
        issuedAt: String,
        expiresAt: String
    ) {
        self.version = version
        self.challengeProfile = challengeProfile
        self.challengeID = challengeID
        self.nonce = nonce
        self.action = action
        self.actionHash = actionHash
        self.profileHash = profileHash
        self.authorizationContext = authorizationContext
        self.webauthn = webauthn
        self.presentation = presentation
        self.attestation = attestation
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case version = "@version"
        case challengeProfile = "challenge_profile"
        case challengeID = "challenge_id"
        case nonce, action
        case actionHash = "action_hash"
        case profileHash = "profile_hash"
        case authorizationContext = "authorization_context"
        case webauthn, presentation, attestation
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
    }
}

public struct EmiliaMobilePresentation: Sendable, Equatable {
    public static let version = "EP-MOBILE-PRESENTATION-v1"
    public let title: String
    public let summary: String
    public let risk: String
    public let consequence: String
    public let materialFields: [String: String]
}

public struct EmiliaPasskeyAssertion: Sendable, Equatable {
    public let credentialID: Data
    public let authenticatorData: Data
    public let clientDataJSON: Data
    public let signature: Data

    public init(credentialID: Data, authenticatorData: Data, clientDataJSON: Data, signature: Data) {
        self.credentialID = credentialID
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
    }
}

public protocol EmiliaPasskeyAssertionProvider: Sendable {
    func assertion(rpID: String, challenge: Data, allowedCredentialIDs: [Data]) async throws -> EmiliaPasskeyAssertion
}

public protocol EmiliaPlatformIntegrityProvider: Sendable {
    var format: String { get }
    var attestationKeyID: String { get }
    func assertion(requestHash: Data) async throws -> EmiliaPlatformIntegrityAssertion
}

public struct EmiliaPlatformIntegrityAssertion: Sendable, Equatable {
    public let token: Data
    public let deviceKeySignature: Data?

    public init(token: Data, deviceKeySignature: Data? = nil) {
        self.token = token
        self.deviceKeySignature = deviceKeySignature
    }
}

public struct EmiliaMobileCeremonyResponse: Sendable, Codable, Equatable {
    public let version = "EP-MOBILE-CEREMONY-v1"
    public let challengeID: String
    public let nonce: String
    public let platform: String
    public let appID: String
    public let deviceKeyID: String
    public let credentialID: String
    public let attestationKeyID: String
    public let decision: String
    public let displayHash: String
    public let signoff: Signoff
    public let attestation: Attestation

    public struct Signoff: Sendable, Codable, Equatable {
        public let context: EmiliaJSONValue
        public let webauthn: WebAuthn

        public init(context: EmiliaJSONValue, webauthn: WebAuthn) {
            self.context = context
            self.webauthn = webauthn
        }
    }

    public struct WebAuthn: Sendable, Codable, Equatable {
        public let authenticatorData: String
        public let clientDataJSON: String
        public let signature: String

        public init(authenticatorData: String, clientDataJSON: String, signature: String) {
            self.authenticatorData = authenticatorData
            self.clientDataJSON = clientDataJSON
            self.signature = signature
        }

        enum CodingKeys: String, CodingKey {
            case authenticatorData = "authenticator_data"
            case clientDataJSON = "client_data_json"
            case signature
        }
    }

    public struct Attestation: Sendable, Codable, Equatable {
        public let format: String
        public let token: String
        public let deviceKeySignature: String?

        public init(format: String, token: String, deviceKeySignature: String? = nil) {
            self.format = format
            self.token = token
            self.deviceKeySignature = deviceKeySignature
        }

        enum CodingKeys: String, CodingKey {
            case format, token
            case deviceKeySignature = "device_key_signature"
        }
    }

    enum CodingKeys: String, CodingKey {
        case version = "@version"
        case challengeID = "challenge_id"
        case nonce, platform
        case appID = "app_id"
        case deviceKeyID = "device_key_id"
        case credentialID = "credential_id"
        case attestationKeyID = "attestation_key_id"
        case decision
        case displayHash = "display_hash"
        case signoff, attestation
    }

    public init(
        challengeID: String,
        nonce: String,
        platform: String,
        appID: String,
        deviceKeyID: String,
        credentialID: String,
        attestationKeyID: String,
        decision: String,
        displayHash: String,
        signoff: Signoff,
        attestation: Attestation
    ) {
        self.challengeID = challengeID
        self.nonce = nonce
        self.platform = platform
        self.appID = appID
        self.deviceKeyID = deviceKeyID
        self.credentialID = credentialID
        self.attestationKeyID = attestationKeyID
        self.decision = decision
        self.displayHash = displayHash
        self.signoff = signoff
        self.attestation = attestation
    }
}

public struct EmiliaValidatedChallenge: Sendable {
    public let challenge: EmiliaMobileChallenge
    public let context: [String: EmiliaJSONValue]
    public let mobileBinding: [String: EmiliaJSONValue]
    public let requestHash: Data
    public let presentation: EmiliaMobilePresentation
    public let decision: EmiliaMobileDecision
    public let actionReference: String
    public let actionIdentity: EmiliaActionIdentity
}

public enum EmiliaMobileChallengeValidator {
    private static func boundedText(_ value: String, maximum: Int, allowEmpty: Bool = false) -> Bool {
        let scalars = value.unicodeScalars
        guard scalars.count <= maximum, allowEmpty || !scalars.isEmpty else { return false }
        return scalars.allSatisfy { scalar in
            let code = scalar.value
            return !(code <= 0x08 || code == 0x0b || code == 0x0c
                || (0x0e...0x1f).contains(code) || code == 0x7f)
        }
    }

    public static func projectMaterialFields(from action: EmiliaJSONValue) throws -> [String: String] {
        guard let object = action.objectValue, (1...64).contains(object.count) else {
            throw EmiliaMobileError.displayMismatch
        }
        var fields: [String: String] = [:]
        for (name, value) in object {
            guard name.range(
                of: #"^@?[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$"#,
                options: .regularExpression
            ) != nil else { throw EmiliaMobileError.displayMismatch }
            let text: String
            switch value {
            case .string(let value): text = value
            case .integer(let value):
                guard (-EmiliaCanonicalJSON.maximumSafeInteger...EmiliaCanonicalJSON.maximumSafeInteger).contains(value)
                else { throw EmiliaMobileError.displayMismatch }
                text = String(value)
            case .bool(let value): text = value ? "true" : "false"
            case .null: text = "null"
            case .array, .object: throw EmiliaMobileError.displayMismatch
            }
            guard boundedText(text, maximum: 4_096, allowEmpty: true) else {
                throw EmiliaMobileError.displayMismatch
            }
            fields[name] = text
        }
        return fields
    }

    public static func validatePresentation(
        _ value: EmiliaJSONValue,
        for action: EmiliaJSONValue
    ) throws -> EmiliaMobilePresentation {
        let members: Set<String> = ["@version", "title", "summary", "risk", "consequence", "material_fields"]
        guard let object = value.objectValue,
              Set(object.keys) == members,
              object["@version"]?.stringValue == EmiliaMobilePresentation.version,
              let title = object["title"]?.stringValue,
              let summary = object["summary"]?.stringValue,
              let risk = object["risk"]?.stringValue,
              let consequence = object["consequence"]?.stringValue,
              boundedText(title, maximum: 200),
              boundedText(summary, maximum: 2_000),
              boundedText(risk, maximum: 128),
              boundedText(consequence, maximum: 2_000, allowEmpty: true),
              let rawFields = object["material_fields"]?.objectValue,
              (1...64).contains(rawFields.count)
        else { throw EmiliaMobileError.displayMismatch }
        var fields: [String: String] = [:]
        for (name, rawValue) in rawFields {
            guard name.range(of: #"^@?[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$"#, options: .regularExpression) != nil,
                  let field = rawValue.stringValue,
                  boundedText(field, maximum: 4_096, allowEmpty: true)
            else { throw EmiliaMobileError.displayMismatch }
            fields[name] = field
        }
        guard fields == (try projectMaterialFields(from: action)) else {
            throw EmiliaMobileError.displayMismatch
        }
        return .init(title: title, summary: summary, risk: risk, consequence: consequence, materialFields: fields)
    }

    public static func decodeAndValidate(
        _ data: Data,
        requestedDecision: EmiliaMobileDecision? = nil,
        expectedActionReference: String? = nil,
        expectedActionIdentity: EmiliaActionIdentity? = nil,
        now: Date = Date()
    ) throws -> EmiliaValidatedChallenge {
        let decoder = JSONDecoder()
        let challenge: EmiliaMobileChallenge
        do { challenge = try decoder.decode(EmiliaMobileChallenge.self, from: data) }
        catch { throw EmiliaMobileError.malformedChallenge("challenge JSON could not be decoded") }

        guard challenge.version == "AE-CHALLENGE-v1",
              challenge.challengeProfile == EmiliaMobileChallenge.supportedProfile,
              challenge.webauthn.userVerification == "required",
              !challenge.webauthn.credentialIDs.isEmpty,
              challenge.webauthn.credentialIDs.allSatisfy({ Data(emiliaBase64URL: $0) != nil })
        else { throw EmiliaMobileError.malformedChallenge("unsupported mobile challenge profile") }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let issued = formatter.date(from: challenge.issuedAt),
              let expires = formatter.date(from: challenge.expiresAt),
              issued <= now, now <= expires, expires > issued
        else { throw EmiliaMobileError.malformedChallenge("challenge is outside its validity window") }

        let derivedActionIdentity: EmiliaActionIdentity
        do {
            derivedActionIdentity = try EmiliaActionIdentity.derive(from: challenge.action)
        } catch {
            throw EmiliaMobileError.actionMismatch
        }
        guard derivedActionIdentity.actionDigest == challenge.actionHash else {
            throw EmiliaMobileError.actionMismatch
        }
        let presentation = try validatePresentation(challenge.presentation, for: challenge.action)
        let presentationDigest = try EmiliaCanonicalJSON.digest(challenge.presentation)
        guard let context = challenge.authorizationContext.objectValue,
              context["action_hash"]?.stringValue == challenge.actionHash,
              context["display_hash"]?.stringValue == presentationDigest,
              context["nonce"]?.stringValue == challenge.nonce,
              let actionReference = context["action_reference"]?.stringValue,
              actionReference.range(
                  of: #"^[A-Za-z0-9:_.@-]{8,256}$"#,
                  options: .regularExpression
              ) != nil,
              let actionCAID = context["action_caid"]?.stringValue,
              let actionDigest = context["action_digest"]?.stringValue,
              actionDigest == challenge.actionHash,
              let mobileBinding = context["mobile_binding"]?.objectValue,
              mobileBinding["profile_hash"]?.stringValue == challenge.profileHash
        else { throw EmiliaMobileError.contextMismatch }
        let actionIdentity: EmiliaActionIdentity
        do {
            actionIdentity = try EmiliaActionIdentity(
                actionCAID: actionCAID,
                actionDigest: actionDigest
            )
        } catch {
            throw EmiliaMobileError.contextMismatch
        }
        guard actionIdentity == derivedActionIdentity else {
            throw EmiliaMobileError.actionMismatch
        }
        if let expectedActionReference, expectedActionReference != actionReference {
            throw EmiliaMobileError.contextMismatch
        }
        if let expectedActionIdentity, expectedActionIdentity != actionIdentity {
            throw EmiliaMobileError.contextMismatch
        }
        guard let decisionValue = context["decision"]?.stringValue,
              let decision = EmiliaMobileDecision(rawValue: decisionValue)
        else { throw EmiliaMobileError.contextMismatch }
        if let requestedDecision, requestedDecision != decision {
            throw EmiliaMobileError.decisionMismatch
        }

        let contextChallenge = try EmiliaCanonicalJSON.sha256(challenge.authorizationContext).emiliaBase64URL
        guard contextChallenge == challenge.webauthn.challenge else { throw EmiliaMobileError.contextMismatch }
        guard let platform = mobileBinding["platform"]?.stringValue,
              let appID = mobileBinding["app_id"]?.stringValue,
              let deviceKeyID = mobileBinding["device_key_id"]?.stringValue,
              let attestationKeyID = mobileBinding["attestation_key_id"]?.stringValue,
              ["ios", "android"].contains(platform),
              challenge.attestation.format == (platform == "ios" ? "apple-app-attest" : "play-integrity-standard")
        else { throw EmiliaMobileError.contextMismatch }
        let expectedBinding = EmiliaJSONValue.object([
            "@version": .string("EP-MOBILE-ATTESTATION-BINDING-v1"),
            "challenge_id": .string(challenge.challengeID),
            "nonce": .string(challenge.nonce),
            "action_hash": .string(challenge.actionHash),
            "context_hash": .string(try EmiliaCanonicalJSON.digest(challenge.authorizationContext)),
            "profile_hash": .string(challenge.profileHash),
            "rp_id": .string(challenge.webauthn.rpID),
            "platform": .string(platform),
            "app_id": .string(appID),
            "device_key_id": .string(deviceKeyID),
            "attestation_key_id": .string(attestationKeyID),
        ])
        guard challenge.attestation.binding == expectedBinding else { throw EmiliaMobileError.contextMismatch }
        let requestHash = try EmiliaCanonicalJSON.sha256(challenge.attestation.binding)
        guard requestHash.emiliaBase64URL == challenge.attestation.requestHash else {
            throw EmiliaMobileError.contextMismatch
        }
        return EmiliaValidatedChallenge(
            challenge: challenge,
            context: context,
            mobileBinding: mobileBinding,
            requestHash: requestHash,
            presentation: presentation,
            decision: decision,
            actionReference: actionReference,
            actionIdentity: actionIdentity
        )
    }
}

public actor EmiliaMobileCeremonyCoordinator {
    private let passkeys: any EmiliaPasskeyAssertionProvider
    private let integrity: any EmiliaPlatformIntegrityProvider
    private let platform: String
    private let appID: String
    private let deviceKeyID: String

    public init(
        passkeys: any EmiliaPasskeyAssertionProvider,
        integrity: any EmiliaPlatformIntegrityProvider,
        platform: String = "ios",
        appID: String,
        deviceKeyID: String
    ) {
        self.passkeys = passkeys
        self.integrity = integrity
        self.platform = platform
        self.appID = appID
        self.deviceKeyID = deviceKeyID
    }

    public func perform(
        challengeData: Data,
        requestedDecision: EmiliaMobileDecision,
        expectedActionReference: String,
        expectedActionIdentity: EmiliaActionIdentity,
        now: Date = Date()
    ) async throws -> EmiliaMobileCeremonyResponse {
        let validated = try EmiliaMobileChallengeValidator.decodeAndValidate(
            challengeData,
            requestedDecision: requestedDecision,
            expectedActionReference: expectedActionReference,
            expectedActionIdentity: expectedActionIdentity,
            now: now
        )
        let challenge = validated.challenge
        guard platform == validated.mobileBinding["platform"]?.stringValue,
              appID == validated.mobileBinding["app_id"]?.stringValue,
              deviceKeyID == validated.mobileBinding["device_key_id"]?.stringValue,
              integrity.attestationKeyID == validated.mobileBinding["attestation_key_id"]?.stringValue,
              integrity.format == challenge.attestation.format
        else { throw EmiliaMobileError.contextMismatch }
        guard let displayHash = validated.context["display_hash"]?.stringValue
        else { throw EmiliaMobileError.contextMismatch }

        let credentialIDs = try challenge.webauthn.credentialIDs.map { value -> Data in
            guard let data = Data(emiliaBase64URL: value) else { throw EmiliaMobileError.contextMismatch }
            return data
        }
        guard let webauthnChallenge = Data(emiliaBase64URL: challenge.webauthn.challenge) else {
            throw EmiliaMobileError.contextMismatch
        }

        async let integrityToken = integrity.assertion(requestHash: validated.requestHash)
        async let passkey = passkeys.assertion(
            rpID: challenge.webauthn.rpID,
            challenge: webauthnChallenge,
            allowedCredentialIDs: credentialIDs
        )
        let (platformAssertion, assertion) = try await (integrityToken, passkey)
        guard challenge.webauthn.credentialIDs.contains(assertion.credentialID.emiliaBase64URL) else {
            throw EmiliaMobileError.contextMismatch
        }

        return EmiliaMobileCeremonyResponse(
            challengeID: challenge.challengeID,
            nonce: challenge.nonce,
            platform: platform,
            appID: appID,
            deviceKeyID: deviceKeyID,
            credentialID: assertion.credentialID.emiliaBase64URL,
            attestationKeyID: integrity.attestationKeyID,
            decision: requestedDecision.rawValue,
            displayHash: displayHash,
            signoff: .init(
                context: challenge.authorizationContext,
                webauthn: .init(
                    authenticatorData: assertion.authenticatorData.emiliaBase64URL,
                    clientDataJSON: assertion.clientDataJSON.emiliaBase64URL,
                    signature: assertion.signature.emiliaBase64URL
                )
            ),
            attestation: .init(
                format: integrity.format,
                token: platformAssertion.token.emiliaBase64URL,
                deviceKeySignature: platformAssertion.deviceKeySignature?.emiliaBase64URL
            )
        )
    }
}
