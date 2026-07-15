// SPDX-License-Identifier: Apache-2.0
import Foundation
import Testing
@testable import EmiliaMobile

private let fixedNow = ISO8601DateFormatter().date(from: "2026-07-14T19:02:00Z")!

private struct SharedVectors: Decodable {
    struct Vector: Decodable {
        let id: String
        let value: EmiliaJSONValue
        let canonical: String
        let sha256: String
    }
    let canonicalization: [Vector]
}

private struct MockPasskey: EmiliaPasskeyAssertionProvider {
    let credentialID: Data
    func assertion(rpID: String, challenge: Data, allowedCredentialIDs: [Data]) async throws -> EmiliaPasskeyAssertion {
        #expect(rpID == "approve.example.gov")
        #expect(allowedCredentialIDs == [credentialID])
        return EmiliaPasskeyAssertion(
            credentialID: credentialID,
            authenticatorData: Data([1, 2, 3]),
            clientDataJSON: Data("client-data".utf8),
            signature: Data([4, 5, 6])
        )
    }
}

private struct MockIntegrity: EmiliaPlatformIntegrityProvider {
    let format = "apple-app-attest"
    let attestationKeyID = "attest_key_1"
    func assertion(requestHash: Data) async throws -> Data {
        #expect(requestHash.count == 32)
        return Data("app-attest-token".utf8)
    }
}

private struct MockRegistration: EmiliaPasskeyRegistrationProvider {
    func registration(
        rpID: String,
        challenge: Data,
        userID: Data,
        userName: String,
        displayName: String
    ) async throws -> EmiliaPasskeyRegistration {
        #expect(rpID == "approve.example.gov")
        #expect(!challenge.isEmpty)
        #expect(!userID.isEmpty)
        return EmiliaPasskeyRegistration(
            credentialID: Data("registered-credential".utf8),
            clientDataJSON: Data("registration-client-data".utf8),
            attestationObject: Data("registration-attestation".utf8)
        )
    }
}

private struct MockPlatformEnrollment: EmiliaPlatformEnrollmentProvider {
    func enrollment(requestHash: Data) async throws -> EmiliaPlatformEnrollment {
        #expect(requestHash.count == 32)
        return EmiliaPlatformEnrollment(
            format: "apple-app-attest-enrollment",
            attestationKeyID: "appattest_enrolled_key_1",
            token: Data("app-attest-enrollment".utf8)
        )
    }
}

private func enrollmentChallengeData() throws -> Data {
    let binding: EmiliaJSONValue = .object([
        "@version": .string("EP-MOBILE-ENROLLMENT-CHALLENGE-v1"),
        "enrollment_id": .string("enr_0123456789abcdef"),
        "challenge": .string(Data("registration-challenge".utf8).emiliaBase64URL),
        "approver_id": .string("ep:approver:case-supervisor"),
        "platform": .string("ios"),
        "app_id": .string("gov.example.approvals"),
        "rp_id": .string("approve.example.gov"),
        "origin": .string("https://approve.example.gov"),
        "enrollment_valid_to": .string("2027-07-14T19:00:00.000Z"),
        "issued_at": .string("2026-07-14T19:00:00.000Z"),
        "expires_at": .string("2026-07-14T19:05:00.000Z"),
    ])
    let challenge = EmiliaMobileEnrollmentChallenge(
        version: "AE-CHALLENGE-v1",
        challengeProfile: "EP-MOBILE-ENROLLMENT-CHALLENGE-v1",
        challengeID: "enr_0123456789abcdef",
        enrollmentID: "enr_0123456789abcdef",
        nonce: "reg_0123456789abcdef",
        challenge: Data("registration-challenge".utf8).emiliaBase64URL,
        approverID: "ep:approver:case-supervisor",
        platform: "ios",
        appID: "gov.example.approvals",
        rpID: "approve.example.gov",
        origin: "https://approve.example.gov",
        user: .init(
            id: Data("ep:approver:case-supervisor".utf8).emiliaBase64URL,
            name: "case-supervisor@example.gov",
            displayName: "Case Supervisor"
        ),
        enrollmentValidTo: "2027-07-14T19:00:00.000Z",
        platformBinding: binding,
        platformRequestHash: try EmiliaCanonicalJSON.sha256(binding).emiliaBase64URL,
        issuedAt: "2026-07-14T19:00:00.000Z",
        expiresAt: "2026-07-14T19:05:00.000Z"
    )
    return try JSONEncoder().encode(challenge)
}

private func challengeData(mutate: ((inout EmiliaMobileChallenge) -> Void)? = nil) throws -> Data {
    let action: EmiliaJSONValue = .object([
        "action_type": .string("benefit.payment_destination_change"),
        "case_id": .string("case-9482"),
        "destination_last4": .string("4401"),
    ])
    let presentation: EmiliaJSONValue = .object([
        "title": .string("Payment destination change"),
        "material_fields": .object([
            "case_id": .string("case-9482"),
            "destination_last4": .string("4401"),
        ]),
    ])
    let actionHash = try EmiliaCanonicalJSON.digest(action)
    let displayHash = try EmiliaCanonicalJSON.digest(presentation)
    let credentialID = Data("credential-1".utf8).emiliaBase64URL
    let profileHash = "sha256:" + String(repeating: "a", count: 64)
    let context: EmiliaJSONValue = .object([
        "ep_version": .string("1.0"),
        "context_type": .string("ep.signoff.v1"),
        "action_hash": .string(actionHash),
        "policy_id": .null,
        "policy_hash": .null,
        "initiator": .string("ep:agent:benefits-assistant"),
        "approver": .string("ep:approver:case-supervisor"),
        "approver_index": .integer(1),
        "required_approvals": .integer(1),
        "nonce": .string("sig_0123456789abcdef0123456789abcdef"),
        "issued_at": .string("2026-07-14T19:00:00.000Z"),
        "expires_at": .string("2026-07-14T19:05:00.000Z"),
        "decision": .string("approved"),
        "display_hash": .string(displayHash),
        "mobile_binding": .object([
            "profile": .string("EP-MOBILE-CHALLENGE-v1"),
            "profile_hash": .string(profileHash),
            "platform": .string("ios"),
            "app_id": .string("gov.example.ios.approvals"),
            "device_key_id": .string("ep:key:mobile-ios-1"),
            "credential_id": .string(credentialID),
            "attestation_key_id": .string("attest_key_1"),
        ]),
    ])
    let challengeID = "mob_0123456789abcdef"
    let binding: EmiliaJSONValue = .object([
        "@version": .string("EP-MOBILE-ATTESTATION-BINDING-v1"),
        "challenge_id": .string(challengeID),
        "nonce": .string("sig_0123456789abcdef0123456789abcdef"),
        "action_hash": .string(actionHash),
        "context_hash": .string(try EmiliaCanonicalJSON.digest(context)),
        "profile_hash": .string(profileHash),
        "rp_id": .string("approve.example.gov"),
        "platform": .string("ios"),
        "app_id": .string("gov.example.ios.approvals"),
        "device_key_id": .string("ep:key:mobile-ios-1"),
        "attestation_key_id": .string("attest_key_1"),
    ])
    var challenge = EmiliaMobileChallenge(
        version: "AE-CHALLENGE-v1",
        challengeProfile: "EP-MOBILE-CHALLENGE-v1",
        challengeID: challengeID,
        nonce: "sig_0123456789abcdef0123456789abcdef",
        action: action,
        actionHash: actionHash,
        profileHash: profileHash,
        authorizationContext: context,
        webauthn: EmiliaWebAuthnRequest(
            rpID: "approve.example.gov",
            challenge: try EmiliaCanonicalJSON.sha256(context).emiliaBase64URL,
            credentialIDs: [credentialID],
            userVerification: "required",
            timeoutMS: 300_000
        ),
        presentation: presentation,
        attestation: EmiliaAttestationRequest(
            required: true,
            format: "apple-app-attest",
            binding: binding,
            requestHash: try EmiliaCanonicalJSON.sha256(binding).emiliaBase64URL
        ),
        issuedAt: "2026-07-14T19:00:00.000Z",
        expiresAt: "2026-07-14T19:05:00.000Z"
    )
    mutate?(&challenge)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(challenge)
}

@Test func canonicalJSONMatchesTheSharedSafeIntegerProfile() throws {
    let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let data = try Data(contentsOf: repository.appending(path: "mobile/conformance/mobile-core.v1.json"))
    let vectors = try JSONDecoder().decode(SharedVectors.self, from: data)
    for vector in vectors.canonicalization {
        let encoded = try #require(String(data: EmiliaCanonicalJSON.encode(vector.value), encoding: .utf8))
        #expect(encoded == vector.canonical, Comment(rawValue: vector.id))
        #expect(try EmiliaCanonicalJSON.digest(vector.value) == "sha256:" + vector.sha256, Comment(rawValue: vector.id))
    }
}

@Test func validatesAndBuildsThePortableCeremonyResponse() async throws {
    let credentialID = Data("credential-1".utf8)
    let coordinator = EmiliaMobileCeremonyCoordinator(
        passkeys: MockPasskey(credentialID: credentialID),
        integrity: MockIntegrity(),
        appID: "gov.example.ios.approvals",
        deviceKeyID: "ep:key:mobile-ios-1"
    )
    let response = try await coordinator.perform(challengeData: challengeData(), now: fixedNow)
    #expect(response.version == "EP-MOBILE-CEREMONY-v1")
    #expect(response.decision == "approved")
    #expect(response.credentialID == credentialID.emiliaBase64URL)
    #expect(response.attestation.format == "apple-app-attest")
}

@Test func refusesMutatedActionAndAttestationBinding() throws {
    let original = try challengeData()
    var object = try #require(try JSONSerialization.jsonObject(with: original) as? [String: Any])
    var action = try #require(object["action"] as? [String: Any])
    action["destination_last4"] = "9999"
    object["action"] = action
    let mutated = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: EmiliaMobileError.actionMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(mutated, now: fixedNow)
    }

    var bindingObject = try #require(try JSONSerialization.jsonObject(with: original) as? [String: Any])
    var attestation = try #require(bindingObject["attestation"] as? [String: Any])
    var binding = try #require(attestation["binding"] as? [String: Any])
    binding["app_id"] = "gov.attacker.app"
    attestation["binding"] = binding
    bindingObject["attestation"] = attestation
    let rebound = try JSONSerialization.data(withJSONObject: bindingObject)
    #expect(throws: EmiliaMobileError.contextMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(rebound, now: fixedNow)
    }
}

@Test func enrollmentBindsPasskeyAndAppAttestToTheSameRequest() async throws {
    let coordinator = EmiliaMobileEnrollmentCoordinator(
        passkeys: MockRegistration(),
        platformEnrollment: MockPlatformEnrollment(),
        appID: "gov.example.approvals"
    )
    let response = try await coordinator.perform(
        challengeData: enrollmentChallengeData(),
        now: fixedNow
    )
    #expect(response.version == "EP-MOBILE-ENROLLMENT-v1")
    #expect(response.passkeyRegistration.type == "public-key")
    #expect(response.attestationKeyID == "appattest_enrolled_key_1")
}
