// SPDX-License-Identifier: Apache-2.0
import Foundation
import Testing
@testable import EmiliaMobile

private let fixedNow = ISO8601DateFormatter().date(from: "2026-07-14T19:02:00Z")!
private let appAttestKeyID = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH/8="
private let actionReference = "mobact_0123456789abcdef0123456789abcdef"
private let actionCAID =
    "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:XupRmBfC67-VesxXE_EsP8EIlpcZHAypJePGjxRYYXM"
private let case9482ActionDigest =
    "sha256:f6a151156b476ece29dab84266ab4a94abd81bd683a222942681d2850cb26f4e"

private struct SharedVectors: Decodable {
    struct Vector: Decodable {
        let id: String
        let value: EmiliaJSONValue
        let canonical: String
        let sha256: String
    }
    let canonicalization: [Vector]
}

private let case9482Action: EmiliaJSONValue = .object([
    "action_type": .string("benefit.payment_destination_change"),
    "case_id": .string("case-9482"),
    "destination_last4": .string("4401"),
])

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
    let attestationKeyID = appAttestKeyID
    func assertion(requestHash: Data) async throws -> EmiliaPlatformIntegrityAssertion {
        #expect(requestHash.count == 32)
        return EmiliaPlatformIntegrityAssertion(token: Data("app-attest-token".utf8))
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
            attestationKeyID: appAttestKeyID,
            token: Data("app-attest-enrollment".utf8),
            requestHash: requestHash
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
    let action = case9482Action
    let presentation: EmiliaJSONValue = .object([
        "@version": .string("EP-MOBILE-PRESENTATION-v1"),
        "title": .string("Payment destination change"),
        "summary": .string("Change benefit payment destination for case 9482"),
        "risk": .string("high"),
        "consequence": .string("Future benefit payments will be sent to the new destination."),
        "material_fields": .object([
            "action_type": .string("benefit.payment_destination_change"),
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
        "action_reference": .string(actionReference),
        "action_caid": .string(actionCAID),
        "action_digest": .string(actionHash),
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
            "profile": .string(EmiliaMobileChallenge.supportedProfile),
            "profile_hash": .string(profileHash),
            "platform": .string("ios"),
            "app_id": .string("gov.example.ios.approvals"),
            "device_key_id": .string("ep:key:mobile-ios-1"),
            "credential_id": .string(credentialID),
            "attestation_key_id": .string(appAttestKeyID),
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
        "attestation_key_id": .string(appAttestKeyID),
    ])
    var challenge = EmiliaMobileChallenge(
        version: "AE-CHALLENGE-v1",
        challengeProfile: EmiliaMobileChallenge.supportedProfile,
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

private func reboundChallenge(
    _ original: Data,
    mutateAction: ((inout [String: Any]) -> Void)? = nil,
    signedActionCAID: String? = nil
) throws -> Data {
    var root = try #require(try JSONSerialization.jsonObject(with: original) as? [String: Any])
    var action = try #require(root["action"] as? [String: Any])
    mutateAction?(&action)
    root["action"] = action
    let actionData = try JSONSerialization.data(withJSONObject: action)
    let actionValue = try JSONDecoder().decode(EmiliaJSONValue.self, from: actionData)
    let actionDigest = try EmiliaCanonicalJSON.digest(actionValue)
    root["action_hash"] = actionDigest

    var presentation = try #require(root["presentation"] as? [String: Any])
    presentation["material_fields"] =
        try EmiliaMobileChallengeValidator.projectMaterialFields(from: actionValue)
    root["presentation"] = presentation
    let presentationData = try JSONSerialization.data(withJSONObject: presentation)
    let presentationValue = try JSONDecoder().decode(
        EmiliaJSONValue.self,
        from: presentationData
    )

    var context = try #require(root["authorization_context"] as? [String: Any])
    context["action_hash"] = actionDigest
    context["action_digest"] = actionDigest
    context["display_hash"] = try EmiliaCanonicalJSON.digest(presentationValue)
    if let signedActionCAID {
        context["action_caid"] = signedActionCAID
    }
    root["authorization_context"] = context
    let contextData = try JSONSerialization.data(withJSONObject: context)
    let contextValue = try JSONDecoder().decode(EmiliaJSONValue.self, from: contextData)

    var webauthn = try #require(root["webauthn"] as? [String: Any])
    webauthn["challenge"] = try EmiliaCanonicalJSON.sha256(contextValue).emiliaBase64URL
    root["webauthn"] = webauthn

    var attestation = try #require(root["attestation"] as? [String: Any])
    var binding = try #require(attestation["binding"] as? [String: Any])
    binding["action_hash"] = actionDigest
    binding["context_hash"] = try EmiliaCanonicalJSON.digest(contextValue)
    attestation["binding"] = binding
    let bindingData = try JSONSerialization.data(withJSONObject: binding)
    let bindingValue = try JSONDecoder().decode(EmiliaJSONValue.self, from: bindingData)
    attestation["request_hash"] = try EmiliaCanonicalJSON.sha256(bindingValue).emiliaBase64URL
    root["attestation"] = attestation
    return try JSONSerialization.data(withJSONObject: root)
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

@Test func actionIdentityMatchesTheCase9482Vector() throws {
    let identity = try EmiliaActionIdentity.derive(from: case9482Action)
    #expect(identity.actionDigest == case9482ActionDigest)
    #expect(identity.actionCAID == actionCAID)
    #expect(identity.fingerprint == "5EEA-5198-17C2-EBBF")
}

@Test func controlledPresentationMatchesSharedMappingVectors() throws {
    let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let data = try Data(contentsOf: repository.appending(path: "mobile/conformance/mobile-core.v1.json"))
    let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    let vectors = try #require(root["presentation_mapping"] as? [[String: Any]])

    for vector in vectors {
        let id = try #require(vector["id"] as? String)
        let expectedAccept = try #require(vector["expect"] as? String) == "accept"
        var action = try #require(vector["action"] as? [String: Any])
        var materialFields = try #require(vector["material_fields"] as? [String: Any])
        if let repeated = vector["repeat_scalar"] as? [String: Any] {
            let field = try #require(repeated["field"] as? String)
            let codePoint = try #require(repeated["code_point"] as? Int)
            let count = try #require(repeated["count"] as? Int)
            let scalar = try #require(UnicodeScalar(codePoint))
            let value = String(repeating: String(scalar), count: count)
            action[field] = value
            materialFields[field] = value
        }

        var accepted = false
        do {
            let actionData = try JSONSerialization.data(withJSONObject: action)
            let actionValue = try JSONDecoder().decode(EmiliaJSONValue.self, from: actionData)
            let expectedFields = try #require(materialFields as? [String: String])
            let presentation: EmiliaJSONValue = .object([
                "@version": .string(EmiliaMobilePresentation.version),
                "title": .string("Controlled action"),
                "summary": .string("Review every exact raw field."),
                "risk": .string("consequential"),
                "consequence": .string("The selected decision applies only to these exact values."),
                "material_fields": .object(expectedFields.mapValues(EmiliaJSONValue.string)),
            ])
            let validated = try EmiliaMobileChallengeValidator.validatePresentation(
                presentation,
                for: actionValue
            )
            accepted = true
            #expect(validated.materialFields == expectedFields, Comment(rawValue: id))
        } catch {
            accepted = false
        }
        #expect(accepted == expectedAccept, Comment(rawValue: id))
    }
}

@Test func projectorRefusesAnUnsafeDirectInteger() {
    #expect(throws: EmiliaMobileError.displayMismatch) {
        try EmiliaMobileChallengeValidator.projectMaterialFields(from: .object([
            "action_type": .string("treasury.disbursement.release"),
            "amount_minor": .integer(9_007_199_254_740_992),
        ]))
    }
}

@Test func validatesAndBuildsThePortableCeremonyResponse() async throws {
    let credentialID = Data("credential-1".utf8)
    let data = try challengeData()
    let challenge = try JSONDecoder().decode(EmiliaMobileChallenge.self, from: data)
    let identity = try EmiliaActionIdentity(
        actionCAID: actionCAID,
        actionDigest: challenge.actionHash
    )
    let coordinator = EmiliaMobileCeremonyCoordinator(
        passkeys: MockPasskey(credentialID: credentialID),
        integrity: MockIntegrity(),
        appID: "gov.example.ios.approvals",
        deviceKeyID: "ep:key:mobile-ios-1"
    )
    let response = try await coordinator.perform(
        challengeData: data,
        requestedDecision: .approved,
        expectedActionReference: actionReference,
        expectedActionIdentity: identity,
        now: fixedNow
    )
    #expect(response.version == "EP-MOBILE-CEREMONY-v1")
    #expect(response.decision == "approved")
    #expect(response.credentialID == credentialID.emiliaBase64URL)
    #expect(response.attestation.format == "apple-app-attest")
    #expect(response.attestationKeyID == appAttestKeyID)
    #expect(response.attestation.deviceKeySignature == nil)
}

@Test func refusesApproveVersusDenyInversionBeforeSigning() throws {
    #expect(throws: EmiliaMobileError.decisionMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(
            challengeData(),
            requestedDecision: .denied,
            now: fixedNow
        )
    }
}

@Test func v2RequiresAndMatchesTheSelectedInboxActionIdentity() throws {
    let original = try challengeData()
    let challenge = try JSONDecoder().decode(EmiliaMobileChallenge.self, from: original)
    let expectedIdentity = try EmiliaActionIdentity(
        actionCAID: actionCAID,
        actionDigest: challenge.actionHash
    )
    let validated = try EmiliaMobileChallengeValidator.decodeAndValidate(
        original,
        requestedDecision: .approved,
        expectedActionReference: actionReference,
        expectedActionIdentity: expectedIdentity,
        now: fixedNow
    )
    #expect(validated.actionReference == actionReference)
    #expect(validated.actionIdentity == expectedIdentity)

    var missingObject = try #require(
        try JSONSerialization.jsonObject(with: original) as? [String: Any]
    )
    var missingContext = try #require(missingObject["authorization_context"] as? [String: Any])
    missingContext.removeValue(forKey: "action_caid")
    missingObject["authorization_context"] = missingContext
    let missing = try JSONSerialization.data(withJSONObject: missingObject)
    #expect(throws: EmiliaMobileError.contextMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(missing, now: fixedNow)
    }

    let differentIdentity = try EmiliaActionIdentity(
        actionCAID: "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        actionDigest: challenge.actionHash
    )
    #expect(throws: EmiliaMobileError.contextMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(
            original,
            requestedDecision: .approved,
            expectedActionReference: actionReference,
            expectedActionIdentity: differentIdentity,
            now: fixedNow
        )
    }
}

@Test func refusesReboundSignedCAIDAndAuthoritativeActionMutations() throws {
    let original = try challengeData()
    let substitutedCAID = try reboundChallenge(
        original,
        signedActionCAID:
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    #expect(throws: EmiliaMobileError.actionMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(substitutedCAID, now: fixedNow)
    }

    let mutatedAction = try reboundChallenge(original) { action in
        action["destination_last4"] = "9999"
    }
    #expect(throws: EmiliaMobileError.actionMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(mutatedAction, now: fixedNow)
    }
}

@Test func sampleRequiresVerifiedDecisionMatchBeforeSealedStatus() throws {
    let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let source = try String(contentsOf: repository.appending(
        path: "examples/mobile-government/ios/Sources/ApprovalViewModel.swift"
    ), encoding: .utf8)
    #expect(source.contains("guard result.decision == pendingDecision.rawValue"))
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

@Test func refusesUnknownAndNestedPresentationFieldsBeforeSigning() throws {
    let original = try challengeData()
    var unknownObject = try #require(try JSONSerialization.jsonObject(with: original) as? [String: Any])
    var unknownPresentation = try #require(unknownObject["presentation"] as? [String: Any])
    unknownPresentation["hidden_detail"] = "not rendered"
    unknownObject["presentation"] = unknownPresentation
    let unknown = try JSONSerialization.data(withJSONObject: unknownObject)
    #expect(throws: EmiliaMobileError.displayMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(unknown, now: fixedNow)
    }

    var nestedObject = try #require(try JSONSerialization.jsonObject(with: original) as? [String: Any])
    var nestedPresentation = try #require(nestedObject["presentation"] as? [String: Any])
    var materialFields = try #require(nestedPresentation["material_fields"] as? [String: Any])
    materialFields["hidden"] = ["nested": true]
    nestedPresentation["material_fields"] = materialFields
    nestedObject["presentation"] = nestedPresentation
    let nested = try JSONSerialization.data(withJSONObject: nestedObject)
    #expect(throws: EmiliaMobileError.displayMismatch) {
        try EmiliaMobileChallengeValidator.decodeAndValidate(nested, now: fixedNow)
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
    #expect(response.attestationKeyID == appAttestKeyID)
    #expect(response.platformAttestation.requestHash == response.platformRequestHash)
}

@Test func actionContinuityDecodesExpandedContractAndGatesExecutedLabel() throws {
    let actionDigest = "sha256:" + String(repeating: "a", count: 64)
    let outcomeDigest = "sha256:" + String(repeating: "b", count: 64)
    let evidenceDigest = "sha256:" + String(repeating: "c", count: 64)
    let profileHash = "sha256:" + String(repeating: "d", count: 64)
    let passportPayload: EmiliaJSONValue = .object([
        "@version": .string(EmiliaDecisionPassport.version),
        "action": .object([
            "action_reference": .string(actionReference),
            "action_caid": .string(actionCAID),
            "action_digest": .string(actionDigest),
        ]),
        "decision": .object([
            "challenge_id": .string("mob_0123456789abcdef"),
            "verdict": .string("verified"),
            "decided_at": .string("2026-07-20T20:00:00.000Z"),
            "evidence_digest": .string(evidenceDigest),
        ]),
        "lifecycle": .object([
            "state": .string("EXECUTED"),
            "retry_safe": .bool(false),
            "quorum": .object([
                "approved": .integer(2),
                "required": .integer(2),
                "denied": .integer(0),
                "withdrawn": .integer(0),
            ]),
            "consumption_nonce": .string("consume-0123456789abcdef"),
            "outcome_digest": .string(outcomeDigest),
        ]),
        "created_at": .string("2026-07-20T19:00:00.000Z"),
    ])
    var passport = try #require(passportPayload.objectValue)
    passport["passport_digest"] = .string(try EmiliaCanonicalJSON.digest(passportPayload))
    let expanded: EmiliaJSONValue = .object([
        "action_reference": .string(actionReference),
        "title": .string("Release protected payment"),
        "summary": .string("Release the exact payment."),
        "risk": .string("critical"),
        "material_fields": .object(["amount": .string("$250,000")]),
        "expires_at": .string("2026-07-20T21:00:00.000Z"),
        "created_at": .string("2026-07-20T19:00:00.000Z"),
        "status": .string("approved"),
        "revision": .integer(2),
        "identity": .object([
            "action_caid": .string(actionCAID),
            "action_digest": .string(actionDigest),
            "fingerprint": .string("5EEA-5198-17C2-EBBF"),
        ]),
        "supersedes_action_caid": .string(
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        ),
        "changes": .array([
            .object([
                "field": .string("amount"),
                "change": .string("changed"),
                "before": .string("$200,000"),
                "after": .string("$250,000"),
            ]),
        ]),
        "continuity": .object([
            "state": .string("EXECUTED"),
            "retry_safe": .bool(false),
            "quorum": .object([
                "approved": .integer(2),
                "required": .integer(2),
                "denied": .integer(0),
                "withdrawn": .integer(0),
            ]),
        ]),
        "quorum": .object([
            "approved": .integer(2),
            "required": .integer(2),
            "denied": .integer(0),
            "withdrawn": .integer(0),
        ]),
        "alignments": .array([
            .object([
                "system": .string("Treasury"),
                "verdict": .string("EQUIVALENT_UNDER_PROFILE"),
                "profile_id": .string("ep:map:treasury:v1"),
                "profile_hash": .string(profileHash),
                "native_verified": .bool(true),
                "evidence_digest": .string(evidenceDigest),
                "reason": .null,
            ]),
        ]),
        "events": .array([
            .object([
                "event_id": .string("mae_0123456789abcdef0123456789abcdef"),
                "type": .string("executed"),
                "details": .object([:]),
                "evidence_digest": .string(outcomeDigest),
                "created_at": .string("2026-07-20T20:05:00.000Z"),
            ]),
        ]),
        "can_withdraw": .bool(false),
        "passport": .object(passport),
    ])
    let action = try JSONDecoder().decode(
        EmiliaMobileAction.self,
        from: EmiliaCanonicalJSON.encode(expanded)
    )
    #expect(action.identity?.fingerprint == "5EEA-5198-17C2-EBBF")
    #expect(action.quorumProgress?.remaining == 0)
    #expect(action.alignments.first?.effectiveVerdict == .equivalentUnderProfile)
    #expect(action.lifecycleLabel == "EXECUTED")
    #expect(action.canDisplayExecuted)
    #expect(try action.passport?.shareableJSON().contains("\"passport_digest\"") == true)

    var unverifiedPassport = passport
    var lifecycle = try #require(unverifiedPassport["lifecycle"]?.objectValue)
    lifecycle["outcome_digest"] = .string("sha256:" + String(repeating: "e", count: 64))
    unverifiedPassport["lifecycle"] = .object(lifecycle)
    var unverifiedExpanded = try #require(expanded.objectValue)
    unverifiedExpanded["passport"] = .object(unverifiedPassport)
    let unverified = try JSONDecoder().decode(
        EmiliaMobileAction.self,
        from: EmiliaCanonicalJSON.encode(.object(unverifiedExpanded))
    )
    #expect(!unverified.canDisplayExecuted)
    #expect(unverified.lifecycleLabel == "OUTCOME UNVERIFIED")
}

@Test func actionContinuityKeepsLegacyResponsesDecodableAndRefusesFingerprintSubstitution() throws {
    let legacy = Data(
        """
        {
          "action_reference":"mobact_0123456789abcdef0123456789abcdef",
          "title":"Legacy action",
          "summary":"Legacy response",
          "risk":"high",
          "material_fields":{"case":"42"},
          "expires_at":"2026-07-20T21:00:00.000Z",
          "created_at":"2026-07-20T19:00:00.000Z"
        }
        """.utf8
    )
    let action = try JSONDecoder().decode(EmiliaMobileAction.self, from: legacy)
    #expect(action.status == "pending")
    #expect(action.revision == 1)
    #expect(action.identity == nil)
    #expect(action.changes.isEmpty)
    #expect(!action.canWithdraw)

    let substituted = Data(
        """
        {
          "action_reference":"mobact_0123456789abcdef0123456789abcdef",
          "identity":{
            "action_caid":"\(actionCAID)",
            "action_digest":"sha256:\(String(repeating: "a", count: 64))",
            "fingerprint":"BBBB-BBBB-BBBB-BBBB"
          }
        }
        """.utf8
    )
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(EmiliaMobileAction.self, from: substituted)
    }
}
