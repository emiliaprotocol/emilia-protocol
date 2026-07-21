// SPDX-License-Identifier: Apache-2.0
import Foundation
import XCTest
import EmiliaMobile
@testable import EMILIA_Approver

@MainActor
final class MobileAPIRecoveryTests: XCTestCase {
    private let token = "mobile-access-token"

    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    func testEveryServerErrorRecoversCommittedOutcomeWithAuthentication() async throws {
        let fixture = try makeFixture()

        for status in [500, 502, 503, 599] {
            StubURLProtocol.install([
                .json(status: status, object: ["detail": "server_failure"]),
                try committedRecovery(decision: fixture.decision, contextHash: fixture.contextHash),
            ])
            let session = stubbedSession()
            let result = try await api(session: session).verify(
                challenge: fixture.challenge,
                response: fixture.response,
                expectedActionReference: fixture.actionReference,
                expectedActionIdentity: fixture.identity
            )

            XCTAssertEqual(result.decision, fixture.decision, "status \(status)")
            XCTAssertEqual(result.contextHash, fixture.contextHash, "status \(status)")
            let requests = StubURLProtocol.requests
            XCTAssertEqual(requests.compactMap(\.httpMethod), ["POST", "GET"], "status \(status)")
            XCTAssertEqual(requests.last?.url?.path, "/api/v1/mobile/ceremonies/\(fixture.challenge.challengeID)")
            XCTAssertEqual(requests.last?.value(forHTTPHeaderField: "Authorization"), "Bearer \(token)")
            session.invalidateAndCancel()
        }
    }

    func testRecoveredOutcomeMustMatchDecisionAndCanonicalContext() async throws {
        let fixture = try makeFixture()
        let mismatches = [
            ("denied", fixture.contextHash),
            (fixture.decision, "sha256:" + String(repeating: "f", count: 64)),
        ]

        for (decision, contextHash) in mismatches {
            StubURLProtocol.install([
                .json(status: 500, object: ["detail": "server_failure"]),
                try committedRecovery(decision: decision, contextHash: contextHash),
            ])
            let session = stubbedSession()
            do {
                _ = try await api(session: session).verify(
                    challenge: fixture.challenge,
                    response: fixture.response,
                    expectedActionReference: fixture.actionReference,
                    expectedActionIdentity: fixture.identity
                )
                XCTFail("A mismatched recovered result must not be accepted")
            } catch APIError.outcomeUnknown {
                XCTAssertEqual(StubURLProtocol.requests.count, 2)
            } catch {
                XCTFail("Expected outcomeUnknown, got \(error)")
            }
            session.invalidateAndCancel()
        }
    }

    func testUnresolvedRecoveryReturnsOutcomeUnknown() async throws {
        let fixture = try makeFixture()
        StubURLProtocol.install([
            .json(status: 504, object: ["detail": "timeout"]),
            .json(status: 200, object: ["committed": false, "outcome": "unknown", "result": NSNull()]),
        ])
        let session = stubbedSession()

        do {
            _ = try await api(session: session).verify(
                challenge: fixture.challenge,
                response: fixture.response,
                expectedActionReference: fixture.actionReference,
                expectedActionIdentity: fixture.identity
            )
            XCTFail("An unresolved recovery must not permit retry")
        } catch APIError.outcomeUnknown {
            XCTAssertEqual(StubURLProtocol.requests.count, 2)
        } catch {
            XCTFail("Expected outcomeUnknown, got \(error)")
        }
        session.invalidateAndCancel()
    }

    func testFourHundredsKeepExistingHandlingWithoutRecovery() async throws {
        let fixture = try makeFixture()
        StubURLProtocol.install([.json(status: 409, object: ["detail": "ceremony_conflict"])])
        var session = stubbedSession()

        do {
            _ = try await api(session: session).verify(
                challenge: fixture.challenge,
                response: fixture.response,
                expectedActionReference: fixture.actionReference,
                expectedActionIdentity: fixture.identity
            )
            XCTFail("Expected refusal")
        } catch APIError.refused(let detail) {
            XCTAssertEqual(detail, "ceremony_conflict")
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        } catch {
            XCTFail("Expected refused, got \(error)")
        }
        session.invalidateAndCancel()

        StubURLProtocol.install([.json(status: 401, object: ["detail": "expired"])])
        session = stubbedSession()
        do {
            _ = try await api(session: session).verify(
                challenge: fixture.challenge,
                response: fixture.response,
                expectedActionReference: fixture.actionReference,
                expectedActionIdentity: fixture.identity
            )
            XCTFail("Expected session expiry")
        } catch APIError.sessionExpired {
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        } catch {
            XCTFail("Expected sessionExpired, got \(error)")
        }
        session.invalidateAndCancel()
    }

    func testDirectResponseRequiresVerifiedVerdictAndMatchingContextHash() async throws {
        let fixture = try makeFixture()
        let responses: [[String: Any]] = [
            [
                "valid": true,
                "verdict": "accepted",
                "decision": fixture.decision,
                "context_hash": fixture.contextHash,
            ],
            [
                "valid": true,
                "verdict": "verified",
                "decision": fixture.decision,
                "context_hash": "sha256:" + String(repeating: "f", count: 64),
            ],
            [
                "valid": false,
                "verdict": "verified",
                "decision": fixture.decision,
                "context_hash": fixture.contextHash,
            ],
        ]

        for object in responses {
            StubURLProtocol.install([.json(status: 200, object: object)])
            let session = stubbedSession()
            do {
                _ = try await api(session: session).verify(
                    challenge: fixture.challenge,
                    response: fixture.response,
                    expectedActionReference: fixture.actionReference,
                    expectedActionIdentity: fixture.identity
                )
                XCTFail("A direct response without the exact verified result must be refused")
            } catch APIError.refused(let reason) {
                XCTAssertEqual(reason, "unverified_ceremony_response")
                XCTAssertEqual(StubURLProtocol.requests.count, 1)
            } catch {
                XCTFail("Expected refusal, got \(error)")
            }
            session.invalidateAndCancel()
        }
    }

    func testSelectedActionIdentityMismatchIsRejectedBeforeNetwork() async throws {
        let fixture = try makeFixture()
        let mismatched = try EmiliaActionIdentity(
            actionCAID: "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            actionDigest: fixture.identity.actionDigest
        )
        StubURLProtocol.install([])
        let session = stubbedSession()

        do {
            _ = try await api(session: session).verify(
                challenge: fixture.challenge,
                response: fixture.response,
                expectedActionReference: fixture.actionReference,
                expectedActionIdentity: mismatched
            )
            XCTFail("A selected-action CAID mismatch must be refused before transport")
        } catch APIError.refused(let reason) {
            XCTAssertEqual(reason, "action_identity_mismatch")
            XCTAssertTrue(StubURLProtocol.requests.isEmpty)
        } catch {
            XCTFail("Expected identity refusal, got \(error)")
        }
        session.invalidateAndCancel()
    }

    func testHistoryPassportAndWithdrawalUseFixedActionContract() async throws {
        let actionReference = "grace:event@42"
        StubURLProtocol.install([
            .json(status: 200, object: ["approver_id": "approver-1", "actions": []]),
            try passportStub(actionReference: actionReference),
            .json(status: 200, object: ["withdrawn": true, "state": "withdrawn"]),
        ])
        let session = stubbedSession()
        let client = api(session: session)

        let history = try await client.history()
        XCTAssertTrue(history.isEmpty)
        let passport = try await client.passport(actionReference: actionReference)
        XCTAssertTrue(passport.hasValidDigest)
        let withdrawal = try await client.withdraw(actionReference: actionReference)
        XCTAssertTrue(withdrawal.withdrawn)
        XCTAssertEqual(withdrawal.state, .withdrawn)

        let requests = StubURLProtocol.requests
        XCTAssertEqual(requests.compactMap(\.httpMethod), ["GET", "GET", "POST"])
        XCTAssertEqual(requests[0].url?.path, "/api/v1/mobile/history")
        XCTAssertTrue(
            requests[1].url?.absoluteString.contains("grace%3Aevent%4042/passport") == true
        )
        XCTAssertTrue(
            requests[2].url?.absoluteString.contains("grace%3Aevent%4042/withdraw") == true
        )
        XCTAssertEqual(StubURLProtocol.requestBodies[2], Data("{}".utf8))
        XCTAssertEqual(requests[2].value(forHTTPHeaderField: "Authorization"), "Bearer \(token)")
        session.invalidateAndCancel()
    }

    func testWithdrawalConflictIsRefusedWithoutRetry() async throws {
        StubURLProtocol.install([
            .json(status: 409, object: ["detail": "action_already_consumed"]),
        ])
        let session = stubbedSession()

        do {
            _ = try await api(session: session).withdraw(
                actionReference: "case-9482"
            )
            XCTFail("A consumed action must not be reported as withdrawn")
        } catch APIError.refused(let reason) {
            XCTAssertEqual(reason, "action_already_consumed")
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        } catch {
            XCTFail("Expected withdrawal refusal, got \(error)")
        }
        session.invalidateAndCancel()
    }

    private func api(session: URLSession) -> MobileAPI {
        MobileAPI(
            baseURL: URL(string: "https://www.emiliaprotocol.ai/api/")!,
            accessToken: token,
            session: session
        )
    }

    private func stubbedSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    private func committedRecovery(decision: String, contextHash: String) throws -> HTTPStub {
        .json(status: 200, object: [
            "committed": true,
            "outcome": "committed",
            "result": [
                "valid": true,
                "verdict": "verified",
                "decision": decision,
                "context_hash": contextHash,
            ],
        ])
    }

    private func passportStub(actionReference: String) throws -> HTTPStub {
        let actionCAID =
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:XupRmBfC67-VesxXE_EsP8EIlpcZHAypJePGjxRYYXM"
        let actionDigest =
            "sha256:f6a151156b476ece29dab84266ab4a94abd81bd683a222942681d2850cb26f4e"
        let payload: EmiliaJSONValue = .object([
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
                "evidence_digest": .string("sha256:" + String(repeating: "b", count: 64)),
            ]),
            "lifecycle": .object([
                "state": .string("CONSUMED"),
                "retry_safe": .bool(false),
                "quorum": .object([
                    "approved": .integer(1),
                    "required": .integer(1),
                    "denied": .integer(0),
                    "withdrawn": .integer(0),
                ]),
                "consumption_nonce": .string("consume-0123456789abcdef"),
                "outcome_digest": .null,
            ]),
            "created_at": .string("2026-07-20T19:00:00.000Z"),
        ])
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: EmiliaCanonicalJSON.encode(payload)
            ) as? [String: Any]
        )
        object["passport_digest"] = try EmiliaCanonicalJSON.digest(payload)
        return .json(status: 200, object: ["passport": object])
    }

    private func makeFixture() throws -> Fixture {
        let decision = "approved"
        let actionReference = "mobact_0123456789abcdef0123456789abcdef"
        let actionCAID =
            "caid:1:emilia.mobile.authorized-action.1:jcs-sha256:XupRmBfC67-VesxXE_EsP8EIlpcZHAypJePGjxRYYXM"
        let actionDigest =
            "sha256:f6a151156b476ece29dab84266ab4a94abd81bd683a222942681d2850cb26f4e"
        let identity = try EmiliaActionIdentity(
            actionCAID: actionCAID,
            actionDigest: actionDigest
        )
        let context: EmiliaJSONValue = .object([
            "action_hash": .string(actionDigest),
            "action_reference": .string(actionReference),
            "action_caid": .string(actionCAID),
            "action_digest": .string(actionDigest),
            "decision": .string(decision),
            "nonce": .string("sig_0123456789abcdef0123456789abcdef"),
        ])
        let challenge = EmiliaMobileChallenge(
            version: "AE-CHALLENGE-v1",
            challengeProfile: EmiliaMobileChallenge.supportedProfile,
            challengeID: "mob_0123456789abcdef",
            nonce: "sig_0123456789abcdef0123456789abcdef",
            action: .object([
                "action_type": .string("benefit.payment_destination_change"),
                "case_id": .string("case-9482"),
                "destination_last4": .string("4401"),
            ]),
            actionHash: actionDigest,
            profileHash: "sha256:" + String(repeating: "b", count: 64),
            authorizationContext: context,
            webauthn: EmiliaWebAuthnRequest(
                rpID: "www.emiliaprotocol.ai",
                challenge: "Y2hhbGxlbmdl",
                credentialIDs: ["Y3JlZGVudGlhbA"],
                userVerification: "required",
                timeoutMS: 300_000
            ),
            presentation: .object(["title": .string("Approve")]),
            attestation: EmiliaAttestationRequest(
                required: true,
                format: "apple-app-attest",
                binding: .object(["challenge_id": .string("mob_0123456789abcdef")]),
                requestHash: "cmVxdWVzdA"
            ),
            issuedAt: "2026-07-16T18:00:00.000Z",
            expiresAt: "2026-07-16T18:05:00.000Z"
        )
        let response = EmiliaMobileCeremonyResponse(
            challengeID: challenge.challengeID,
            nonce: challenge.nonce,
            platform: "ios",
            appID: "ai.emiliaprotocol.approver",
            deviceKeyID: "ep:key:mobile-ios-1",
            credentialID: "Y3JlZGVudGlhbA",
            attestationKeyID: "attestation-key",
            decision: decision,
            displayHash: "sha256:" + String(repeating: "c", count: 64),
            signoff: .init(
                context: context,
                webauthn: .init(authenticatorData: "YQ", clientDataJSON: "Yg", signature: "Yw")
            ),
            attestation: .init(format: "apple-app-attest", token: "ZA", deviceKeySignature: nil)
        )
        return Fixture(
            challenge: challenge,
            response: response,
            decision: decision,
            contextHash: try EmiliaCanonicalJSON.digest(context),
            actionReference: actionReference,
            identity: identity
        )
    }
}

private struct Fixture {
    let challenge: EmiliaMobileChallenge
    let response: EmiliaMobileCeremonyResponse
    let decision: String
    let contextHash: String
    let actionReference: String
    let identity: EmiliaActionIdentity
}

private struct HTTPStub: Sendable {
    let status: Int
    let body: Data

    static func json(status: Int, object: Any) -> HTTPStub {
        HTTPStub(status: status, body: try! JSONSerialization.data(withJSONObject: object))
    }
}

private final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var stubs: [HTTPStub] = []
    nonisolated(unsafe) private static var capturedRequests: [URLRequest] = []
    nonisolated(unsafe) private static var capturedRequestBodies: [Data?] = []

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return capturedRequests
    }

    static var requestBodies: [Data?] {
        lock.lock()
        defer { lock.unlock() }
        return capturedRequestBodies
    }

    static func install(_ newStubs: [HTTPStub]) {
        lock.lock()
        stubs = newStubs
        capturedRequests = []
        capturedRequestBodies = []
        lock.unlock()
    }

    static func reset() { install([]) }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let body = request.httpBody ?? Self.readBody(from: request.httpBodyStream)
        Self.lock.lock()
        Self.capturedRequests.append(request)
        Self.capturedRequestBodies.append(body)
        let stub = Self.stubs.isEmpty ? nil : Self.stubs.removeFirst()
        Self.lock.unlock()

        guard let stub, let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: stub.status,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Type": "application/json",
                    "Content-Length": String(stub.body.count),
                ]
              )
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readBody(from stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }

        var body = Data()
        var buffer = [UInt8](repeating: 0, count: 1_024)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count < 0 { return nil }
            if count == 0 { return body }
            body.append(buffer, count: count)
        }
    }
}
