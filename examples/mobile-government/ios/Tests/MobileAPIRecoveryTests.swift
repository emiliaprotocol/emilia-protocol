// SPDX-License-Identifier: Apache-2.0
import Foundation
import XCTest
@testable import EmiliaMobile

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
                response: fixture.response
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
                    response: fixture.response
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
            _ = try await api(session: session).verify(challenge: fixture.challenge, response: fixture.response)
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
            _ = try await api(session: session).verify(challenge: fixture.challenge, response: fixture.response)
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
            _ = try await api(session: session).verify(challenge: fixture.challenge, response: fixture.response)
            XCTFail("Expected session expiry")
        } catch APIError.sessionExpired {
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        } catch {
            XCTFail("Expected sessionExpired, got \(error)")
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

    private func makeFixture() throws -> Fixture {
        let decision = "approved"
        let context: EmiliaJSONValue = .object([
            "action_hash": .string("sha256:" + String(repeating: "a", count: 64)),
            "decision": .string(decision),
            "nonce": .string("sig_0123456789abcdef0123456789abcdef"),
        ])
        let challenge = EmiliaMobileChallenge(
            version: "AE-CHALLENGE-v1",
            challengeProfile: "EP-MOBILE-CHALLENGE-v1",
            challengeID: "mob_0123456789abcdef",
            nonce: "sig_0123456789abcdef0123456789abcdef",
            action: .object(["amount": .integer(10)]),
            actionHash: "sha256:" + String(repeating: "a", count: 64),
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
            contextHash: try EmiliaCanonicalJSON.digest(context)
        )
    }
}

private struct Fixture {
    let challenge: EmiliaMobileChallenge
    let response: EmiliaMobileCeremonyResponse
    let decision: String
    let contextHash: String
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

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return capturedRequests
    }

    static func install(_ newStubs: [HTTPStub]) {
        lock.lock()
        stubs = newStubs
        capturedRequests = []
        lock.unlock()
    }

    static func reset() { install([]) }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.capturedRequests.append(request)
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
}
