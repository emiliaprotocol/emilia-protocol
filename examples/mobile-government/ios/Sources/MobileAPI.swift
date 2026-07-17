// SPDX-License-Identifier: Apache-2.0
import EmiliaMobile
import Foundation

private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

struct MobileAPI: Sendable {
    struct PairingResponse: Decodable, Sendable {
        let accessToken: String
        let expiresAt: String
        let approverID: String
        let profileID: String

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case expiresAt = "expires_at"
            case approverID = "approver_id"
            case profileID = "profile_id"
        }
    }

    struct InboxResponse: Decodable, Sendable {
        let approverID: String
        let actions: [InboxAction]

        enum CodingKeys: String, CodingKey {
            case approverID = "approver_id"
            case actions
        }
    }

    struct InboxAction: Decodable, Identifiable, Sendable, Equatable {
        let actionReference: String
        let title: String
        let summary: String
        let risk: String
        let materialFields: [String: String]
        let expiresAt: String
        let createdAt: String

        var id: String { actionReference }

        enum CodingKeys: String, CodingKey {
            case actionReference = "action_reference"
            case title, summary, risk
            case materialFields = "material_fields"
            case expiresAt = "expires_at"
            case createdAt = "created_at"
        }
    }

    struct IssueResponse: Decodable {
        let ok: Bool
        let verdict: String
        let challenge: EmiliaMobileChallenge?
    }

    struct EnrollmentIssueResponse: Decodable {
        let ok: Bool
        let verdict: String
        let challenge: EmiliaMobileEnrollmentChallenge?
    }

    struct VerificationResponse: Decodable {
        let valid: Bool
        let verdict: String
        let decision: String?
        let reason: String?
        let contextHash: String?

        enum CodingKeys: String, CodingKey {
            case valid, verdict, decision, reason
            case contextHash = "context_hash"
        }
    }

    private struct CeremonyRecoveryResponse: Decodable {
        let committed: Bool
        let outcome: String
        let result: VerificationResponse?
    }

    struct EnrollmentResponse: Decodable {
        struct Enrollment: Decodable {
            let deviceKeyID: String
            let attestationKeyID: String

            enum CodingKeys: String, CodingKey {
                case deviceKeyID = "device_key_id"
                case attestationKeyID = "attestation_key_id"
            }
        }
        let ok: Bool
        let verdict: String
        let enrollment: Enrollment?
    }

    let baseURL: URL
    let accessToken: String?
    let session: URLSession
    private static let productionBaseURL = "https://www.emiliaprotocol.ai/api/"
    private static let maximumResponseBytes = 1_048_576

    init(baseURL: URL, accessToken: String? = nil, session: URLSession? = nil) {
        precondition(baseURL.absoluteString == Self.productionBaseURL, "The approval API identity is not pinned")
        self.baseURL = baseURL
        self.accessToken = accessToken
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.urlCache = nil
            configuration.timeoutIntervalForRequest = 15
            configuration.timeoutIntervalForResource = 30
            self.session = URLSession(
                configuration: configuration,
                delegate: NoRedirectSessionDelegate(),
                delegateQueue: nil
            )
        }
    }

    func exchangePairing(code: String, appID: String) async throws -> PairingResponse {
        let body: [String: String] = [
            "pairing_code": code,
            "platform": "ios",
            "app_id": appID,
        ]
        return try await post("v1/mobile/pairings/exchange", body, authenticated: false)
    }

    func inbox() async throws -> [InboxAction] {
        let response: InboxResponse = try await get("v1/mobile/inbox")
        return response.actions
    }

    func issueChallenge(
        requestID: String,
        approverID: String,
        decision: String,
        profileID: String,
        appID: String,
        deviceKeyID: String
    ) async throws -> EmiliaMobileChallenge {
        let body: [String: String] = [
            "profile_id": profileID,
            "action_reference": requestID,
            "approver_id": approverID,
            "decision": decision,
            "platform": "ios",
            "app_id": appID,
            "device_key_id": deviceKeyID,
        ]
        let response: IssueResponse = try await post("v1/mobile/challenges", body)
        guard response.ok, let challenge = response.challenge else { throw APIError.refused(response.verdict) }
        return challenge
    }

    func verify(challenge: EmiliaMobileChallenge, response: EmiliaMobileCeremonyResponse) async throws -> VerificationResponse {
        struct Request: Encodable {
            let challenge: EmiliaMobileChallenge
            let response: EmiliaMobileCeremonyResponse
        }
        guard let expectedDecision = challenge.authorizationContext.decision,
              response.decision == expectedDecision
        else {
            throw APIError.refused("decision_mismatch")
        }
        let expectedContextHash = try EmiliaCanonicalJSON.digest(challenge.authorizationContext)
        do {
            return try await post("v1/mobile/ceremonies", Request(challenge: challenge, response: response))
        } catch APIError.transport {
            return try await recoverCeremonyResult(
                challengeID: challenge.challengeID,
                expectedDecision: challenge.authorizationContext.decision ?? expectedDecision,
                expectedContextHash: expectedContextHash
            )
        }
    }

    func issueEnrollment(approverID: String, appID: String) async throws -> EmiliaMobileEnrollmentChallenge {
        let body: [String: String] = [
            "approver_id": approverID,
            "platform": "ios",
            "app_id": appID,
        ]
        let response: EnrollmentIssueResponse = try await post("v1/mobile/enrollments/challenges", body)
        guard response.ok, let challenge = response.challenge else { throw APIError.refused(response.verdict) }
        return challenge
    }

    func completeEnrollment(
        challenge: EmiliaMobileEnrollmentChallenge,
        response: EmiliaMobileEnrollmentResponse
    ) async throws -> EnrollmentResponse {
        struct Request: Encodable {
            let challenge: EmiliaMobileEnrollmentChallenge
            let response: EmiliaMobileEnrollmentResponse
        }
        return try await post("v1/mobile/enrollments", Request(challenge: challenge, response: response))
    }

    func revokeSession() async throws {
        struct RevocationResponse: Decodable { let revoked: Bool }
        var request = URLRequest(url: endpoint("v1/mobile/session"))
        request.httpMethod = "DELETE"
        authorize(&request)
        let response: RevocationResponse = try await execute(request)
        guard response.revoked else { throw APIError.refused("session_not_revoked") }
    }

    private func get<Response: Decodable>(_ path: String) async throws -> Response {
        var request = URLRequest(url: endpoint(path))
        request.httpMethod = "GET"
        authorize(&request)
        return try await execute(request)
    }

    private func recoverCeremonyResult(
        challengeID: String,
        expectedDecision: String,
        expectedContextHash: String
    ) async throws -> VerificationResponse {
        guard challengeID.range(
            of: #"^[A-Za-z0-9:_.@-]{8,256}$"#,
            options: .regularExpression
        ) != nil else { throw APIError.outcomeUnknown }
        do {
            let recovery: CeremonyRecoveryResponse = try await get("v1/mobile/ceremonies/\(challengeID)")
            guard recovery.committed,
                  recovery.outcome == "committed",
                  let result = recovery.result,
                  result.valid,
                  result.verdict == "verified",
                  result.decision == expectedDecision,
                  result.reason == nil,
                  result.contextHash == expectedContextHash
            else { throw APIError.outcomeUnknown }
            return result
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw APIError.outcomeUnknown
        }
    }

    private func post<Request: Encodable, Response: Decodable>(
        _ path: String,
        _ body: Request,
        authenticated: Bool = true
    ) async throws -> Response {
        var request = URLRequest(url: endpoint(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        if authenticated { authorize(&request) }
        return try await execute(request)
    }

    private func endpoint(_ path: String) -> URL {
        path.split(separator: "/").reduce(baseURL) { partial, component in
            partial.appendingPathComponent(String(component))
        }
    }

    private func authorize(_ request: inout URLRequest) {
        if let accessToken, !accessToken.isEmpty {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
    }

    private func execute<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        do {
            let (bytes, rawResponse) = try await session.bytes(for: request)
            guard let response = rawResponse as? HTTPURLResponse else { throw APIError.transport }
            guard response.url?.scheme == "https",
                  response.url?.host == "www.emiliaprotocol.ai",
                  response.url?.path.hasPrefix("/api/") == true,
                  response.mimeType == "application/json",
                  response.expectedContentLength <= Int64(Self.maximumResponseBytes)
            else { throw APIError.transport }
            var data = Data()
            data.reserveCapacity(max(0, min(Int(response.expectedContentLength), Self.maximumResponseBytes)))
            for try await byte in bytes {
                guard data.count < Self.maximumResponseBytes else { throw APIError.transport }
                data.append(byte)
            }
            guard (200..<300).contains(response.statusCode) else {
                let problem = try? JSONDecoder().decode(ProblemResponse.self, from: data)
                if response.statusCode == 401 { throw APIError.sessionExpired }
                if (500..<600).contains(response.statusCode) { throw APIError.transport }
                throw APIError.refused(problem?.detail ?? problem?.reason ?? "HTTP \(response.statusCode)")
            }
            return try JSONDecoder().decode(Response.self, from: data)
        } catch let error as APIError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw APIError.transport
        }
    }
}

private extension EmiliaJSONValue {
    var decision: String? { objectValue?["decision"]?.stringValue }
}

private struct ProblemResponse: Decodable {
    let detail: String?
    let reason: String?
}

enum APIError: LocalizedError {
    case transport
    case outcomeUnknown
    case sessionExpired
    case refused(String)

    var errorDescription: String? {
        switch self {
        case .transport:
            return "The approval service is unavailable."
        case .outcomeUnknown:
            return "The approval outcome is unknown. Do not retry or assume it was not authorized."
        case .sessionExpired:
            return "This device connection has expired. Pair it again to continue."
        case .refused(let verdict):
            return "The request was refused: \(verdict)"
        }
    }
}
