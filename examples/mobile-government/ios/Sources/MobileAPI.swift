// SPDX-License-Identifier: Apache-2.0
import EmiliaMobile
import Foundation

struct MobileAPI: Sendable {
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
    let session: URLSession

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
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
        return try await post("v1/mobile/ceremonies", Request(challenge: challenge, response: response))
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

    private func post<Request: Encodable, Response: Decodable>(_ path: String, _ body: Request) async throws -> Response {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, rawResponse) = try await session.data(for: request)
        guard let response = rawResponse as? HTTPURLResponse, (200..<300).contains(response.statusCode) else {
            throw APIError.transport
        }
        return try JSONDecoder().decode(Response.self, from: data)
    }
}

enum APIError: LocalizedError {
    case transport
    case refused(String)

    var errorDescription: String? {
        switch self {
        case .transport: return "The approval service is unavailable. No action was authorized."
        case .refused(let verdict): return "The approval service refused the request: \(verdict)"
        }
    }
}
