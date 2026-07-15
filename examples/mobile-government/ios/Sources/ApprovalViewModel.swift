// SPDX-License-Identifier: Apache-2.0
import AuthenticationServices
import EmiliaMobile
import Foundation
import SwiftUI
import UIKit

@MainActor
final class ApprovalViewModel: ObservableObject {
    enum Stage: Equatable {
        case ready
        case loading
        case review(String)
        case complete(String)
        case failed(String)
    }

    @Published var requestID = ""
    @Published var stage: Stage = .ready
    @Published private(set) var challenge: EmiliaMobileChallenge?

    @AppStorage("emilia.approverID") var approverID = "ep:approver:case-supervisor"
    @AppStorage("emilia.deviceKeyID") var deviceKeyID = ""
    @AppStorage("emilia.appAttestKeyID") var appAttestKeyID = ""
    @AppStorage("emilia.profileID") var profileID = "agency.high-assurance.mobile.v1"
    @AppStorage("emilia.apiBaseURL") var apiBaseURL = "https://approve.example.gov"

    private var pendingDecision: String?

    var isEnrolled: Bool { !deviceKeyID.isEmpty && !appAttestKeyID.isEmpty }
    var title: String { challenge?.presentation.objectValue?["title"]?.stringValue ?? "Review required" }
    var summary: String { challenge?.presentation.objectValue?["summary"]?.stringValue ?? "Verify the material fields before continuing." }
    var materialFields: [(String, String)] {
        guard let fields = challenge?.presentation.objectValue?["material_fields"]?.objectValue else { return [] }
        return fields.keys.sorted().map { ($0.replacingOccurrences(of: "_", with: " ").capitalized, display(fields[$0])) }
    }

    func begin(decision: String) async {
        guard isEnrolled else { stage = .failed("Enroll this device before approving a protected action."); return }
        guard !requestID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            stage = .failed("Enter the approval request identifier.")
            return
        }
        stage = .loading
        do {
            let api = try configuredAPI()
            let appID = Bundle.main.bundleIdentifier ?? "org.example.government.approvals"
            challenge = try await api.issueChallenge(
                requestID: requestID,
                approverID: approverID,
                decision: decision,
                profileID: profileID,
                appID: appID,
                deviceKeyID: deviceKeyID
            )
            pendingDecision = decision
            stage = .review(decision)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func confirm() async {
        guard let challenge, let pendingDecision else { return }
        stage = .loading
        do {
            let passkeys = EmiliaApplePasskeyProvider { Self.presentationWindow() }
            let integrity = EmiliaAppleAppAttestProvider(attestationKeyID: appAttestKeyID)
            let coordinator = EmiliaMobileCeremonyCoordinator(
                passkeys: passkeys,
                integrity: integrity,
                appID: Bundle.main.bundleIdentifier ?? "org.example.government.approvals",
                deviceKeyID: deviceKeyID
            )
            let challengeData = try JSONEncoder().encode(challenge)
            let ceremony = try await coordinator.perform(challengeData: challengeData)
            let result = try await configuredAPI().verify(challenge: challenge, response: ceremony)
            guard result.valid else { throw APIError.refused(result.verdict) }
            stage = .complete(pendingDecision == "approved" ? "Approval recorded" : "Denial recorded")
            self.challenge = nil
            self.pendingDecision = nil
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func enroll() async {
        stage = .loading
        do {
            let api = try configuredAPI()
            let appID = Bundle.main.bundleIdentifier ?? "org.example.government.approvals"
            let enrollmentChallenge = try await api.issueEnrollment(approverID: approverID, appID: appID)
            let coordinator = EmiliaMobileEnrollmentCoordinator(
                passkeys: EmiliaApplePasskeyRegistrationProvider { Self.presentationWindow() },
                platformEnrollment: EmiliaAppleAppAttestEnrollmentProvider(),
                appID: appID
            )
            let response = try await coordinator.perform(
                challengeData: JSONEncoder().encode(enrollmentChallenge)
            )
            let result = try await api.completeEnrollment(challenge: enrollmentChallenge, response: response)
            guard result.ok, let enrollment = result.enrollment else { throw APIError.refused(result.verdict) }
            deviceKeyID = enrollment.deviceKeyID
            appAttestKeyID = enrollment.attestationKeyID
            stage = .complete("Device enrolled")
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func reset() {
        challenge = nil
        pendingDecision = nil
        stage = .ready
    }

    private func configuredAPI() throws -> MobileAPI {
        guard let url = URL(string: apiBaseURL), url.scheme == "https" else { throw APIError.transport }
        return MobileAPI(baseURL: url)
    }

    private func display(_ value: EmiliaJSONValue?) -> String {
        guard let value else { return "" }
        switch value {
        case .string(let text): return text
        case .integer(let number): return String(number)
        case .bool(let flag): return flag ? "Yes" : "No"
        case .null: return "None"
        case .array, .object: return "Structured value"
        }
    }

    private static func presentationWindow() -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        if let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow) { return window }
        return UIWindow(windowScene: scenes[0])
    }
}
