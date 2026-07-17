// SPDX-License-Identifier: Apache-2.0
import AuthenticationServices
import EmiliaMobile
import Foundation
import SwiftUI
import UIKit

@MainActor
final class ApprovalViewModel: ObservableObject {
    struct Completion: Equatable {
        let title: String
        let verdict: String
        let contextHash: String?
    }

    enum Stage: Equatable {
        case idle
        case loading(String)
        case review(String)
        case complete(Completion)
        case failed(String)
    }

    @Published var pairingCode = ""
    @Published private(set) var stage: Stage = .idle
    @Published private(set) var actions: [MobileAPI.InboxAction] = []
    @Published private(set) var selectedAction: MobileAPI.InboxAction?
    @Published private(set) var challenge: EmiliaMobileChallenge?
    @Published private(set) var accessToken: String?

    @Published private(set) var approverID = ""
    @Published private(set) var deviceKeyID = ""
    @Published private(set) var appAttestKeyID = ""
    @Published private(set) var profileID = ""
    @Published private(set) var screenCaptureDetected = UIScreen.main.isCaptured
    @Published private(set) var isReferenceDemo = false

    private let sessionStore = SecureSessionStore()
    private var sessionExpiresAt = ""
    private var pendingDecision: String?
    private var didBootstrap = false

    var isConnected: Bool { accessToken?.isEmpty == false }
    var isEnrolled: Bool { !deviceKeyID.isEmpty && !appAttestKeyID.isEmpty }
    var appID: String { Bundle.main.bundleIdentifier ?? "" }
    var isBusy: Bool { if case .loading = stage { return true }; return false }

    init(arguments: [String] = ProcessInfo.processInfo.arguments) {
#if DEBUG
        guard arguments.contains("-emilia-reference-demo") else { return }
        let action = MobileAPI.InboxAction(
            actionReference: "grace:event:caiso-reference-0042",
            title: "Approve 18 MW curtailment",
            summary: "Reduce facility load from 64 MW to approximately 46 MW for 90 minutes.",
            risk: "critical",
            materialFields: [
                "facility": "US West AI Data Center 17",
                "power_reduction": "18 MW",
                "window": "1:15-2:45 PM PT",
                "trigger": "CAISO reference dispatch",
                "approval_rule": "2-person Class-A quorum",
            ],
            expiresAt: "2026-07-15T21:45:00.000Z",
            createdAt: "2026-07-15T20:00:00.000Z"
        )
        accessToken = "debug-reference-demo"
        approverID = "ep:approver:grid-operator"
        profileID = "ep:grace:mobile-curtailment:v1"
        deviceKeyID = "ep:key:debug-reference-device"
        appAttestKeyID = "appattest:debug-reference-key"
        sessionExpiresAt = "2026-07-15T22:00:00.000Z"
        actions = [action]
        selectedAction = arguments.contains("-emilia-reference-inbox") ? nil : action
        isReferenceDemo = true
        didBootstrap = true
#endif
    }

    var reviewTitle: String {
        validatedPresentation?.title
            ?? selectedAction?.title
            ?? "Review required"
    }

    var reviewSummary: String {
        validatedPresentation?.summary
            ?? selectedAction?.summary
            ?? "Review the material fields before deciding."
    }

    var consequence: String {
        validatedPresentation?.consequence ?? ""
    }

    var reviewRisk: String {
        validatedPresentation?.risk ?? selectedAction?.risk ?? "consequential"
    }

    var presentationVersion: String? {
        validatedPresentation == nil ? nil : EmiliaMobilePresentation.version
    }

    var materialFields: [(String, String)] {
        if let fields = validatedPresentation?.materialFields {
            return fields.keys.sorted().map { (label($0), fields[$0] ?? "") }
        }
        return (selectedAction?.materialFields ?? [:]).keys.sorted().map {
            (label($0), selectedAction?.materialFields[$0] ?? "")
        }
    }

    private var validatedPresentation: EmiliaMobilePresentation? {
        guard let challenge else { return nil }
        return try? EmiliaMobileChallengeValidator.validatePresentation(challenge.presentation)
    }

    func bootstrap() async {
        guard !didBootstrap else { return }
        didBootstrap = true
        do {
            if let stored = try sessionStore.load() {
                accessToken = stored.accessToken
                approverID = stored.approverID
                profileID = stored.profileID
                sessionExpiresAt = stored.expiresAt
                deviceKeyID = stored.deviceKeyID ?? ""
                appAttestKeyID = stored.appAttestKeyID ?? ""
                await refreshInbox()
            } else {
                clearSessionMetadata()
            }
        } catch {
            stage = .failed("Secure storage is unavailable. This device was not connected.")
        }
    }

    func receivePairingLink(_ url: URL) {
        guard !isConnected else {
            stage = .failed("Disconnect this device before pairing it with another organization.")
            return
        }
        guard url.scheme == "https", url.host == "www.emiliaprotocol.ai", url.path == "/mobile/pair",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let rawCode = components.queryItems?.first(where: { $0.name == "code" })?.value
        else {
            stage = .failed("This pairing link is not valid.")
            return
        }
        let code = rawCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard code.range(
            of: #"^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$"#,
            options: .regularExpression
        ) != nil else {
            stage = .failed("This pairing link is malformed or incomplete.")
            return
        }
        pairingCode = code
        stage = .idle
    }

    func connect() async {
        let code = pairingCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !appID.isEmpty else { stage = .failed("This build has no permanent application identity."); return }
        guard !code.isEmpty else { stage = .failed("Enter the pairing code."); return }
        stage = .loading("Pairing this device")
        do {
            let response = try await MobileAPI(baseURL: try baseURL()).exchangePairing(code: code, appID: appID)
            accessToken = response.accessToken
            approverID = response.approverID
            profileID = response.profileID
            sessionExpiresAt = response.expiresAt
            deviceKeyID = ""
            appAttestKeyID = ""
            do {
                try persistSession()
            } catch {
                try? sessionStore.clear()
                clearSessionMetadata()
                throw error
            }
            pairingCode = ""
            stage = .idle
            await refreshInbox()
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func enroll() async {
        guard isConnected else { stage = .failed("Pair this device first."); return }
        stage = .loading("Securing this device")
        do {
            let api = try configuredAPI()
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
            do {
                try persistSession()
            } catch {
                try? await api.revokeSession()
                disconnectLocal()
                throw APIError.refused("secure_storage_unavailable")
            }
            stage = .complete(.init(title: "Device secured", verdict: "enrolled", contextHash: nil))
            await refreshInbox(preserveCompletion: true)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func refreshInbox(preserveCompletion: Bool = false) async {
        guard isConnected else { return }
#if DEBUG
        if isReferenceDemo {
            if !preserveCompletion { stage = .idle }
            return
        }
#endif
        if !preserveCompletion { stage = .loading("Checking protected actions") }
        do {
            actions = try await configuredAPI().inbox()
            if !preserveCompletion { stage = .idle }
        } catch APIError.sessionExpired {
            disconnectLocal()
            stage = .failed(APIError.sessionExpired.localizedDescription)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func select(_ action: MobileAPI.InboxAction) {
        selectedAction = action
        challenge = nil
        pendingDecision = nil
        stage = .idle
    }

    func begin(decision: String) async {
        guard !screenCaptureDetected, !UIScreen.main.isCaptured else {
            blockCapturedScreen()
            return
        }
        guard isEnrolled else { stage = .failed("Secure this device before deciding."); return }
        guard let selectedAction else { return }
#if DEBUG
        if isReferenceDemo {
            pendingDecision = decision
            stage = .review(decision)
            return
        }
#endif
        stage = .loading("Binding the exact action")
        do {
            let issuedChallenge = try await configuredAPI().issueChallenge(
                requestID: selectedAction.actionReference,
                approverID: approverID,
                decision: decision,
                profileID: profileID,
                appID: appID,
                deviceKeyID: deviceKeyID
            )
            _ = try EmiliaMobileChallengeValidator.decodeAndValidate(
                JSONEncoder().encode(issuedChallenge)
            )
            challenge = issuedChallenge
            pendingDecision = decision
            stage = .review(decision)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func confirm() async {
        guard !screenCaptureDetected, !UIScreen.main.isCaptured else {
            blockCapturedScreen()
            return
        }
        guard let challenge, let pendingDecision else { return }
        stage = .loading(pendingDecision == "approved" ? "Waiting for passkey" : "Signing the refusal")
        do {
            let coordinator = EmiliaMobileCeremonyCoordinator(
                passkeys: EmiliaApplePasskeyProvider { Self.presentationWindow() },
                integrity: EmiliaAppleAppAttestProvider(attestationKeyID: appAttestKeyID),
                appID: appID,
                deviceKeyID: deviceKeyID
            )
            let ceremony = try await coordinator.perform(challengeData: JSONEncoder().encode(challenge))
            guard !screenCaptureDetected, !UIScreen.main.isCaptured else {
                blockCapturedScreen()
                return
            }
            let result = try await configuredAPI().verify(challenge: challenge, response: ceremony)
            guard result.valid else { throw APIError.refused(result.reason ?? result.verdict) }
            let approved = pendingDecision == "approved"
            stage = .complete(.init(
                title: approved ? "Approval sealed" : "Denial sealed",
                verdict: result.verdict,
                contextHash: result.contextHash
            ))
            selectedAction = nil
            self.challenge = nil
            self.pendingDecision = nil
            await refreshInbox(preserveCompletion: true)
        } catch {
            stage = .failed(error.localizedDescription)
        }
    }

    func cancelReview() {
        challenge = nil
        pendingDecision = nil
        stage = .idle
    }

    func closeAction() {
        cancelReview()
        selectedAction = nil
    }

    func dismissStatus() {
        if case .complete = stage { stage = .idle }
        if case .failed = stage { stage = .idle }
    }

    func updateScreenCaptureState() {
        screenCaptureDetected = UIScreen.main.isCaptured
        if screenCaptureDetected { blockCapturedScreen() }
    }

    func disconnect() async {
        guard isConnected else { disconnectLocal(); return }
        stage = .loading("Revoking this device session")
        do {
            try await configuredAPI().revokeSession()
            disconnectLocal()
            stage = .complete(.init(title: "Device disconnected", verdict: "revoked", contextHash: nil))
        } catch APIError.sessionExpired {
            disconnectLocal()
            stage = .complete(.init(title: "Device disconnected", verdict: "expired", contextHash: nil))
        } catch {
            stage = .failed("The server could not revoke this session. This device remains connected.")
        }
    }

    private func disconnectLocal() {
        try? sessionStore.clear()
        clearSessionMetadata()
        actions = []
        selectedAction = nil
        challenge = nil
        pendingDecision = nil
    }

    private func blockCapturedScreen() {
        screenCaptureDetected = true
        challenge = nil
        pendingDecision = nil
        stage = .failed("Approval is blocked while screen recording or mirroring is active.")
    }

    private func clearSessionMetadata() {
        accessToken = nil
        approverID = ""
        profileID = ""
        deviceKeyID = ""
        appAttestKeyID = ""
        sessionExpiresAt = ""
    }

    private func persistSession() throws {
        guard let accessToken, !approverID.isEmpty, !profileID.isEmpty, !sessionExpiresAt.isEmpty else {
            throw SecureSessionStore.StoreError.invalidValue
        }
        try sessionStore.save(.init(
            accessToken: accessToken,
            approverID: approverID,
            profileID: profileID,
            expiresAt: sessionExpiresAt,
            deviceKeyID: deviceKeyID.isEmpty ? nil : deviceKeyID,
            appAttestKeyID: appAttestKeyID.isEmpty ? nil : appAttestKeyID
        ))
    }

    private func configuredAPI() throws -> MobileAPI {
        guard let accessToken else { throw APIError.sessionExpired }
        return MobileAPI(baseURL: try baseURL(), accessToken: accessToken)
    }

    private func baseURL() throws -> URL {
        guard let raw = Bundle.main.object(forInfoDictionaryKey: "EmiliaAPIBaseURL") as? String,
              raw == "https://www.emiliaprotocol.ai/api/",
              let url = URL(string: raw), url.scheme == "https"
        else { throw APIError.transport }
        return url
    }

    private func label(_ value: String) -> String {
        value.replacingOccurrences(of: "_", with: " ").localizedCapitalized
    }

    private static func presentationWindow() -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        if let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow) { return window }
        guard let scene = scenes.first else { return ASPresentationAnchor() }
        return UIWindow(windowScene: scene)
    }
}
