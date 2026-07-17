// SPDX-License-Identifier: Apache-2.0
import SwiftUI

struct ApprovalView: View {
    @ObservedObject var model: ApprovalViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            ZStack {
                Color(.systemGroupedBackground).ignoresSafeArea()
                if !model.isConnected {
                    pairing
                } else if model.selectedAction != nil {
                    review
                } else {
                    inbox
                }
                if model.isBusy { loading }
            }
            .toolbar { toolbar }
            .task { await model.bootstrap() }
            .alert("Unable to continue", isPresented: failureBinding) {
                Button("OK") { model.dismissStatus() }
            } message: {
                Text(failureMessage)
            }
            .alert(completionTitle, isPresented: completionBinding) {
                Button("Done") { model.dismissStatus() }
            } message: {
                Text(completionMessage)
            }
        }
        .tint(Brand.ink)
        .overlay {
            if scenePhase != .active || model.screenCaptureDetected {
                PrivacyShield()
            }
        }
    }

    private var pairing: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                Spacer(minLength: 40)
                HStack(spacing: 14) {
                    TrustMark(size: 52)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("EMILIA")
                            .font(.title2.weight(.semibold))
                        Text("Approver")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                VStack(alignment: .leading, spacing: 10) {
                    Text("Connect this device")
                        .font(.largeTitle.weight(.semibold))
                    Text("Enter the one-time code issued by your organization.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 10) {
                    Text("PAIRING CODE")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TextField("XXXX-XXXX-XXXX", text: $model.pairingCode)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .textContentType(.oneTimeCode)
                        .font(.title3.monospaced().weight(.semibold))
                        .padding(.horizontal, 16)
                        .frame(minHeight: 58)
                        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel("Pairing code")
                        .accessibilityIdentifier("pairing.code")
                        .submitLabel(.go)
                        .onSubmit { Task { await model.connect() } }
                        .privacySensitive()
                    Button {
                        Task { await model.connect() }
                    } label: {
                        Label("Connect securely", systemImage: "lock.shield.fill")
                            .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.pairingCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("pairing.connect")
                }
                Spacer(minLength: 30)
                Label("No organization secret is stored in the app.", systemImage: "key.horizontal.fill")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityElement(children: .combine)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .navigationBarHidden(true)
    }

    private var inbox: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 18) {
                statusBand
                VStack(alignment: .leading, spacing: 6) {
                    Text("Protected actions")
                        .font(.largeTitle.weight(.semibold))
                    Text(model.actions.isEmpty ? "Nothing is waiting for you." : "\(model.actions.count) decision\(model.actions.count == 1 ? "" : "s") waiting")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                if !model.isEnrolled {
                    enrollmentCallout
                } else if model.actions.isEmpty {
                    emptyState
                } else {
                    ForEach(model.actions) { action in
                        ActionCard(action: action) { model.select(action) }
                    }
                }
                Button {
                    Task { await model.refreshInbox() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                        .frame(minHeight: 44)
                }
                .buttonStyle(.borderless)
            }
            .padding(20)
            .frame(maxWidth: 700)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle("EMILIA Approver")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await model.refreshInbox() }
    }

    private var statusBand: some View {
        HStack(spacing: 12) {
            Image(systemName: model.isEnrolled ? "checkmark.shield.fill" : "iphone.and.arrow.forward")
                .font(.title3)
                .foregroundStyle(model.isEnrolled ? Brand.green : Brand.brass)
                .frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.isEnrolled ? "Device protected" : "Device connection ready")
                    .font(.subheadline.weight(.semibold))
                Text(model.isEnrolled ? "Passkey and app integrity active" : "One security step remains")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.isReferenceDemo {
                Text("DEMO")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(Brand.ink)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Brand.brass.opacity(0.22), in: Capsule())
                    .accessibilityLabel("Reference demo")
            }
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }

    private var enrollmentCallout: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Secure this device", systemImage: "faceid")
                .font(.headline)
            Text("Create the device-bound passkey used for protected decisions.")
                .font(.body)
                .foregroundStyle(.secondary)
            Button {
                Task { await model.enroll() }
            } label: {
                Text("Continue")
                    .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("enrollment.begin")
        }
        .padding(18)
        .background(Brand.brass.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 42))
                .foregroundStyle(Brand.green)
                .accessibilityHidden(true)
            Text("All clear")
                .font(.title3.weight(.semibold))
            Text("New protected actions will appear here.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 220)
        .accessibilityElement(children: .combine)
    }

    private var review: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Button {
                    model.closeAction()
                } label: {
                    Label("Back", systemImage: "chevron.left")
                        .frame(minHeight: 44)
                }
                .buttonStyle(.plain)
                HStack {
                    RiskLabel(text: model.reviewRisk)
                    Spacer()
                    if model.isReferenceDemo {
                        Text("DEMO")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(Brand.ink)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .background(Brand.brass.opacity(0.22), in: Capsule())
                            .accessibilityLabel("Reference demo")
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.reviewTitle)
                        .font(.largeTitle.weight(.semibold))
                    Text(model.reviewSummary)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                if let version = model.presentationVersion {
                    Text(version)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Presentation format \(version)")
                }
                Divider()
                VStack(spacing: 0) {
                    ForEach(Array(model.materialFields.enumerated()), id: \.offset) { index, field in
                        MaterialField(label: field.0, value: field.1)
                        if index < model.materialFields.count - 1 { Divider() }
                    }
                }
                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
                if !model.consequence.isEmpty {
                    Label(model.consequence, systemImage: "scope")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .accessibilityElement(children: .combine)
                }
                decisionControls
            }
            .padding(20)
            .frame(maxWidth: 700)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle("Exact action")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .privacySensitive()
    }

    @ViewBuilder
    private var decisionControls: some View {
        if case .review(let decision) = model.stage {
            VStack(spacing: 10) {
                Label("Exact fields locked", systemImage: "lock.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Brand.green)
                Button {
                    Task { await model.confirm() }
                } label: {
                    Label(
                        decision == "approved" ? "Approve with passkey" : "Sign denial with passkey",
                        systemImage: decision == "approved" ? "checkmark.shield.fill" : "xmark.shield.fill"
                    )
                    .frame(maxWidth: .infinity, minHeight: 52)
                }
                .buttonStyle(.borderedProminent)
                .tint(decision == "approved" ? Brand.ink : Brand.red)
                .accessibilityIdentifier("decision.confirm")
                Button("Cancel", role: .cancel) { model.cancelReview() }
                    .frame(minHeight: 44)
            }
        } else {
            VStack(spacing: 10) {
                Button {
                    Task { await model.begin(decision: "approved") }
                } label: {
                    Label("Approve exact action", systemImage: "checkmark.shield.fill")
                        .frame(maxWidth: .infinity, minHeight: 52)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("decision.approve")
                Button(role: .destructive) {
                    Task { await model.begin(decision: "denied") }
                } label: {
                    Label("Deny", systemImage: "xmark.shield")
                        .frame(maxWidth: .infinity, minHeight: 48)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("decision.deny")
            }
        }
    }

    private var loading: some View {
        ZStack {
            Color.black.opacity(0.24).ignoresSafeArea()
            VStack(spacing: 14) {
                ProgressView()
                    .controlSize(.large)
                if case .loading(let message) = model.stage {
                    Text(message).font(.headline)
                }
            }
            .padding(28)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Working")
        }
        .transition(reduceMotion ? .identity : .opacity)
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if model.isConnected && model.selectedAction == nil {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Disconnect device", role: .destructive) {
                        Task { await model.disconnect() }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .frame(width: 44, height: 44)
                }
                .accessibilityLabel("Device options")
            }
        }
    }

    private var failureBinding: Binding<Bool> {
        Binding(
            get: { if case .failed = model.stage { return true }; return false },
            set: { if !$0 { model.dismissStatus() } }
        )
    }

    private var failureMessage: String {
        if case .failed(let message) = model.stage { return message }
        return ""
    }

    private var completionBinding: Binding<Bool> {
        Binding(
            get: { if case .complete = model.stage { return true }; return false },
            set: { if !$0 { model.dismissStatus() } }
        )
    }

    private var completionTitle: String {
        if case .complete(let completion) = model.stage { return completion.title }
        return "Complete"
    }

    private var completionMessage: String {
        guard case .complete(let completion) = model.stage else { return "" }
        if let hash = completion.contextHash, !hash.isEmpty {
            return "\(completion.verdict.capitalized). Evidence \(hash.prefix(16))…"
        }
        return completion.verdict.capitalized
    }
}

private struct PrivacyShield: View {
    var body: some View {
        ZStack {
            Color(.systemGroupedBackground).ignoresSafeArea()
            VStack(spacing: 12) {
                TrustMark(size: 48)
                Text("EMILIA Approver")
                    .font(.headline)
                Label("Protected content hidden", systemImage: "lock.fill")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
        }
    }
}

private struct ActionCard: View {
    let action: MobileAPI.InboxAction
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    RiskLabel(text: action.risk)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
                Text(action.title)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(action.summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(3)
                if let first = action.materialFields.sorted(by: { $0.key < $1.key }).first {
                    Text(first.value)
                        .font(.headline)
                        .foregroundStyle(Brand.ink)
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.primary.opacity(0.08)))
        }
        .buttonStyle(.plain)
        .frame(minHeight: 44)
        .accessibilityLabel("\(action.title). \(action.risk). \(action.summary)")
        .accessibilityHint("Opens the exact action for review")
        .accessibilityIdentifier("action.\(action.id)")
    }
}

private struct MaterialField: View {
    let label: String
    let value: String

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                Text(label).foregroundStyle(.secondary)
                Spacer(minLength: 20)
                Text(value).fontWeight(.semibold).multilineTextAlignment(.trailing)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(value).fontWeight(.semibold)
            }
        }
        .font(.body)
        .padding(16)
        .accessibilityElement(children: .combine)
    }
}

private struct RiskLabel: View {
    let text: String

    var body: some View {
        Label(text.uppercased(), systemImage: "exclamationmark.triangle.fill")
            .font(.caption2.weight(.bold))
            .foregroundStyle(Brand.red)
            .accessibilityLabel("Risk: \(text)")
    }
}

private struct TrustMark: View {
    let size: CGFloat

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.22)
                .fill(Brand.ink)
            Circle()
                .stroke(Brand.brass, lineWidth: max(2, size * 0.07))
                .frame(width: size * 0.52, height: size * 0.52)
            Circle()
                .fill(Color(.systemBackground))
                .frame(width: size * 0.15, height: size * 0.15)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

private enum Brand {
    static let ink = Color(red: 0.07, green: 0.20, blue: 0.24)
    static let brass = Color(red: 0.72, green: 0.49, blue: 0.16)
    static let green = Color(red: 0.12, green: 0.48, blue: 0.32)
    static let red = Color(red: 0.70, green: 0.19, blue: 0.18)
}
