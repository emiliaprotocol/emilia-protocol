// SPDX-License-Identifier: Apache-2.0
import SwiftUI

struct ApprovalView: View {
    @ObservedObject var model: ApprovalViewModel

    var body: some View {
        NavigationStack {
            Form {
                header
                if case .review(let decision) = model.stage {
                    review(decision: decision)
                } else {
                    request
                }
                status
            }
            .navigationTitle("Government Approval")
            .disabled(model.stage == .loading)
        }
    }

    private var header: some View {
        Section {
            Label(
                model.isEnrolled ? "Device enrolled" : "Enrollment required",
                systemImage: model.isEnrolled ? "checkmark.shield.fill" : "exclamationmark.shield"
            )
            if !model.isEnrolled {
                Button("Enroll this device") { Task { await model.enroll() } }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private var request: some View {
        Section("Protected request") {
            TextField("Request identifier", text: $model.requestID)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Review for approval") { Task { await model.begin(decision: "approved") } }
                .buttonStyle(.borderedProminent)
            Button("Review for denial", role: .destructive) { Task { await model.begin(decision: "denied") } }
        }
    }

    private func review(decision: String) -> some View {
        Group {
            Section(model.title) {
                Text(model.summary)
                ForEach(model.materialFields, id: \.0) { field in
                    LabeledContent(field.0, value: field.1)
                }
            }
            Section {
                Text("Your passkey and this app's integrity evidence will be bound to these exact fields.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button(decision == "approved" ? "Approve exact action" : "Submit signed denial",
                       role: decision == "approved" ? nil : .destructive) {
                    Task { await model.confirm() }
                }
                .buttonStyle(.borderedProminent)
                Button("Cancel", role: .cancel) { model.reset() }
            }
        }
    }

    @ViewBuilder
    private var status: some View {
        switch model.stage {
        case .loading:
            Section { HStack { ProgressView(); Text("Verifying") } }
        case .complete(let message):
            Section { Label(message, systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
        case .failed(let message):
            Section { Label(message, systemImage: "xmark.octagon.fill").foregroundStyle(.red) }
        case .ready, .review:
            EmptyView()
        }
    }
}
