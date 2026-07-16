// SPDX-License-Identifier: Apache-2.0
import SwiftUI
import UIKit

@main
struct EmiliaApproverApp: App {
    @StateObject private var model = ApprovalViewModel()

    var body: some Scene {
        WindowGroup {
            ApprovalView(model: model)
                .preferredColorScheme(nil)
                .onOpenURL { model.receivePairingLink($0) }
                .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
                    model.updateScreenCaptureState()
                }
                .task { model.updateScreenCaptureState() }
        }
    }
}
