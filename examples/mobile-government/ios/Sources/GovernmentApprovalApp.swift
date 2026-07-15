// SPDX-License-Identifier: Apache-2.0
import SwiftUI

@main
struct GovernmentApprovalApp: App {
    @StateObject private var model = ApprovalViewModel()

    var body: some Scene {
        WindowGroup {
            ApprovalView(model: model)
                .tint(Color(red: 0.08, green: 0.31, blue: 0.42))
        }
    }
}
