# iOS reference app

This SwiftUI application exercises native enrollment, exact-action review,
approval or denial, passkey user verification, App Attest, and server-side
consumption.

The checked-in reference identity is `ai.emiliaprotocol.approver`, owned by the
EMILIA Apple Developer team, with App Attest and associated domains configured
per build. Generate the project with `xcodegen generate`. A downstream agency
that distributes its own binary must fork the identity, provisioning, domains,
and server allowlist together; changing only the visible app name is not a trust
configuration.
