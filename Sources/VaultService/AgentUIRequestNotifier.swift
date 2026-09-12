import Foundation

/// Agent-to-App UI bridge. Only a session identifier is broadcast; the
/// plaintext remains in the Agent session store and is fetched by the native
/// App's explicit UI client request. The Agent never imports AppKit/SwiftUI or
/// creates a window.
public struct AgentUIRequestNotifier: RevealSessionPresenting, Sendable {
    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.ui.reveal-request"
    )

    private let activateApp: @Sendable () -> Void

    public init(activateApp: @escaping @Sendable () -> Void = Self.activateSVLTApp) {
        self.activateApp = activateApp
    }

    public func present(sessionID: String, store: RevealSessionStore) async {
        DistributedNotificationCenter.default().post(
            name: Self.notificationName,
            object: nil,
            userInfo: ["sessionID": sessionID]
        )
        activateApp()
    }

    public static func activateSVLTApp() {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/open")
        process.arguments = ["-b", "com.agent-secret-vault.SVLT"]
        try? process.run()
    }
}

/// Non-sensitive signal emitted only after LocalAuthentication has actually
/// been asked to present a fresh operation-approval UI. The signal carries
/// only an opaque per-presentation identifier. The GUI app owns the real
/// UNUserNotificationCenter delivery so the LaunchAgent never receives
/// notification text or sensitive operation details.
public struct AgentApprovalPresentationNotifier: Sendable {
    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.ui.approval-presented"
    )

    private let activateAppInBackground: @Sendable () -> Void

    public init(
        activateAppInBackground: @escaping @Sendable () -> Void = Self.activateSVLTAppInBackground
    ) {
        self.activateAppInBackground = activateAppInBackground
    }

    public func notify(approvalID: UUID) {
        // Launch the GUI without stealing focus so UNUserNotificationCenter is
        // available even when the user invoked SVLT only through MCP/Agent.
        // Delivery remains best-effort and completely independent of approval.
        activateAppInBackground()
        Self.post(approvalID: approvalID)

        // A cold-launched GUI may not have installed its distributed observer
        // when the first signal is posted. Re-post the same opaque ID once;
        // the GUI's notify-once gate guarantees that this cannot create a
        // second system notification or sound for the same approval window.
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .milliseconds(900))
            Self.post(approvalID: approvalID)
        }
    }

    private static func post(approvalID: UUID) {
        DistributedNotificationCenter.default().post(
            name: notificationName,
            object: nil,
            userInfo: ["approvalID": approvalID.uuidString],
            deliverImmediately: true
        )
    }

    private static func activateSVLTAppInBackground() {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/open")
        process.arguments = ["-g", "-b", "com.agent-secret-vault.SVLT"]
        try? process.run()
    }
}
