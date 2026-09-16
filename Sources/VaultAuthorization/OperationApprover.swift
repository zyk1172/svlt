import Foundation
import VaultCore

public enum OperationAuthorizationError: Error, Equatable, Sendable {
    case cancelled
    case denied
    case timeout
    case unavailable
}

public protocol OperationApproving: Sendable {
    func approve(summary: String) async throws
}

/// An approval implementation may return the exact `LAContext` that completed
/// the owner-authentication prompt. Consumers use it only for the immediately
/// following Keychain lookup in the same logical operation, preventing a
/// legacy userPresence item from opening a second system prompt.
public protocol OperationApprovalContextProviding: OperationApproving {
    func approveWithAuthenticationContext(
        summary: String
    ) async throws -> LocalAuthenticationContext?
}

/// Uses Apple's system-owned Touch ID / device-owner authentication UI in
/// approval mode. In no-approval mode this is a hard final short-circuit: SVLT
/// does not create a device-owner prompt and returns no authentication context.
public struct LocalOperationApprover: OperationApprovalContextProviding {
    private let authenticator: any BiometricAuthorizing

    public init(authenticator: any BiometricAuthorizing = LocalAuthenticator()) {
        self.authenticator = authenticator
    }

    public func approve(summary: String) async throws {
        _ = try await approveWithAuthenticationContext(summary: summary)
    }

    public func approveWithAuthenticationContext(
        summary: String
    ) async throws -> LocalAuthenticationContext? {
        guard VaultApprovalModeState.shared.mode == .approvalRequired else {
            return nil
        }

        do {
            if let contextAuthorizer = authenticator as? any KeychainContextAuthorizing {
                return try await contextAuthorizer.makeAuthenticationContext(reason: summary)
            }
            try await authenticator.evaluate(reason: summary)
            return nil
        } catch let error as BiometricAuthorizationError {
            switch error {
            case .cancelled:
                throw OperationAuthorizationError.cancelled
            case .unavailable:
                throw OperationAuthorizationError.unavailable
            case .lockout, .authenticationFailed:
                throw OperationAuthorizationError.denied
            }
        } catch is CancellationError {
            throw OperationAuthorizationError.cancelled
        } catch {
            throw OperationAuthorizationError.denied
        }
    }
}
