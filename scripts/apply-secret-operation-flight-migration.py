#!/usr/bin/env python3
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
app_path = root / "Sources/VaultService/VaultAppServices.swift"
budget_path = root / "scripts/check-architecture-budgets.sh"
text = app_path.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match, found {count}: {old[:100]!r}")
    text = text.replace(old, new, 1)

replace_once('''private struct ExecutionApprovalFlight {
    let id: UUID
    let generation: UInt64
    let task: Task<LocalAuthenticationContext?, Error>
}

''', '')
replace_once('    private var executionApprovalFlights: [ExecutionAuthorizationScope: ExecutionApprovalFlight] = [:]\n', '')
replace_once('''        for flight in executionApprovalFlights.values {
            flight.task.cancel()
        }
        executionApprovalFlights.removeAll()
        await secretOperationService.invalidateAllCoordination()
''', '''        await secretOperationService.invalidateAllCoordination()
''')

start = text.index('    private func authorizeAgentExecution(\n')
end = text.index('    private func waitForExecutionApprovalFlight(\n', start)
text = text[:start] + '''    private func authorizeAgentExecution(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision,
        generation: UInt64,
        scope: ExecutionAuthorizationScope,
        hostKeyReview: SSHHostKeyReview? = nil
    ) async throws -> SecretOperationAuthorizationPath {
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            return .executionWindowReuse
        }

        if let flight = await secretOperationService.executionApprovalFlight(for: scope) {
            return try await waitForExecutionApprovalFlight(
                flight,
                scope: scope,
                generation: generation
            )
        }

        // AuthorizationSession is a separate actor. Recheck before asking the
        // SecretOperationService to atomically join-or-create the shared
        // approval flight. The second check plus atomic insert prevents
        // duplicate owner prompts under actor reentrancy.
        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            return .executionWindowReuse
        }

        let acquisition = await secretOperationService.joinOrCreateExecutionApprovalFlight(
            scope: scope,
            generation: generation,
            create: { [weak self] in
                guard let self else {
                    throw OperationAuthorizationError.cancelled
                }
                return try await self.performFreshExecutionApproval(
                    descriptor: descriptor,
                    metadata: metadata,
                    decision: decision,
                    generation: generation,
                    hostKeyReview: hostKeyReview
                )
            }
        )
        let flight = acquisition.flight
        if !acquisition.created {
            return try await waitForExecutionApprovalFlight(
                flight,
                scope: scope,
                generation: generation
            )
        }
        await statusObserver?(status())

        do {
            let authenticationContext = try await flight.task.value
            await markExecutionApprovalCompleted(flight.id)
            return .freshLocalApproval(authenticationContext)
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }
    }

''' + text[end:]

replace_once('        _ flight: ExecutionApprovalFlight,\n', '        _ flight: SecretOperationService.ExecutionApprovalFlight,\n')

start = text.index('    private func finishExecutionApprovalFlight(\n')
end = text.index('    private func markExecutionApprovalCompleted(\n', start)
text = text[:start] + '''    private func finishExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        approvalID: UUID,
        generation: UInt64
    ) async {
        if await secretOperationService.finishExecutionApprovalFlight(
            scope: scope,
            approvalID: approvalID,
            generation: generation
        ) {
            await statusObserver?(status())
        }
    }

''' + text[end:]

start = text.index('    private func commitExecutionAuthorization(\n')
end = text.index('    private func abandonExecutionAuthorization(\n', start)
text = text[:start] + '''    private func commitExecutionAuthorization(
        scope: ExecutionAuthorizationScope,
        generation: UInt64,
        masterKey: SymmetricKey
    ) async throws -> ExecutionAuthorizationCommit {
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(scope: scope) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard let flight = await secretOperationService.executionApprovalFlight(for: scope),
              flight.generation == generation
        else {
            return .needsFreshApproval
        }

        do {
            _ = try await flight.task.value
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }

        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(
                scope: scope,
                matching: flight.id
            ) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard await secretOperationService.executionApprovalFlight(for: scope)?.id == flight.id else {
            return .needsFreshApproval
        }

        let expiresAt = await authorizationSession.authorizeExecution(for: scope)
        guard generation == securityGeneration else {
            await authorizationSession.invalidateExecutionAuthorization(for: scope)
            throw SecretOperationError.authorizationCancelled
        }

        let executionWindowDuration: TimeInterval?
        if expiresAt == nil {
            executionWindowDuration = nil
        } else {
            executionWindowDuration = await authorizationSession.executionAuthorizationWindowDuration()
        }
        await scopedMasterKeyCoordinator.storeAuthorizedKey(
            masterKey,
            for: scope,
            duration: executionWindowDuration
        )

        if await secretOperationService.removeExecutionApprovalFlight(
            scope: scope,
            matching: flight.id
        ) {
            await statusObserver?(status())
        }
        return expiresAt == nil ? .approvedWithoutLease : .leaseEstablished
    }

''' + text[end:]

start = text.index('    private func abandonExecutionAuthorization(\n')
end = text.index('    private func emitExecutionWindowReuseAudit(\n', start)
text = text[:start] + '''    private func abandonExecutionAuthorization(
        scope: ExecutionAuthorizationScope?
    ) async {
        guard let scope else {
            return
        }
        if await secretOperationService.removeExecutionApprovalFlight(
            scope: scope,
            cancelTask: true
        ) {
            await statusObserver?(status())
        }
        await scopedMasterKeyCoordinator.abandon(scope: scope)
    }

''' + text[end:]

if 'executionApprovalFlights' in text:
    raise SystemExit('executionApprovalFlights still present in VaultAppServices')
if 'private struct ExecutionApprovalFlight' in text:
    raise SystemExit('local ExecutionApprovalFlight still present')

app_path.write_text(text)
actual = len(text.encode())
budget = budget_path.read_text()
budget, count = re.subn(r'Sources/VaultService/VaultAppServices\.swift:\d+', f'Sources/VaultService/VaultAppServices.swift:{actual}', budget, count=1)
if count != 1:
    raise SystemExit('architecture budget entry not found')
budget_path.write_text(budget)
print(f'VaultAppServices.swift -> {actual} bytes')
