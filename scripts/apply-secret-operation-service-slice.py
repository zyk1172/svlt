#!/usr/bin/env python3
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
app_path = root / "Sources/VaultService/VaultAppServices.swift"
service_path = root / "Sources/VaultService/SecretOperationService.swift"
budget_path = root / "scripts/check-architecture-budgets.sh"

text = app_path.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "    let secretOperationCoordinator = SecretOperationCoordinator()\n",
    "    let secretOperationService = SecretOperationService()\n",
)

replace_once(
    """    private var secureInputCatalogOperations: [UUID: CatalogDocumentOperation] = [:]\n"
    "    private var approvalPending = false\n"
    "    private var executionApprovalFlights: [ExecutionAuthorizationScope: ExecutionApprovalFlight] = [:]\n"
    "    private var pendingExecutionApprovalIDs: Set<UUID> = []\n"
    "    var inFlightSecretOperations: [UUID: Task<SecretOperationOutput, Error>] = [:]\n"
    "    private var securityGeneration: UInt64 = 0\n""".replace('"\n    "', ''),
    """    private var secureInputCatalogOperations: [UUID: CatalogDocumentOperation] = [:]\n"
    "    private var executionApprovalFlights: [ExecutionAuthorizationScope: ExecutionApprovalFlight] = [:]\n"
    "    private var securityGeneration: UInt64 = 0\n""".replace('"\n    "', ''),
)

replace_once(
    "            approvalPending: approvalPending,\n",
    "            approvalPending: await secretOperationService.approvalPending,\n",
)

replace_once(
    """        for flight in executionApprovalFlights.values {
            flight.task.cancel()
        }
        executionApprovalFlights.removeAll()
        await scopedMasterKeyCoordinator.invalidateAll()
        pendingExecutionApprovalIDs.removeAll()
        await invalidateTrackedSecretOperations()
        for operation in inFlightSecretOperations.values {
            operation.cancel()
        }
        inFlightSecretOperations.removeAll()
        approvalPending = false
""",
    """        for flight in executionApprovalFlights.values {
            flight.task.cancel()
        }
        executionApprovalFlights.removeAll()
        await secretOperationService.invalidateAllCoordination()
        await scopedMasterKeyCoordinator.invalidateAll()
""",
)

replace_once(
    "        let executionID = trackedSecretOperationID() ?? UUID()\n",
    "",
)
replace_once(
    """        inFlightSecretOperations[executionID] = executionTask
        defer {
            inFlightSecretOperations.removeValue(forKey: executionID)
        }
        do {
            let output = try await executionTask.value
""",
    """        do {
            let output = try await secretOperationService.awaitExecutionTask(
                executionTask,
                operationID: trackedSecretOperationID()
            )
""",
)

replace_once(
    """        approvalPending = true
        await statusObserver?(status())

        var authenticationContext: LocalAuthenticationContext?
""",
    """        let approvalID = await secretOperationService.beginApproval()
        await statusObserver?(status())

        var authenticationContext: LocalAuthenticationContext?
""",
)

# Three error exits from the one-shot approval path share this exact state reset.
old_catch_reset = """            approvalPending = false
            await statusObserver?(status())
"""
if text.count(old_catch_reset) != 3:
    raise SystemExit(f"expected 3 one-shot approval catch resets, found {text.count(old_catch_reset)}")
text = text.replace(
    old_catch_reset,
    """            if await secretOperationService.finishApproval(id: approvalID) {
                await statusObserver?(status())
            }
""",
)
replace_once(
    """        approvalPending = false
        await statusObserver?(status())
        try ensureTrackedSecretOperationIsActive()
""",
    """        if await secretOperationService.finishApproval(id: approvalID) {
            await statusObserver?(status())
        }
        try ensureTrackedSecretOperationIsActive()
""",
)

replace_once(
    """        pendingExecutionApprovalIDs.insert(approvalID)
        approvalPending = true
        await statusObserver?(status())
""",
    """        await secretOperationService.beginApproval(id: approvalID)
        await statusObserver?(status())
""",
)

replace_once(
    """    private func finishExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        approvalID: UUID,
        generation: UInt64
    ) async {
        guard let flight = executionApprovalFlights[scope],
              flight.id == approvalID,
              flight.generation == generation
        else {
            pendingExecutionApprovalIDs.remove(approvalID)
            return
        }
        flight.task.cancel()
        executionApprovalFlights.removeValue(forKey: scope)
        pendingExecutionApprovalIDs.remove(approvalID)
        approvalPending = !pendingExecutionApprovalIDs.isEmpty
        await statusObserver?(status())
    }

    private func markExecutionApprovalCompleted(_ approvalID: UUID) async {
        guard pendingExecutionApprovalIDs.remove(approvalID) != nil else {
            return
        }
        approvalPending = !pendingExecutionApprovalIDs.isEmpty
        await statusObserver?(status())
    }
""",
    """    private func finishExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        approvalID: UUID,
        generation: UInt64
    ) async {
        guard let flight = executionApprovalFlights[scope],
              flight.id == approvalID,
              flight.generation == generation
        else {
            if await secretOperationService.finishApproval(id: approvalID) {
                await statusObserver?(status())
            }
            return
        }
        flight.task.cancel()
        executionApprovalFlights.removeValue(forKey: scope)
        if await secretOperationService.finishApproval(id: approvalID) {
            await statusObserver?(status())
        }
    }

    private func markExecutionApprovalCompleted(_ approvalID: UUID) async {
        guard await secretOperationService.finishApproval(id: approvalID) else {
            return
        }
        await statusObserver?(status())
    }
""",
)

old_removed_flight = """            if let flight = executionApprovalFlights.removeValue(forKey: scope) {
                if pendingExecutionApprovalIDs.remove(flight.id) != nil {
                    approvalPending = !pendingExecutionApprovalIDs.isEmpty
                    await statusObserver?(status())
                }
            }
"""
if text.count(old_removed_flight) != 1:
    raise SystemExit(f"expected one active-lease flight cleanup, found {text.count(old_removed_flight)}")
text = text.replace(
    old_removed_flight,
    """            if let flight = executionApprovalFlights.removeValue(forKey: scope),
               await secretOperationService.finishApproval(id: flight.id) {
                await statusObserver?(status())
            }
""",
    1,
)

replace_once(
    """            if executionApprovalFlights[scope]?.id == flight.id {
                executionApprovalFlights.removeValue(forKey: scope)
                if pendingExecutionApprovalIDs.remove(flight.id) != nil {
                    approvalPending = !pendingExecutionApprovalIDs.isEmpty
                    await statusObserver?(status())
                }
            }
""",
    """            if executionApprovalFlights[scope]?.id == flight.id {
                executionApprovalFlights.removeValue(forKey: scope)
                if await secretOperationService.finishApproval(id: flight.id) {
                    await statusObserver?(status())
                }
            }
""",
)

replace_once(
    """        executionApprovalFlights.removeValue(forKey: scope)
        if pendingExecutionApprovalIDs.remove(flight.id) != nil {
            approvalPending = !pendingExecutionApprovalIDs.isEmpty
            await statusObserver?(status())
        }
        return expiresAt == nil ? .approvedWithoutLease : .leaseEstablished
""",
    """        executionApprovalFlights.removeValue(forKey: scope)
        if await secretOperationService.finishApproval(id: flight.id) {
            await statusObserver?(status())
        }
        return expiresAt == nil ? .approvedWithoutLease : .leaseEstablished
""",
)

replace_once(
    """        if let flight = executionApprovalFlights.removeValue(forKey: scope) {
            flight.task.cancel()
            if pendingExecutionApprovalIDs.remove(flight.id) != nil {
                approvalPending = !pendingExecutionApprovalIDs.isEmpty
                await statusObserver?(status())
            }
        }
""",
    """        if let flight = executionApprovalFlights.removeValue(forKey: scope) {
            flight.task.cancel()
            if await secretOperationService.finishApproval(id: flight.id) {
                await statusObserver?(status())
            }
        }
""",
)

for forbidden in (
    "secretOperationCoordinator",
    "pendingExecutionApprovalIDs",
    "inFlightSecretOperations",
    "approvalPending =",
    "approvalPending: approvalPending",
):
    if forbidden in text:
        raise SystemExit(f"stale Secret Operation coordination state remains: {forbidden}")

app_path.write_text(text)

# Close a cancellation race in the new service without hand-editing the file
# while this one-shot transform is active.
service = service_path.read_text()
old_defer = """        defer {
            guard executionTasks[executionID]?.registrationID == registrationID else { return }
            executionTasks.removeValue(forKey: executionID)
        }
"""
new_defer = """        defer {
            if executionTasks[executionID]?.registrationID == registrationID {
                executionTasks.removeValue(forKey: executionID)
            }
        }
"""
if service.count(old_defer) != 1:
    raise SystemExit("expected exactly one execution-task defer cleanup")
service_path.write_text(service.replace(old_defer, new_defer, 1))

# Architecture budgets are ceilings. This refactor must ratchet the God-file
# ceiling down to the new exact byte size rather than preserving historical slack.
new_size = len(text.encode("utf-8"))
budget = budget_path.read_text()
budget, count = re.subn(
    r'Sources/VaultService/VaultAppServices\.swift:\d+',
    f'Sources/VaultService/VaultAppServices.swift:{new_size}',
    budget,
    count=1,
)
if count != 1:
    raise SystemExit("failed to update VaultAppServices architecture budget")
budget_path.write_text(budget)

print(f"VaultAppServices.swift -> {new_size} bytes")
