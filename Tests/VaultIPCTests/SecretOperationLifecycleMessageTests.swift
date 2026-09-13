import Foundation
import Testing
import VaultCore
import VaultExecution
@testable import VaultIPC

@Test func operationLifecycleRequestsRoundTrip() throws {
    let operationID = UUID()
    let descriptor = SecretOperationDescriptor(
        actionType: .vaultStatus,
        secretReferences: []
    )
    let requests: [IPCRequest] = [
        .startSecretOperation(descriptor),
        .secretOperationStatus(operationID: operationID),
        .cancelSecretOperation(operationID: operationID)
    ]

    for request in requests {
        let encoded = try JSONEncoder().encode(request)
        #expect(try JSONDecoder().decode(IPCRequest.self, from: encoded) == request)
    }
}

@Test func operationLifecycleResponsesRoundTrip() throws {
    let operationID = UUID()
    let handle = SecretOperationHandle(operationID: operationID, state: .queued)
    let status = SecretOperationStatus(
        operationID: operationID,
        state: .succeeded,
        output: SecretOperationOutput(status: "COMPLETED")
    )
    let responses: [IPCResponse] = [
        .secretOperationHandle(handle),
        .secretOperationStatus(status)
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        #expect(try JSONDecoder().decode(IPCResponse.self, from: encoded) == response)
    }
}
