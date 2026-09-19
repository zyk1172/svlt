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
        .executeSecretOperation(descriptor),
        .startSecretOperation(descriptor),
        .startSecretOperationIdempotent(descriptor: descriptor, idempotencyKey: "job-001"),
        .secretOperationStatus(operationID: operationID),
        .secretOperationOutput(operationID: operationID, cursor: 0, maxChunks: 16),
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
        output: SecretOperationOutput(status: "COMPLETED"),
        nextOutputCursor: 1
    )
    let outputPage = SecretOperationOutputPage(
        operationID: operationID,
        state: .running,
        cursor: 0,
        nextCursor: 1,
        chunks: [
            SecretOperationOutputChunk(
                cursor: 0,
                stream: .stdout,
                text: "ready\n",
                commandIndex: 0
            )
        ],
        hasMore: false
    )
    let responses: [IPCResponse] = [
        .secretOperation(SecretOperationOutput(status: "COMPLETED")),
        .secretOperationHandle(handle),
        .secretOperationStatus(status),
        .secretOperationOutput(outputPage),
        .failure(code: "ACTION_EXECUTION_FAILED")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        #expect(try JSONDecoder().decode(IPCResponse.self, from: encoded) == response)
    }
}

@Test func sharedSecretOperationProtocolFixturesRoundTrip() throws {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("ProtocolFixtures", isDirectory: true)
        .appendingPathComponent("secret-operations", isDirectory: true)

    let requestFixtures = try loadFixtureMap(root.appendingPathComponent("requests.json"))
    #expect(Set(requestFixtures.keys) == Set([
        "executeSecretOperation",
        "startSecretOperation",
        "startSecretOperationIdempotent",
        "secretOperationStatus",
        "secretOperationOutput",
        "cancelSecretOperation"
    ]))
    for (name, object) in requestFixtures {
        let fixtureData = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let decoded = try JSONDecoder().decode(IPCRequest.self, from: fixtureData)
        let encoded = try JSONEncoder().encode(decoded)
        #expect(try canonicalJSON(encoded) == canonicalJSON(fixtureData), "request fixture drift: \(name)")
    }

    let responseFixtures = try loadFixtureMap(root.appendingPathComponent("responses.json"))
    for (name, object) in responseFixtures {
        let fixtureData = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: fixtureData)
        let encoded = try JSONEncoder().encode(decoded)
        #expect(try canonicalJSON(encoded) == canonicalJSON(fixtureData), "response fixture drift: \(name)")
    }
}

@Test func lifecycleErrorCodesStayStable() {
    #expect(SecretOperationLifecycleErrorCode.operationNotFound == "OPERATION_NOT_FOUND")
    #expect(SecretOperationLifecycleErrorCode.cancelled == "OPERATION_CANCELLED")
    #expect(SecretOperationLifecycleErrorCode.outcomeUnknown == "OPERATION_OUTCOME_UNKNOWN")
    #expect(SecretOperationLifecycleErrorCode.idempotencyKeyConflict == "IDEMPOTENCY_KEY_CONFLICT")
}

private func loadFixtureMap(_ url: URL) throws -> [String: Any] {
    let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    guard let fixtures = object as? [String: Any] else {
        throw FixtureError.invalidTopLevelObject(url.lastPathComponent)
    }
    return fixtures
}

private func canonicalJSON(_ data: Data) throws -> Data {
    let object = try JSONSerialization.jsonObject(with: data)
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private enum FixtureError: Error {
    case invalidTopLevelObject(String)
}
