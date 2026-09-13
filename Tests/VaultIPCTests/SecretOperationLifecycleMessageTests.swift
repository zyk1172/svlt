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
        .secretOperation(SecretOperationOutput(status: "COMPLETED")),
        .secretOperationHandle(handle),
        .secretOperationStatus(status),
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
        "secretOperationStatus",
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
