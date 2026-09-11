import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultExecution
@testable import VaultService

private struct SummaryTextEncryptor: TextEncrypting {
    func encryptText(_: String, label _: String?, policy _: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private func makeService() -> VaultAppServices {
    VaultAppServices(textEncryptor: SummaryTextEncryptor(), activeRoot: nil)
}

private func batchMetadata(_ reference: SecretReference) -> [SecretPolicyMetadata] {
    [SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "NAS 凭据",
        allowedDestinations: ["192.168.2.240"],
        allowedProtocols: ["ssh"]
    )]
}

@Test func destructiveSSHBatchSummaryShowsTheActualCommandsAndHighestRequirement() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [
            SSHCommandSpec(executable: "whoami"),
            SSHCommandSpec(executable: "mkdir", arguments: ["/share/test"]),
            SSHCommandSpec(executable: "rm", arguments: ["-rf", "/share/test"]),
            SSHCommandSpec(executable: "docker", arguments: ["system", "prune"])
        ])
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))
    #expect(decision.authorizationRequirement == .freshApprovalRequired)

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    // The device owner must see what a destructive batch will run; the
    // single-command fallback text would hide the actual operations.
    #expect(!summary.contains("未提供命令"))
    #expect(summary.contains("SSH 批处理（4 条）"))
    #expect(summary.contains("whoami"))
    #expect(summary.contains("rm"))
    #expect(summary.contains("-rf"))
    #expect(summary.contains("/share/test"))
    #expect(summary.contains("批处理最高授权级别：必须重新本机认证"))
    #expect(summary.contains("192.168.2.240"))
    #expect(!summary.contains("secret://"))
}

@Test func sshBatchSummaryShowsEveryCommandAndArgumentInFull() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let longArgument = "/share/" + String(repeating: "a", count: 300)
    var commands = (0..<7).map { index in
        SSHCommandSpec(executable: "touch", arguments: ["/tmp/svlt-\(index)"])
    }
    commands[0] = SSHCommandSpec(
        executable: "rm",
        arguments: ["-rf", longArgument, "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: commands)
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    // The owner approves the exact batch, so every command and every
    // argument is displayed in full — nothing is summarized away.
    #expect(summary.contains("SSH 批处理（7 条）"))
    for index in 1...6 {
        #expect(summary.contains("/tmp/svlt-\(index)"), "command \(index) must be shown")
    }
    #expect(summary.contains(longArgument))
    #expect(summary.contains("x7"))
    #expect(summary.contains("rm"))
    // The overall prompt stays byte-bounded at the command ceiling, and
    // control characters never reach the approval prompt.
    #expect(summary.utf8.count <= 65_536 + 2_000)
    #expect(!summary.unicodeScalars.contains { $0.value < 0x20 && $0 != "\n" && $0 != "\t" })
}

@Test func sshBatchSummaryNeverIncludesCredentialLabelsOrReferencesFromArguments() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [
            SSHCommandSpec(executable: "hostname"),
            SSHCommandSpec(executable: "df", arguments: ["-h", "/share"])
        ])
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    // A read-only batch takes the plain prompt, and the summary must not
    // echo secret:// references from anywhere in the descriptor. The
    // credential label itself is intended, user-owned display text.
    #expect(summary.contains("SSH 批处理（2 条）"))
    #expect(summary.contains("hostname"))
    #expect(summary.contains("df"))
    #expect(!summary.contains("secret://"))
    #expect(summary.contains("凭据：NAS 凭据"))
}

@Test func sshHostKeyPinSummaryShowsOwnerReviewMaterialWithoutSecretReference() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let pin = try summaryTestSSHHostKeyPin()
    let descriptor = SecretOperationDescriptor(
        actionType: .changeDestinationBinding,
        secretReferences: [reference],
        destination: "nas.local",
        port: 2222,
        protocolType: .ssh,
        requestedEffects: ["pin-ssh-host-key"],
        parameters: [
            "hostKeyAlgorithm": pin.algorithm,
            "hostKeySHA256": pin.sha256
        ]
    )
    let metadata = batchMetadata(reference)
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: metadata)
    let review = SSHHostKeyReview(host: "nas.local", port: 2222, pins: [pin])

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: metadata,
        decision: decision,
        hostKeyReview: review
    )

    #expect(summary.contains("固定 SSH 主机指纹"))
    #expect(summary.contains("待审核 SSH 主机身份"))
    #expect(summary.contains("nas.local"))
    #expect(summary.contains("2222"))
    #expect(summary.contains("ssh-ed25519"))
    #expect(summary.contains(pin.sha256))
    #expect(summary.contains("（待固定）"))
    #expect(!summary.contains("secret://"))
}

private func summaryTestSSHHostKeyPin() throws -> SSHHostKeyPin {
    let digest = Data(SHA256.hash(data: Data(repeating: 0x5A, count: 32)))
    let fingerprint = "SHA256:" + digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
    return try SSHHostKeyPin(algorithm: "ssh-ed25519", sha256: fingerprint)
}
