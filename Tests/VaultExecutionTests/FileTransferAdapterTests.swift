import Foundation
import Testing
import VaultCore
@testable import VaultExecution

private let transferReferenceText = "secret://0123456789ABCDEFGHJKMNPQRS"

@Test func sftpAdapterKeepsCredentialOutOfProcessArgumentsAndFramesInput() async throws {
    let reference = try SecretReference(transferReferenceText)
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-sftp-test-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let runner = TransferCapturingProcessRunner(
        result: ProcessResult(
            exitCode: 0,
            stdout: Data("remote-file.txt\n".utf8),
            stderr: Data("__SVLT_SFTP_TRANSFER_COMPLETED_v1__\n".utf8)
        )
    )
    let adapter = SFTPSecretOperationAdapter(processRunner: runner, localRoot: root)
    let descriptor = transferDescriptor(
        action: .sftpTransfer,
        protocolType: .sftp,
        operation: .list,
        reference: reference,
        host: "nas.local",
        remotePath: "/share/USBSSD/temp"
    )

    let output = try await adapter.execute(
        descriptor,
        metadata: [],
        context: SecretOperationExecutionContext(principal: "test", securityGeneration: 1),
        resolve: { _ in Data("ASV_CANARY_SFTP_PASSWORD".utf8) }
    )

    let invocation = await runner.invocation
    let stdin = await runner.stdin
    #expect(output.status == "COMPLETED")
    #expect(output.listingPreview == "remote-file.txt\n")
    #expect(invocation?.executable == "/usr/bin/expect")
    #expect(invocation?.arguments == ["-c", SFTPSecretOperationAdapter.expectScript()])
    #expect(!invocation!.arguments.joined(separator: " ").contains("ASV_CANARY_SFTP_PASSWORD"))
    #expect(stdin.range(of: Data("ASV_CANARY_SFTP_PASSWORD".utf8)) == nil)
    #expect(String(decoding: stdin, as: UTF8.self).contains("6e61732e6c6f63616c"))
    #expect(SFTPSecretOperationAdapter.expectScript().contains("-o BatchMode=no"))
    #expect(!SFTPSecretOperationAdapter.expectScript().contains("-b -"))
    #expect(SFTPSecretOperationAdapter.expectScript().contains("sftp>"))
}

@Test func sftpExpectWrapperRejectsUnframedInputBeforeNetworkAccess() async throws {
    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/usr/bin/expect",
            arguments: ["-c", SFTPSecretOperationAdapter.expectScript()]
        ),
        stdin: Data("GG\n".utf8),
        timeout: .seconds(2),
        outputLimitBytes: 16_384
    )

    #expect(result.exitCode == 122)
}

@Test func fileTransferAcceptsArbitraryLocalAndRemotePaths() throws {
    let reference = try SecretReference(transferReferenceText)
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-transfer-root-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let uploadPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Downloads/source archive.zip")
        .path
    let upload = transferDescriptor(
        action: .sftpTransfer,
        protocolType: .sftp,
        operation: .upload,
        reference: reference,
        host: "nas.local",
        remotePath: "../../other-share/incoming/archive.zip",
        localPath: uploadPath
    )
    let uploadPlan = try FileTransferAdapterSupport.makePlan(
        for: upload,
        action: .sftpTransfer,
        protocols: [.sftp, .scp],
        defaultPort: 22,
        localRoot: root
    )
    #expect(uploadPlan.localURL?.path == uploadPath)
    #expect(uploadPlan.remotePath == "../../other-share/incoming/archive.zip")

    let downloadPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Desktop/NAS/report.txt")
        .path
    let download = transferDescriptor(
        action: .sftpTransfer,
        protocolType: .sftp,
        operation: .download,
        reference: reference,
        host: "nas.local",
        remotePath: "share/reports/../final/report.txt",
        localPath: downloadPath
    )
    let downloadPlan = try FileTransferAdapterSupport.makePlan(
        for: download,
        action: .sftpTransfer,
        protocols: [.sftp, .scp],
        defaultPort: 22,
        localRoot: root
    )
    #expect(downloadPlan.localURL?.path == downloadPath)
    #expect(downloadPlan.remotePath == "share/reports/../final/report.txt")
}

@Test func fileTransferStillRejectsUnrepresentablePaths() throws {
    let reference = try SecretReference(transferReferenceText)
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-transfer-root-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let remoteControlCharacter = transferDescriptor(
        action: .sftpTransfer,
        protocolType: .sftp,
        operation: .upload,
        reference: reference,
        host: "nas.local",
        remotePath: "share/bad\nname.txt",
        localPath: "/tmp/source.txt"
    )
    #expect(throws: FileTransferAdapterError.invalidParameter) {
        _ = try FileTransferAdapterSupport.makePlan(
            for: remoteControlCharacter,
            action: .sftpTransfer,
            protocols: [.sftp, .scp],
            defaultPort: 22,
            localRoot: root
        )
    }

    let relativeLocalPath = transferDescriptor(
        action: .sftpTransfer,
        protocolType: .sftp,
        operation: .upload,
        reference: reference,
        host: "nas.local",
        remotePath: "incoming/source.txt",
        localPath: "Downloads/source.txt"
    )
    #expect(throws: FileTransferAdapterError.invalidLocalPath) {
        _ = try FileTransferAdapterSupport.makePlan(
            for: relativeLocalPath,
            action: .sftpTransfer,
            protocols: [.sftp, .scp],
            defaultPort: 22,
            localRoot: root
        )
    }
}

@Test func ftpAdapterRejectsPublicDestinationsBeforeResolvingSecret() async throws {
    let reference = try SecretReference(transferReferenceText)
    let adapter = FTPSecretOperationAdapter(
        localRoot: FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-ftp-test-\(UUID().uuidString)", isDirectory: true)
    )
    let descriptor = transferDescriptor(
        action: .ftpTransfer,
        protocolType: .ftp,
        operation: .list,
        reference: reference,
        host: "public.example",
        remotePath: "/"
    )

    #expect(adapter.preflight(descriptor) == .invalidParameters)
    await #expect(throws: SecretOperationExecutionError.insecureTransportDenied) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [],
            context: SecretOperationExecutionContext(principal: "test", securityGeneration: 1),
            resolve: { _ in
                Issue.record("FTP resolved a credential before rejecting a public destination")
                return Data("unused".utf8)
            }
        )
    }
}

@Test func ftpAdapterSupportsLegacyQNAPPathEncodingOnlyForReads() {
    let encoded = FTPPathEncoding.gb18030.data(for: "不说.mp4")
    #expect(encoded == Data([0xB2, 0xBB, 0xCB, 0xB5, 0x2E, 0x6D, 0x70, 0x34]))
    #expect(
        FTPPathEncoding.candidates(
            for: "/USBSSD/temp/不说.mp4",
            operation: .download
        ) == [.utf8, .gb18030]
    )
    #expect(
        FTPPathEncoding.candidates(
            for: "/USBSSD/temp/不说.mp4",
            operation: .upload
        ) == [.utf8]
    )
}


@Test func ftpStagePrefersTaskCancellationOverTransportFailure() async {
    let gate = BlockingFTPStageGate()
    let task = Task {
        try await runFTPStage {
            await gate.markStartedAndWait()
            throw FTPCancellationProbeError.transport
        }
    }
    await gate.waitUntilStarted()
    task.cancel()
    await gate.release()

    do {
        _ = try await task.value
        Issue.record("FTP stage returned a transport result after cancellation.")
    } catch is CancellationError {
        // Expected: explicit task cancellation wins over the callback error.
    } catch {
        Issue.record("FTP cancellation was rewritten as \(error).")
    }
}

private enum FTPCancellationProbeError: Error {
    case transport
}

private actor BlockingFTPStageGate {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func markStartedAndWait() async {
        started = true
        let waiters = startWaiters
        startWaiters.removeAll()
        waiters.forEach { $0.resume() }
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

private func transferDescriptor(
    action: SecretOperationAction,
    protocolType: SecretOperationProtocol,
    operation: SecretFileOperation,
    reference: SecretReference,
    host: String,
    remotePath: String,
    localPath: String? = nil
) -> SecretOperationDescriptor {
    SecretOperationDescriptor(
        actionType: action,
        secretReferences: [reference],
        destination: host,
        port: protocolType == .ftp ? 21 : 22,
        protocolType: protocolType,
        fileOperation: operation,
        fileTarget: localPath,
        payload: .fileTransfer(
            FileTransferOperation(
                protocolType: protocolType,
                operation: operation,
                remotePath: remotePath,
                localPath: localPath,
                username: "zyk",
                passwordReference: reference
            )
        ),
        parameters: [
            "remotePath": remotePath,
            "passwordRef": reference.description,
            "username": "zyk"
        ]
    )
}

private actor TransferCapturingProcessRunner: ProcessRunning {
    let result: ProcessResult
    private(set) var invocation: ProcessInvocation?
    private(set) var stdin = Data()

    init(result: ProcessResult) {
        self.result = result
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout _: Duration?,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        self.invocation = invocation
        self.stdin = stdin
        return result
    }
}
