import Darwin
import Foundation
import Testing
@testable import VaultExecution

@Test func sshKnownHostsStoreCreatesOwnerOnlyTrustState() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let store = SSHKnownHostsStore(directoryURL: root)
    let firstPath = try store.prepare()
    let secondPath = try store.prepare()

    #expect(firstPath == secondPath)
    #expect(firstPath == root.appendingPathComponent("known_hosts").path)

    var directoryStat = stat()
    #expect(root.path.withCString { lstat($0, &directoryStat) } == 0)
    #expect((directoryStat.st_mode & mode_t(0o777)) == mode_t(0o700))

    var fileStat = stat()
    #expect(firstPath.withCString { lstat($0, &fileStat) } == 0)
    #expect((fileStat.st_mode & S_IFMT) == S_IFREG)
    #expect((fileStat.st_mode & mode_t(0o777)) == mode_t(0o600))
    #expect(fileStat.st_uid == geteuid())
}

@Test func sshKnownHostsStoreRejectsSymlinkedKnownHostsFile() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-\(UUID().uuidString)", isDirectory: true)
    let target = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-target-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: target)
    }

    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: target.path, contents: Data())
    try FileManager.default.createSymbolicLink(
        at: root.appendingPathComponent("known_hosts"),
        withDestinationURL: target
    )

    #expect(throws: SSHKnownHostsStoreError.unavailable) {
        _ = try SSHKnownHostsStore(directoryURL: root).prepare()
    }
}
