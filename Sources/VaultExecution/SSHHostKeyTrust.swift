import CryptoKit
import Darwin
import Foundation
import VaultCore

public enum SSHHostKeyReviewError: Error, Equatable, Sendable {
    case invalidHost
    case invalidPort
    case unavailable
    case noHostKey
    case malformedHostKey
    case pinNotPresented
    case trustStoreUnavailable
}

/// Non-secret data that the App can show while the owner reviews an SSH
/// server identity. The public key bytes never cross this projection.
public struct SSHHostKeyReview: Codable, Equatable, Sendable {
    public let host: String
    public let port: Int
    public let pins: [SSHHostKeyPin]

    public init(host: String, port: Int, pins: [SSHHostKeyPin]) {
        self.host = host
        self.port = port
        self.pins = pins.sorted {
            if $0.algorithm == $1.algorithm {
                return $0.sha256 < $1.sha256
            }
            return $0.algorithm < $1.algorithm
        }
    }
}

/// Implemented by the App-facing executor so the service can obtain a host
/// key before it resolves a Secret or asks the owner to authenticate.
public protocol SSHHostKeyReviewing: Sendable {
    func reviewSSHHostKey(host: String, port: Int) async throws -> SSHHostKeyReview
}

public protocol SSHHostKeyPinning: SSHHostKeyReviewing {
    /// Re-discovers the selected key after owner authentication and installs
    /// it in the App-owned strict trust profile. The fingerprint is checked
    /// against the fresh discovery; callers cannot supply a public key blob.
    func installSSHHostKey(host: String, port: Int, pin: SSHHostKeyPin) async throws
}

private struct SSHHostKeyMaterial: Sendable {
    let pin: SSHHostKeyPin
    let publicKeyBase64: String
}

struct SSHHostKeyDiscovery: Sendable {
    private static let executablePath = "/usr/bin/ssh-keyscan"
    private static let outputLimitBytes = 256 * 1024

    private let processRunner: any ProcessRunning
    private let timeout: Duration

    init(
        processRunner: any ProcessRunning,
        timeout: Duration = .seconds(5)
    ) {
        self.processRunner = processRunner
        self.timeout = timeout
    }

    func review(host: String, port: Int) async throws -> SSHHostKeyReview {
        let materials = try await discover(host: host, port: port)
        return SSHHostKeyReview(
            host: host,
            port: port,
            pins: materials.map(\.pin)
        )
    }

    private func material(host: String, port: Int, pin: SSHHostKeyPin) async throws -> SSHHostKeyMaterial {
        let materials = try await discover(host: host, port: port)
        guard let material = materials.first(where: { $0.pin == pin }) else {
            throw SSHHostKeyReviewError.pinNotPresented
        }
        return material
    }

    func install(
        host: String,
        port: Int,
        pin: SSHHostKeyPin,
        into store: SSHKnownHostsStore
    ) async throws {
        let material = try await material(host: host, port: port, pin: pin)
        do {
            _ = try store.preparePinnedPath(
                host: host,
                port: port,
                pin: pin,
                publicKeyBase64: material.publicKeyBase64
            )
        } catch SSHKnownHostsStoreError.unavailable {
            throw SSHHostKeyReviewError.trustStoreUnavailable
        }
    }

    private func discover(host: String, port: Int) async throws -> [SSHHostKeyMaterial] {
        guard Self.isSafeHost(host) else { throw SSHHostKeyReviewError.invalidHost }
        guard (1...65_535).contains(port) else { throw SSHHostKeyReviewError.invalidPort }

        let result: ProcessResult
        do {
            result = try await processRunner.run(
                ProcessInvocation(
                    executable: Self.executablePath,
                    arguments: [
                        "-T", String(Self.timeoutSeconds(for: timeout)),
                        "-p", String(port),
                        "--",
                        host
                    ]
                ),
                stdin: Data(),
                timeout: timeout,
                outputLimitBytes: Self.outputLimitBytes
            )
        } catch ProcessRunError.timedOut {
            throw SSHHostKeyReviewError.unavailable
        } catch ProcessRunError.outputLimitExceeded {
            throw SSHHostKeyReviewError.malformedHostKey
        } catch ProcessRunError.processLaunchFailed,
                ProcessRunError.stdinWriteFailed,
                ProcessRunError.launchFailed {
            throw SSHHostKeyReviewError.unavailable
        }

        let output = String(decoding: result.stdout, as: UTF8.self)
        let materials = Self.parse(output)
        guard !materials.isEmpty else {
            if output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw SSHHostKeyReviewError.noHostKey
            }
            throw SSHHostKeyReviewError.malformedHostKey
        }
        return materials
    }

    private static func parse(_ output: String) -> [SSHHostKeyMaterial] {
        var materials: [SSHHostKeyMaterial] = []
        var seen = Set<SSHHostKeyPin>()

        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 3 else { continue }

            let algorithm = String(fields[1])
            let publicKeyBase64 = String(fields[2])
            guard let sha256 = fingerprint(for: publicKeyBase64),
                  let pin = try? SSHHostKeyPin(algorithm: algorithm, sha256: sha256),
                  seen.insert(pin).inserted else {
                continue
            }
            materials.append(
                SSHHostKeyMaterial(
                    pin: pin,
                    publicKeyBase64: publicKeyBase64
                )
            )
        }

        return materials.sorted {
            if $0.pin.algorithm == $1.pin.algorithm {
                return $0.pin.sha256 < $1.pin.sha256
            }
            return $0.pin.algorithm < $1.pin.algorithm
        }
    }

    private static func fingerprint(for publicKeyBase64: String) -> String? {
        guard let keyData = decodeBase64(publicKeyBase64) else {
            return nil
        }
        let digest = Data(SHA256.hash(data: keyData))
        return "SHA256:" + digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64(_ value: String) -> Data? {
        guard !value.isEmpty else { return nil }
        let paddingCount = value.reversed().prefix { $0 == "=" }.count
        guard paddingCount <= 2 else { return nil }
        let contentEnd = value.index(value.endIndex, offsetBy: -paddingCount)
        let content = value[..<contentEnd]
        guard !content.contains("="),
              content.count % 4 != 1,
              content.unicodeScalars.allSatisfy({ scalar in
                  (scalar.value >= 0x41 && scalar.value <= 0x5A)
                      || (scalar.value >= 0x61 && scalar.value <= 0x7A)
                      || (scalar.value >= 0x30 && scalar.value <= 0x39)
                      || scalar == "+"
                      || scalar == "/"
              }) else {
            return nil
        }
        let requiredPadding = (4 - content.count % 4) % 4
        guard paddingCount == 0 || paddingCount == requiredPadding else { return nil }
        return Data(base64Encoded: String(content) + String(repeating: "=", count: requiredPadding))
    }

    private static func isSafeHost(_ host: String) -> Bool {
        guard (1...255).contains(host.utf8.count),
              !host.hasPrefix("-"),
              !host.contains(where: { $0.isWhitespace }),
              !host.contains("/"),
              !host.contains("@"),
              !host.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            return false
        }
        return true
    }

    private static func timeoutSeconds(for duration: Duration) -> Int {
        let components = duration.components
        let seconds = Double(components.seconds)
            + Double(components.attoseconds) / 1_000_000_000_000_000_000
        return max(1, min(30, Int(seconds.rounded(.up))))
    }
}

extension SSHKnownHostsStore {
    func preparePinnedPath(
        host: String,
        port: Int,
        pin: SSHHostKeyPin,
        publicKeyBase64: String
    ) throws -> String {
        guard Self.isSafeHost(host), (1...65_535).contains(port),
              let fingerprint = SSHHostKeyDiscoveryFingerprint.value(for: publicKeyBase64),
              fingerprint == pin.sha256 else {
            throw SSHKnownHostsStoreError.unavailable
        }

        _ = try prepare()
        let pinsDirectoryURL = try securePinsDirectory()
        let line = "\(Self.knownHostsHostToken(host: host, port: port)) \(pin.algorithm) \(publicKeyBase64)\n"
        guard line.utf8.count <= 65_536 else {
            throw SSHKnownHostsStoreError.unavailable
        }

        let finalURL = pinsDirectoryURL.appendingPathComponent(Self.profileFilename(host: host, port: port))
        try Self.writeAtomically(Data(line.utf8), to: finalURL, in: pinsDirectoryURL)
        guard try Self.secureFileContainsExactlyPinnedKey(at: finalURL, host: host, port: port, pin: pin) else {
            throw SSHKnownHostsStoreError.unavailable
        }
        return finalURL.path
    }

    func validatedPinnedPath(
        host: String,
        port: Int,
        pin: SSHHostKeyPin
    ) throws -> String {
        guard Self.isSafeHost(host), (1...65_535).contains(port) else {
            throw SSHKnownHostsStoreError.unavailable
        }
        _ = try prepare()
        let pinsDirectoryURL = try securePinsDirectory()
        let finalURL = pinsDirectoryURL.appendingPathComponent(Self.profileFilename(host: host, port: port))
        guard try Self.secureFileContainsExactlyPinnedKey(at: finalURL, host: host, port: port, pin: pin) else {
            throw SSHKnownHostsStoreError.unavailable
        }
        return finalURL.path
    }

    private func securePinsDirectory() throws -> URL {
        let fileManager = FileManager.default
        let pinsDirectoryURL = directoryURL.appendingPathComponent("pins", isDirectory: true)
        do {
            try fileManager.createDirectory(
                at: pinsDirectoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
            )
        } catch {
            throw SSHKnownHostsStoreError.unavailable
        }

        var directoryStat = stat()
        guard pinsDirectoryURL.path.withCString({ lstat($0, &directoryStat) }) == 0,
              (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == geteuid(),
              pinsDirectoryURL.path.withCString({ chmod($0, S_IRWXU) }) == 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }
        return pinsDirectoryURL
    }

    private static func writeAtomically(_ data: Data, to finalURL: URL, in directoryURL: URL) throws {
        let temporaryURL = directoryURL.appendingPathComponent(".pin-\(UUID().uuidString).tmp")
        let descriptor = temporaryURL.path.withCString {
            Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        }
        guard descriptor >= 0 else { throw SSHKnownHostsStoreError.unavailable }

        var openDescriptor = descriptor
        var committed = false
        defer {
            if openDescriptor >= 0 { Darwin.close(openDescriptor) }
            if !committed { temporaryURL.path.withCString { _ = unlink($0) } }
        }

        var writeFailed = false
        data.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                writeFailed = !data.isEmpty
                return
            }
            var offset = 0
            while offset < data.count {
                let written = Darwin.write(
                    openDescriptor,
                    baseAddress.advanced(by: offset),
                    data.count - offset
                )
                if written <= 0 {
                    if errno == EINTR { continue }
                    writeFailed = true
                    return
                }
                offset += written
            }
        }
        guard !writeFailed,
              Darwin.fsync(openDescriptor) == 0,
              Darwin.fchmod(openDescriptor, mode_t(0o600)) == 0,
              Darwin.close(openDescriptor) == 0 else {
            openDescriptor = -1
            throw SSHKnownHostsStoreError.unavailable
        }
        openDescriptor = -1

        guard temporaryURL.path.withCString({ temporaryPath in
            finalURL.path.withCString { finalPath in
                Darwin.rename(temporaryPath, finalPath)
            }
        }) == 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }
        committed = true
    }

    private static func secureFileContainsExactlyPinnedKey(
        at url: URL,
        host: String,
        port: Int,
        pin: SSHHostKeyPin
    ) throws -> Bool {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw SSHKnownHostsStoreError.unavailable }
        defer { Darwin.close(descriptor) }

        var fileStat = stat()
        guard Darwin.fstat(descriptor, &fileStat) == 0,
              (fileStat.st_mode & S_IFMT) == S_IFREG,
              fileStat.st_uid == geteuid(),
              (fileStat.st_mode & mode_t(0o077)) == 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8_192)
        while true {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(descriptor, rawBuffer.baseAddress, rawBuffer.count)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw SSHKnownHostsStoreError.unavailable
            }
            if count == 0 { break }
            guard data.count + count <= 65_536 else {
                throw SSHKnownHostsStoreError.unavailable
            }
            data.append(contentsOf: buffer.prefix(count))
        }

        guard let contents = String(data: data, encoding: .utf8) else {
            throw SSHKnownHostsStoreError.unavailable
        }
        let expectedHost = knownHostsHostToken(host: host, port: port)
        var hostLineCount = 0
        var matchingLineCount = 0
        for rawLine in contents.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count == 3,
                  String(fields[0]) == expectedHost else {
                return false
            }
            hostLineCount += 1
            guard String(fields[1]) == pin.algorithm,
                  SSHHostKeyDiscoveryFingerprint.value(for: String(fields[2])) == pin.sha256 else {
                return false
            }
            matchingLineCount += 1
        }
        return hostLineCount == 1 && matchingLineCount == 1
    }

    private static func isSafeHost(_ host: String) -> Bool {
        guard (1...255).contains(host.utf8.count),
              !host.hasPrefix("-"),
              !host.contains(where: { $0.isWhitespace }),
              !host.contains("/"),
              !host.contains("@"),
              !host.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            return false
        }
        return true
    }

    private static func profileFilename(host: String, port: Int) -> String {
        let digest = SHA256.hash(data: Data("\(host.lowercased())\u{1F}\(port)".utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return "profile-\(hex).known_hosts"
    }

    private static func knownHostsHostToken(host: String, port: Int) -> String {
        let unwrapped = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host
        return port == 22 && !unwrapped.contains(":")
            ? unwrapped
            : "[\(unwrapped)]:\(port)"
    }
}

private enum SSHHostKeyDiscoveryFingerprint {
    static func value(for publicKeyBase64: String) -> String? {
        guard let keyData = decodeBase64(publicKeyBase64) else {
            return nil
        }
        return "SHA256:" + Data(SHA256.hash(data: keyData))
            .base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64(_ value: String) -> Data? {
        guard !value.isEmpty else { return nil }
        let paddingCount = value.reversed().prefix { $0 == "=" }.count
        guard paddingCount <= 2 else { return nil }
        let contentEnd = value.index(value.endIndex, offsetBy: -paddingCount)
        let content = value[..<contentEnd]
        guard !content.contains("="),
              content.count % 4 != 1,
              content.unicodeScalars.allSatisfy({ scalar in
                  (scalar.value >= 0x41 && scalar.value <= 0x5A)
                      || (scalar.value >= 0x61 && scalar.value <= 0x7A)
                      || (scalar.value >= 0x30 && scalar.value <= 0x39)
                      || scalar == "+"
                      || scalar == "/"
              }) else {
            return nil
        }
        let requiredPadding = (4 - content.count % 4) % 4
        guard paddingCount == 0 || paddingCount == requiredPadding else { return nil }
        return Data(base64Encoded: String(content) + String(repeating: "=", count: requiredPadding))
    }
}
