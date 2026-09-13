import Darwin
import Foundation
import VaultCore

public struct SensitiveCatalogAdoptionAvailability: Equatable, Sendable {
    public let canAdoptV2: Bool
    public let canAdoptV3: Bool

    public init(canAdoptV2: Bool = false, canAdoptV3: Bool = false) {
        self.canAdoptV2 = canAdoptV2
        self.canAdoptV3 = canAdoptV3
    }
}

private let svltCatalogUIProbeMaximumBytes = 64 * 1024 * 1024

private final class CatalogUIProbeResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var result: (status: Int32, data: Data?)?
    private var timedOut = false

    func complete(status: Int32, data: Data?) {
        lock.lock()
        defer { lock.unlock() }
        guard !timedOut else { return }
        result = (status, data)
    }

    func resultAfterTimeout() -> (status: Int32, data: Data?) {
        lock.lock()
        defer { lock.unlock() }
        if let result { return result }
        timedOut = true
        return (ETIMEDOUT, nil)
    }
}

/// UI-facing probes use the same low-level reader as the Catalog store, but
/// keep their own admission gate so a File Provider stall cannot create an
/// unbounded queue of work while the App remains responsive.
private enum CatalogUIProbeIO {
    static let permits = DispatchSemaphore(value: 1)
    static let queue = DispatchQueue(
        label: "com.agent-secret-vault.catalog-ui-probe",
        qos: .userInitiated,
        autoreleaseFrequency: .workItem
    )

    static func read(_ path: String) -> (status: Int32, data: Data?) {
        guard permits.wait(timeout: .now()) == .success else {
            return (ETIMEDOUT, nil)
        }

        let completion = DispatchSemaphore(value: 0)
        let resultBox = CatalogUIProbeResultBox()
        queue.async {
            defer { permits.signal() }
            var bytes: UnsafeMutableRawPointer?
            var length = 0
            let status = path.withCString { svlt_read_file($0, &bytes, &length) }

            let data: Data?
            if status == 0,
               length <= svltCatalogUIProbeMaximumBytes,
               let bytes {
                data = Data(bytes: bytes, count: length)
            } else {
                data = nil
            }
            if let bytes { svlt_free_file(bytes) }

            let normalizedStatus = status == 0 && length > svltCatalogUIProbeMaximumBytes
                ? EFBIG
                : status
            resultBox.complete(status: normalizedStatus, data: data)
            completion.signal()
        }

        guard completion.wait(timeout: .now() + .seconds(3)) == .success else {
            return resultBox.resultAfterTimeout()
        }
        return resultBox.resultAfterTimeout()
    }
}

public extension SensitiveCatalogDocumentStore {
    /// A bounded existence probe for App presentation code. The caller awaits
    /// this actor instead of touching File Provider-backed paths on MainActor.
    func selectedDocumentExists() -> Bool {
        guard let url = selectedDocumentURL() else { return false }
        return CatalogUIProbeIO.read(url.path).status == 0
    }

    /// Determines whether the selected unmanaged/legacy candidate is a v2 or
    /// v3 Catalog without performing disk I/O on MainActor. The read is
    /// bounded to three seconds and 64 MiB; failures fail closed.
    func adoptionAvailability() throws -> SensitiveCatalogAdoptionAvailability {
        guard let url = selectedDocumentURL() else {
            return SensitiveCatalogAdoptionAvailability()
        }

        let result = CatalogUIProbeIO.read(url.path)
        // Admission contention and an I/O deadline are both unavailable
        // states for an optional UI adoption probe.  In particular, the
        // single-permit gate deliberately fails fast instead of queueing
        // File Provider work; do not turn that expected back-pressure into a
        // write failure that makes the presentation test (and UI) throw.
        if result.status == ENOENT || result.status == ETIMEDOUT {
            return SensitiveCatalogAdoptionAvailability()
        }
        guard result.status == 0, let data = result.data else {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }

        switch SensitiveCatalogDocumentCodec.format(data) {
        case .managedV2:
            return SensitiveCatalogAdoptionAvailability(canAdoptV2: true)
        case .managedV3:
            return SensitiveCatalogAdoptionAvailability(canAdoptV3: true)
        case .unmanaged, .legacy:
            return SensitiveCatalogAdoptionAvailability()
        }
    }
}
