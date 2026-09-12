import Foundation

extension SensitiveInformationDocumentStore {
    /// Keeps File Provider-backed metadata probes on this store actor instead
    /// of performing them directly from the App's MainActor runtime.
    public func selectedExistingDocumentURL() -> URL? {
        guard let url = selectedDocumentURL(),
              FileManager.default.fileExists(atPath: url.path)
        else {
            return nil
        }
        return url
    }

    public func documentExists(at url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }
}
