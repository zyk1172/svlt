import VaultIPC

public protocol RevealSessionPresenting: Sendable {
    func present(sessionID: String, store: RevealSessionStore) async
}

public struct NoopRevealSessionPresenter: RevealSessionPresenting {
    public init() {}

    public func present(sessionID: String, store: RevealSessionStore) async {}
}

/// Owns reveal-session presentation and access after plaintext authorization
/// and resolution have completed. It deliberately has no policy, key, or
/// authorization dependencies.
struct RevealSessionCoordinator: Sendable {
    private let store: RevealSessionStore
    private let presenter: any RevealSessionPresenting

    init(
        store: RevealSessionStore,
        presenter: any RevealSessionPresenting
    ) {
        self.store = store
        self.presenter = presenter
    }

    func clearAll() async {
        await store.clearAll()
    }

    func createAndPresent(_ restoredParagraph: RestoredParagraph) async -> String {
        let sessionID = await store.create(resolvedParagraph: restoredParagraph)
        await presenter.present(sessionID: sessionID, store: store)
        return sessionID
    }

    func sessionIDs() async -> [String] {
        await store.sessionIDs()
    }

    func data(sessionID: String) async throws -> RestoredParagraph {
        guard let restoredParagraph = await store.restoredParagraph(id: sessionID) else {
            throw VaultAppServicesRevealError.sessionNotFound
        }
        return restoredParagraph
    }
}
