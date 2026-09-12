import Testing
import VaultIPC
@testable import VaultService

@Test func revealSessionCoordinatorCreatesPresentsReadsAndListsSession() async throws {
    let store = RevealSessionStore()
    let presenter = RevealCoordinatorSpyPresenter()
    let coordinator = RevealSessionCoordinator(store: store, presenter: presenter)
    let restored = RestoredParagraph(text: "Token: secret", values: ["secret"])

    let sessionID = await coordinator.createAndPresent(restored)

    #expect(sessionID.hasPrefix("session-"))
    #expect(await presenter.presentedSessionIDs == [sessionID])
    #expect(await coordinator.sessionIDs() == [sessionID])
    #expect(try await coordinator.data(sessionID: sessionID) == restored)
}

@Test func revealSessionCoordinatorClearAllRemovesEverySession() async throws {
    let store = RevealSessionStore()
    let coordinator = RevealSessionCoordinator(
        store: store,
        presenter: RevealCoordinatorSpyPresenter()
    )
    _ = await coordinator.createAndPresent(RestoredParagraph(text: "first", values: []))
    _ = await coordinator.createAndPresent(RestoredParagraph(text: "second", values: []))

    await coordinator.clearAll()

    #expect(await coordinator.sessionIDs().isEmpty)
}

@Test func revealSessionCoordinatorMapsMissingSessionToStableServiceError() async {
    let coordinator = RevealSessionCoordinator(
        store: RevealSessionStore(),
        presenter: RevealCoordinatorSpyPresenter()
    )

    do {
        _ = try await coordinator.data(sessionID: "session-missing")
        Issue.record("A missing reveal session unexpectedly returned data.")
    } catch let error as VaultAppServicesRevealError {
        #expect(error == .sessionNotFound)
    } catch {
        Issue.record("A missing reveal session returned an unstable error type.")
    }
}

private actor RevealCoordinatorSpyPresenter: RevealSessionPresenting {
    private(set) var presentedSessionIDs: [String] = []

    func present(sessionID: String, store _: RevealSessionStore) async {
        presentedSessionIDs.append(sessionID)
    }
}
