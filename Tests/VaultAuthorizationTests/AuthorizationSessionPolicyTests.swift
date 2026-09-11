import Foundation
import Testing
@testable import VaultAuthorization

@Test func defaultReadAuthorizationSurvivesTimeUntilExplicitInvalidation() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let session = AuthorizationSession(readTTL: nil, now: { clock.now })

    await session.authorizeRead()
    clock.now = Date(timeIntervalSinceReferenceDate: 10_000_000)

    #expect(await session.consumeAuthorization(for: .read))
    await session.invalidate()
    #expect(await session.consumeAuthorization(for: .read) == false)
}

@Test func credentialAuthorizationIsReusableUntilConfiguredTTL() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 2_000))
    let session = AuthorizationSession(
        credentialTTL: 300,
        now: { clock.now }
    )

    await session.authorizeCredential()
    #expect(await session.consumeCredential())
    #expect(await session.consumeCredential())

    clock.now = Date(timeIntervalSinceReferenceDate: 2_300)
    #expect(await session.consumeCredential() == false)
}

@Test func externalSendAuthorizationIsBoundToDestination() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 3_000))
    let session = AuthorizationSession(
        externalSendTTL: 300,
        now: { clock.now }
    )

    await session.authorizeExternalSend(destination: "api.openai.com")
    #expect(await session.consumeExternalSend(destination: "api.openai.com"))
    #expect(await session.consumeExternalSend(destination: "github.com") == false)

    clock.now = Date(timeIntervalSinceReferenceDate: 3_301)
    #expect(await session.consumeExternalSend(destination: "api.openai.com") == false)
}

@Test func deleteAuthorizationRemainsSingleUse() async {
    let session = AuthorizationSession()
    await session.authorizeSingleUse(for: .deleteOrCredentialChange)

    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange))
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

// MARK: - Database authorization regression coverage

@Test func databaseClassifierKeepsPersistentAndIdentityChangingSetStatementsFresh() {
    let classifier = DatabaseStatementClassifier()
    let statements = [
        "SET PERSIST_ONLY max_connections = 200",
        "SET @@PERSIST_ONLY.max_connections = 200",
        "SET DEFAULT ROLE admin TO app_user",
        "SET PASSWORD FOR app_user = 'redacted'",
        "SET SESSION AUTHORIZATION app_user",
        "SET LOCAL ROLE app_role",
        "SET SESSION ROLE app_role",
        "RESET PERSIST max_connections"
    ]

    for statement in statements {
        let classification = classifier.classify(statement)
        #expect(classification.requirement == .freshApprovalRequired, "statement: \(statement)")
        #expect(
            classification.ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin,
            "statement: \(statement)"
        )
        #expect(classification.scopeFamily == "database.fresh.privilege-account-admin")
    }
}

@Test func databaseClassifierRejectsExecutableCommentsIntoFreshUnknownPath() {
    let classifier = DatabaseStatementClassifier()
    let statements = [
        "SELECT 1; /*!50000 DELETE FROM logs */",
        "/*!50000 UPDATE users SET disabled = 1 */ SELECT 1",
        "/*M!100100 DELETE FROM logs */ SELECT 1"
    ]

    for statement in statements {
        let classification = classifier.classify(statement)
        #expect(classification.requirement == .freshApprovalRequired, "statement: \(statement)")
        #expect(classification.ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.unknown)
        #expect(classification.scopeFamily == "database.fresh.unknown")
    }
}

@Test func databaseClassifierDoesNotTreatMySQLArithmeticAsDashDashComment() {
    let classifier = DatabaseStatementClassifier()
    let classification = classifier.classify("SELECT 1--1; DELETE FROM logs")

    #expect(classification.requirement == .freshApprovalRequired)
    #expect(classification.ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite)
    #expect(classification.scopeFamily == "database.fresh.destructive-write")
}

@Test func databaseClassifierPreservesPostgreSQLHashJSONOperators() {
    let classifier = DatabaseStatementClassifier()
    let read = classifier.classify("SELECT payload #>> '{profile,name}' FROM accounts")
    let mutation = classifier.classify("SELECT payload #> '{profile}' FROM accounts; DELETE FROM accounts")

    #expect(read.requirement == .reusableApproval)
    #expect(read.scopeFamily == "database.read")
    #expect(mutation.requirement == .freshApprovalRequired)
    #expect(mutation.ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite)
}

private final class PolicyTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date

    init(_ now: Date) {
        storedNow = now
    }

    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }
}
