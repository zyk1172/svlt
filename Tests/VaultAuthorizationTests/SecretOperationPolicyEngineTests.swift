import Foundation
import Testing
import VaultCore
import VaultExecution
@testable import VaultAuthorization

// SVLT policy classifies authorization requirements; it does not replace the
// device owner's decision. Agent risk is display/audit metadata only, while
// malformed or unverifiable descriptors remain technical failures.

@Test func hostnameIsAnOrdinarySecretBearingOperationAndEntersTheWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "NAS.LOCAL.",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read-only check",
            intendedEffect: "inspect service state"
        )
    )

    let decision = engine.evaluate(descriptor, metadata: [metadata])

    // §22: every secret-bearing execution defaults to reusableApproval —
    // the first use is one device-owner approval, then the 300-second
    // window covers follow-ups. There is no silent tier for secret ops.
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.requiredApproval)
}

@Test func agentApprovalHintIsDisplayOnlyAndDoesNotChangeTheRequirement() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "agent wants explicit confirmation",
            intendedEffect: "read host name"
        )
    )
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    // §30: AgentRisk never changes the authorization requirement. The hint
    // and its reason are displayed in the approval prompt only.
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.reasons.contains { $0.contains("Agent 提示此操作需要审批") })
    #expect(decision.reasons.contains { $0.contains("agent wants explicit confirmation") })
}

@Test func agentDeniedHintIsAWarningThatNeverChangesTheRequirement() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .denied,
            reason: "ambiguous request",
            intendedEffect: "unspecified"
        )
    )
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    // §30: an Agent "denied" hint is only a visible warning; the ordinary
    // reusable requirement is untouched and the owner still decides.
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.reasons.contains { $0.contains("Agent 自身认为此操作风险很高") })
    #expect(decision.requiredApproval)
}

@Test func agentApprovalHintKeepsReusableOperationsInsideTheExecutionWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "creates a directory",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    // The local classifier granted reusable approval for this reversible
    // write. An honest "this needs approval" hint must not upgrade it to a
    // fresh decision, which would silently disable the five-minute window.
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.requiredApproval)
}

@Test func agentDeniedHintOnReusableOperationDoesNotPromoteToFresh() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .denied,
            reason: "agent is unsure",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    // §30: the Agent cannot manufacture additional approval prompts. The
    // ordinary five-minute window stays intact.
    #expect(decision.authorizationRequirement == .reusableApproval)
}

@Test func destructiveSSHStaysFreshRegardlessOfAgentApprovalHint() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "removes a directory tree",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

// MARK: Raw SSH command tiers (§41/§42/§43)

@Test func ordinaryShellSyntaxAndUnknownCommandsEnterTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let ordinaryCommands = [
        "echo hello",
        "echo \"hello world\"",
        "cd /tmp && pwd",
        "cat /tmp/a | head",
        "echo hello > /tmp/file",
        "echo hello >> /tmp/file",
        "VAR=value command",
        "echo $HOME",
        "echo $(hostname)",
        "grep foo /tmp/a | head",
        "bash -c 'echo hello'",
        "sh -c 'echo hello'",
        "python3 -c 'print(\"hello\")'",
        "perl -e 'print 1;'",
        "node -e 'console.log(1)'",
        "find /tmp -exec echo {} \\;",
        "find /tmp -name \"*.log\"",
        "sudo systemctl restart example",
        "sudo reboot-check",
        "env sh -c 'echo hi'",
        "xargs -0 sh -c 'echo hi'",
        "qnap-custom-tool foo",
        "synoservice bar",
        "custom-nas-cli xyz",
        "unknown-command",
        "cat /etc/passwd",
        "printenv",
        "docker ps",
        "docker inspect web",
        "systemctl status nginx",
        "systemctl stop jellyfin",
        "cp -f /tmp/a /tmp/b",
        "mv /tmp/a /tmp/b",
        "chmod 755 /tmp/a",
        "chown admin /tmp/a",
        "mkdir /tmp/svlt-test",
        "touch /tmp/svlt-test"
    ]

    for command in ordinaryCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "command: \(command)")
        #expect(decision.risk == .approvalRequired, "command: \(command)")
    }
}

@Test func multilineShellConstructsEnterTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let multilineCommands = [
        """
        if [ -f /tmp/a ]; then
          echo yes
        else
          echo no
        fi
        """,
        """
        for x in a b c; do
          echo "$x"
        done
        """,
        """
        cat <<'EOF' > /tmp/test
        hello
        world
        EOF
        """,
        """
        foo() {
          echo hello
        }
        foo
        """
    ]

    for command in multilineCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "command: \(command)")
    }
}

@Test func explicitlyDangerousCommandsRequireFreshApprovalButAreNeverDenied() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let dangerousCommands = [
        "rm -rf /tmp/svlt-test",
        "rm /tmp/svlt-file",
        "shred /tmp/svlt-file",
        "mkfs.ext4 /dev/sda1",
        "wipefs /dev/sda",
        "fdisk /dev/sda",
        "parted /dev/sda print",
        "dd if=/dev/zero of=/dev/sda",
        "reboot",
        "shutdown -h now",
        "poweroff",
        "halt",
        "systemctl reboot",
        "systemctl poweroff",
        "systemctl halt",
        "systemctl isolate rescue.target",
        "docker rm web",
        "docker rm -f web",
        "docker volume rm data",
        "docker system prune"
    ]

    for command in dangerousCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .freshApprovalRequired, "command: \(command)")
        #expect(decision.risk == .approvalRequired, "command: \(command)")
        // §44/§45: the rule ID must come from the explicit fixed registry.
        #expect(SSHFreshRules.all.contains(decision.policyRuleID), "command: \(command)")
    }
}

@Test func technicalSSHFailuresStayTechnicalInsteadOfPolicyDenials() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    let empty = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: ""
    )
    let emptyDecision = engine().evaluate(empty, metadata: metadata)
    #expect(emptyDecision.risk == .denied)
    #expect(emptyDecision.technicalFailure)

    let nul = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "echo \u{0}hello"
    )
    // NUL inside a raw command string is technically unsendable to the
    // remote shell argv, so it stays a technical failure.
    let nulDecision = engine().evaluate(nul, metadata: metadata)
    #expect(nulDecision.risk == .denied)
    #expect(nulDecision.authorizationRequirement == .denied)
    #expect(nulDecision.technicalFailure)
    #expect(nulDecision.policyRuleID == "ssh.command.nul")

    let oversized = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: String(repeating: "a", count: 65_537)
    )
    let oversizedDecision = engine().evaluate(oversized, metadata: metadata)
    #expect(oversizedDecision.risk == .denied)
    #expect(oversizedDecision.technicalFailure)
}

// MARK: HTTP tiers (§49)

@Test func httpTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")

    func descriptor(method: String, url: String) -> SecretOperationDescriptor {
        let scheme = url.hasPrefix("https") ? "https" : "http"
        return SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: "qnap.local:8080",
            port: 8080,
            protocolType: SecretOperationProtocol(rawValue: scheme) ?? .http,
            httpMethod: method,
            url: url,
            parameters: ["tokenRef": reference.description]
        )
    }

    let engine = SecretOperationPolicyEngine()
    let metadata = [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http", "https"])]

    // §33: every Secret-bearing network send gets an explicit owner
    // decision. The destination is shown to the owner; hostname spelling is
    // never used as proof that the eventual connection is private.
    let ordinaryHTTPS = engine.evaluate(
        descriptor(method: "GET", url: "https://qnap.local:8080/api/status"),
        metadata: metadata
    )
    #expect(ordinaryHTTPS.authorizationRequirement == .freshApprovalRequired)
    #expect(ordinaryHTTPS.policyRuleID == "http.fresh.secret-network-send")
    #expect(engine.evaluate(descriptor(method: "POST", url: "https://qnap.local:8080/api/restart"), metadata: metadata).authorizationRequirement == .freshApprovalRequired)
    #expect(engine.evaluate(descriptor(method: "PUT", url: "https://qnap.local:8080/api/config"), metadata: metadata).authorizationRequirement == .freshApprovalRequired)

    let delete = engine.evaluate(descriptor(method: "DELETE", url: "https://qnap.local:8080/api/items/1"), metadata: metadata)
    #expect(delete.authorizationRequirement == .freshApprovalRequired)
    #expect(delete.policyRuleID == "http.fresh.delete")

    let insecure = engine.evaluate(descriptor(method: "GET", url: "http://qnap.local:8080/api/status"), metadata: metadata)
    #expect(insecure.authorizationRequirement == .freshApprovalRequired)
    #expect(insecure.policyRuleID == "http.fresh.insecure-secret-transport")
    #expect(insecure.reasons.contains { $0.contains("明文") })

    let credentialQuery = engine.evaluate(descriptor(method: "GET", url: "https://qnap.local:8080/api?token=abc"), metadata: metadata)
    #expect(credentialQuery.risk == .approvalRequired)
    #expect(credentialQuery.authorizationRequirement == .freshApprovalRequired)
    #expect(credentialQuery.technicalFailure == false)
    #expect(credentialQuery.policyRuleID == "http.fresh.credential-in-url")
}

@Test func HTTPTransportRiskIsOwnerApprovedBeforeTheExactProfileGate() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "nas-a.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://nas-a.local:8080/status",
        parameters: ["tokenRef": reference.description]
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas-b.local:8080"], protocols: ["https"])]
    )

    // Missing/mismatched insecure profiles are enforced by the executor only
    // after the owner-facing fresh approval path, not as a policy denial.
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.technicalFailure == false)
    #expect(decision.policyRuleID == "http.fresh.insecure-secret-transport")
}

@Test func httpDestinationMismatchOpensANewOrdinaryScopeWithAWarning() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    let unboundPrivate = engine.evaluate(SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "unbound-nas.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "POST",
        url: "https://unbound-nas.local:8080/api",
        parameters: ["tokenRef": reference.description]
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])])
    #expect(unboundPrivate.authorizationRequirement == .freshApprovalRequired)
    #expect(unboundPrivate.reasons.contains { $0.contains("不在该凭据已保存的绑定中") })

    let unboundPublic = engine.evaluate(SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "8.8.8.8",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://8.8.8.8/status",
        parameters: ["tokenRef": reference.description]
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])])
    #expect(unboundPublic.authorizationRequirement == .freshApprovalRequired)
    #expect(unboundPublic.policyRuleID == "http.fresh.secret-network-send")
    #expect(unboundPublic.reasons.contains { $0.contains("不在该凭据已保存的绑定中") })
    #expect(unboundPublic.reasons.contains { !$0.contains("公网地址") })
}

@Test func insecureHTTPRequiresFreshApprovalBeforeExecutorProfileCheck() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/status",
        parameters: ["tokenRef": reference.description]
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])
    ])

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.technicalFailure == false)
    #expect(decision.policyRuleID == "http.fresh.insecure-secret-transport")
}

@Test func sshDestinationMismatchOpensANewOrdinaryScopeWithAWarning() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    let mismatch = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "other-nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["ssh"])])

    // §31: the mismatched destination is a new execution scope — first use
    // takes the ordinary approval; the warning is display-only.
    #expect(mismatch.risk == .approvalRequired)
    #expect(mismatch.authorizationRequirement == .reusableApproval)
    #expect(mismatch.reasons.contains { $0.contains("不在该凭据已保存的绑定中") })
}

@Test func secretPolicyMismatchIsAWarningOnTheOrdinaryPath() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let readOnlyMetadata = [SecretPolicyMetadata(
        reference: reference,
        policy: .read,
        label: "read-only",
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["ssh"]
    )]

    let decision = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: readOnlyMetadata)

    // §32/§45: a saved credential-policy mismatch is a visible hint on the
    // ordinary path — never fresh, never denied.
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.reasons.contains { $0.contains("凭据被用户标记为") })
}

@Test func secretProtocolMismatchIsAWarningOnTheOrdinaryPath() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    let decision = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])])

    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.reasons.contains { $0.contains("凭据未绑定当前协议") })
}

@Test func databaseTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])]
    let engine = SecretOperationPolicyEngine()

    func decision(_ statement: String) -> PolicyDecision {
        engine.evaluate(SecretOperationDescriptor(
            actionType: .databaseQuery,
            secretReferences: [reference],
            destination: "db.local:5432",
            port: 5432,
            protocolType: .postgres,
            databaseStatement: statement
        ), metadata: metadata)
    }

    // §38: clearly read-only statements keep the reusable path so an Agent
    // can complete a normal multi-query workflow without authenticating for
    // every harmless SELECT.
    #expect(decision("SELECT 1").authorizationRequirement == .reusableApproval)
    #expect(decision("SELECT * FROM users WHERE id = 1").authorizationRequirement == .reusableApproval)

    // INSERT and harmless schema/session maintenance remain ordinary, but
    // their reusable leases are separated by operation family.
    #expect(decision("INSERT INTO logs VALUES (1)").authorizationRequirement == .reusableApproval)
    #expect(decision("UPDATE users SET name = 'x' WHERE id = 1").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("CREATE INDEX idx ON logs (ts)").authorizationRequirement == .reusableApproval)
    #expect(decision("ALTER TABLE logs ADD COLUMN note TEXT").authorizationRequirement == .reusableApproval)
    #expect(decision("VACUUM").authorizationRequirement == .reusableApproval)
    #expect(decision("SELECT 1; SELECT 2").authorizationRequirement == .reusableApproval)
    #expect(decision("my-custom-procedure-call").authorizationRequirement == .freshApprovalRequired)

    // The five fixed fresh rules cover destructive writes, destructive
    // structure changes, privilege/account administration, dynamic
    // execution, and unknown/unparseable SQL.
    #expect(decision("DROP TABLE logs").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("TRUNCATE TABLE logs").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("DELETE FROM logs").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("DELETE FROM logs WHERE id = 1").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("ALTER TABLE logs DROP COLUMN note").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("GRANT ALL ON app TO someone").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("REVOKE SELECT ON app FROM someone").authorizationRequirement == .freshApprovalRequired)
}

@Test func databaseClassifierCatchesWrappedAndVendorSpecificMutations() {
    let classifier = DatabaseStatementClassifier()
    let freshStatements: [(String, String)] = [
        (
            "WITH doomed AS (SELECT id FROM logs) DELETE FROM logs USING doomed WHERE logs.id = doomed.id",
            SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite
        ),
        (
            "WITH candidates AS (SELECT id FROM users) UPDATE users SET disabled = true FROM candidates WHERE users.id = candidates.id",
            SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite
        ),
        (
            "WITH removed AS (DELETE FROM logs RETURNING id) SELECT id FROM removed",
            SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite
        ),
        (
            "MERGE INTO inventory AS target USING incoming AS source ON target.id = source.id WHEN MATCHED THEN UPDATE SET count = source.count",
            SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite
        ),
        (
            "CREATE USER app_user IDENTIFIED BY 'not-a-secret-fixture'",
            SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin
        ),
        (
            "ALTER ROLE app_user SET statement_timeout = 0",
            SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin
        ),
        (
            "SET GLOBAL max_connections = 200",
            SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin
        ),
        (
            "ALTER SYSTEM SET log_statement = 'all'",
            SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin
        ),
        (
            "GRANT SELECT ON *.* TO app_user",
            SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin
        ),
        (
            "DO $$ BEGIN DELETE FROM logs; END $$",
            SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution
        ),
        (
            "CALL rotate_credentials()",
            SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution
        ),
        (
            "PREPARE purge AS DELETE FROM logs",
            SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution
        ),
        (
            "CREATE PROCEDURE purge_logs() BEGIN DELETE FROM logs; END",
            SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution
        ),
        (
            "SELECT * INTO OUTFILE '/tmp/export.txt' FROM logs",
            SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution
        )
    ]

    for (statement, ruleID) in freshStatements {
        let classification = classifier.classify(statement)
        #expect(classification.requirement == .freshApprovalRequired)
        #expect(classification.ruleID == ruleID)
    }
}

@Test func databaseClassifierPreservesReadWorkflowsAndDoesNotReadDangerousWordsFromLiterals() {
    let classifier = DatabaseStatementClassifier()
    let readStatements = [
        "-- DELETE FROM logs\nSELECT 'UPDATE users SET password = redacted'",
        "/* GRANT ALL */ SELECT \"delete\" FROM \"update\"",
        "SELECT $$DROP TABLE logs;$$ AS example",
        "SELECT $tag$DROP TABLE logs;$tag$ AS example",
        "WITH recent AS (SELECT id FROM logs WHERE message = 'MERGE') SELECT id FROM recent",
        "SHOW TABLES; DESCRIBE logs; EXPLAIN SELECT 1",
        "# TRUNCATE logs\nSELECT 1; SELECT 2"
    ]

    for statement in readStatements {
        let classification = classifier.classify(statement)
        #expect(classification.requirement == .reusableApproval)
        #expect(classification.scopeFamily == "database.read")
    }
}

@Test func databaseClassifierUsesNarrowOperationFamiliesForReusableWorkflows() {
    let classifier = DatabaseStatementClassifier()
    let read = classifier.classify("SELECT 1")
    let insert = classifier.classify("INSERT INTO logs VALUES (1)")
    let schema = classifier.classify("CREATE INDEX idx ON logs (ts)")

    #expect(read.requirement == .reusableApproval)
    #expect(insert.requirement == .reusableApproval)
    #expect(schema.requirement == .reusableApproval)
    #expect(read.scopeFamily == "database.read")
    #expect(insert.scopeFamily == "database.ordinary.insert")
    #expect(schema.scopeFamily == "database.ordinary.schema-maintenance")
    #expect(Set([read.scopeFamily, insert.scopeFamily, schema.scopeFamily]).count == 3)
}

@Test func databaseClassifierTakesConservativeFreshApprovalForUnknownOrMalformedSQL() {
    let classifier = DatabaseStatementClassifier()
    let unknownStatements = [
        "SELEC 1",
        "MYSTERY_OPERATION 1",
        "WITH rows AS (SELECT 1) mystery_operation()",
        "SELECT (1",
        "SELECT $tag$ SELECT 1"
    ]

    for statement in unknownStatements {
        let classification = classifier.classify(statement)
        #expect(classification.requirement == .freshApprovalRequired)
        #expect(classification.ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.unknown)
        #expect(classification.scopeFamily == "database.fresh.unknown")
    }
}

@Test func databasePolicyExposesConservativeOwnerVisibleReasons() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [reference],
        destination: "db.local:5432",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: "SELEC 1"
    )
    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])]
    )

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == SecretOperationPolicyEngine.DatabaseFreshRules.unknown)
    #expect(decision.reasons.contains { $0.contains("无法被本地分类器可靠识别") })
    #expect(decision.authorizationRequirement != .denied)
    #expect(!decision.technicalFailure)
}

@Test func sftpTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["sftp"])]
    let engine = SecretOperationPolicyEngine()

    func decision(_ operation: SecretFileOperation, _ target: String?) -> PolicyDecision {
        engine.evaluate(SecretOperationDescriptor(
            actionType: .sftpTransfer, secretReferences: [reference],
            destination: "nas.local", port: 22, protocolType: .sftp,
            fileOperation: operation, fileTarget: target
        ), metadata: metadata)
    }

    // §39: ordinary transfers share the 300-second window regardless of the
    // local path — there are no safe-directory fresh rules.
    #expect(decision(.list, "/share").authorizationRequirement == .reusableApproval)
    #expect(decision(.read, "/share/a").authorizationRequirement == .reusableApproval)
    #expect(decision(.download, "/tmp/elsewhere/report.txt").authorizationRequirement == .reusableApproval)
    #expect(decision(.upload, "/tmp/elsewhere/report.txt").authorizationRequirement == .reusableApproval)
    #expect(decision(.move, "/share/b").authorizationRequirement == .reusableApproval)

    // Fixed fresh rules.
    #expect(decision(.delete, "/share/report.txt").authorizationRequirement == .freshApprovalRequired)
    #expect(decision(.overwrite, "/share/report.txt").authorizationRequirement == .freshApprovalRequired)
    #expect(decision(.write, "/share/report.txt").authorizationRequirement == .freshApprovalRequired)
}

@Test func ftpTransfersRequireFreshApprovalForPlaintextTransport() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ftp"])]
    let descriptor = SecretOperationDescriptor(
        actionType: .ftpTransfer,
        secretReferences: [reference],
        destination: "nas.local",
        port: 21,
        protocolType: .ftp,
        fileOperation: .list,
        fileTarget: nil
    )

    let decision = engine().evaluate(descriptor, metadata: metadata)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "ftp.fresh.plaintext-transport")
    #expect(decision.reasons.contains { $0.contains("明文传输凭据") })
}

@Test func localExecutionIsASingleFixedFreshSecretReleaseRule() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: [], protocols: [])
    let descriptor = SecretOperationDescriptor(actionType: .localExecution, secretReferences: [reference])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.reasons.contains { $0.contains("把凭据交给本地任意进程") })
    #expect(decision.policyRuleID == "local-execution.fresh.arbitrary-secret-release")
}

@Test func trustedProcessUsesTheOrdinaryWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let trustedPayload = SecretOperationPayload.trustedProcess(
        TrustedProcessOperation(profileID: "signed-helper", secretReferences: [reference])
    )
    let trusted = SecretOperationDescriptor(
        actionType: .trustedProcess,
        secretReferences: [reference],
        payload: trustedPayload
    )

    // §43: a user-registered signed process profile is an ordinary scoped
    // operation — first approval opens the five-minute window.
    #expect(engine().evaluate(trusted, metadata: [policyMetadata(reference, destinations: [], protocols: [])]).authorizationRequirement == .reusableApproval)
}

@Test func duplicateSecretReferencesAreRejectedWithoutTrapping() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference, reference],
        destination: "qnap.local",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local/status"
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])
    ])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "secret-reference.duplicate")
}

@Test func legacyExecutionReferencesMustExactlyMatchTheDescriptorSet() throws {
    let password = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let extra = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [password, extra],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        parameters: [
            "passwordRef": password.description,
            "username": "admin"
        ]
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(password, destinations: ["qnap.local"], protocols: ["ssh"]),
        policyMetadata(extra, destinations: ["qnap.local"], protocols: ["ssh"])
    ])

    // Only the password reference is executable in this legacy shape. An
    // extra declared reference would otherwise widen the lease's scope.
    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "operation.reference-mismatch")
}

@Test func missingSecretMetadataIsATechnicalFailureBeforeApproval() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    )

    let decision = engine().evaluate(descriptor, metadata: [])

    #expect(decision.risk == .denied)
    #expect(decision.authorizationRequirement == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "secret-metadata.missing")
}

@Test func contradictoryDescriptorFieldsRemainTechnicalFailures() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local",
        protocolType: .https,
        httpMethod: "GET",
        url: "https://evil.example/status",
        parameters: ["tokenRef": reference.description]
    )

    let decision = engine().evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "http.destination-mismatch")
}

@Test func operationPortMustMatchTheActualTarget() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    let descriptor = SecretOperationDescriptor(
        actionType: .httpRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 443,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status",
        parameters: ["passwordRef": reference.description]
    )

    let decision = engine().evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "http.port-mismatch")
}

@Test func operationHashIsIndependentOfTheAgentRiskReport() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let base = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local:8080/api/status",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "check NAS status",
            intendedEffect: "read status"
        )
    )
    let reworded = SecretOperationDescriptor(
        actionType: base.actionType,
        secretReferences: base.secretReferences,
        destination: base.destination,
        port: base.port,
        protocolType: base.protocolType,
        httpMethod: base.httpMethod,
        url: base.url,
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read NAS status",
            intendedEffect: "completely different wording"
        )
    )

    #expect(base.operationHash == reworded.operationHash)
}

@Test func transportSessionIDDoesNotChangeTheOperationAuthorizationHash() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let base = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        parameters: ["passwordRef": reference.description, "username": "admin"]
    )
    let withSession = SecretOperationDescriptor(
        actionType: base.actionType,
        secretReferences: base.secretReferences,
        destination: base.destination,
        port: base.port,
        protocolType: base.protocolType,
        command: base.command,
        sessionID: "ssh_session_opaque",
        requestedEffects: base.requestedEffects,
        parameters: base.parameters,
        agentAssessment: base.agentAssessment
    )

    #expect(base.operationHash == withSession.operationHash)
}

@Test func rawCommandLengthLimitMatchesTheExecutorCeiling() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    let withinLimit = engine().evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: String(repeating: "echo hi\n", count: 1_000)
    ), metadata: metadata)
    #expect(withinLimit.authorizationRequirement == .reusableApproval)
}

private func engine() -> SecretOperationPolicyEngine {
    SecretOperationPolicyEngine()
}

private func policyMetadata(
    _ reference: SecretReference,
    destinations: [String],
    protocols: [String]
) -> SecretPolicyMetadata {
    SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "QNAP credential",
        allowedDestinations: destinations,
        allowedProtocols: protocols
    )
}


// MARK: §44/§45 — fixed fresh rule registry bounds

@Test func freshRuleRegistriesNeverExceedFiveCategoriesPerLayer() {
    #expect(SSHFreshRules.all.count <= 5)
    #expect(SecretOperationPolicyEngine.HTTPFreshRules.all.count == 5)
    #expect(SecretOperationPolicyEngine.DatabaseFreshRules.all.count <= 5)
    #expect(SecretOperationPolicyEngine.SFTPFreshRules.all.count <= 5)
}

@Test func localExecutionHasExactlyOneFreshRule() {
    // §42: the only localExecution fresh category is arbitrary secret
    // release; there is deliberately nothing else.
    let reference = try! SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    #expect(engine().evaluate(SecretOperationDescriptor(
        actionType: .localExecution,
        secretReferences: [reference]
    ), metadata: [policyMetadata(reference, destinations: [], protocols: [])]).policyRuleID == "local-execution.fresh.arbitrary-secret-release")
}

// MARK: §28/§71 — the shallow dangerous scanner sees through wrappers

@Test func dangerousScannerCatchesWrapperAndCompositionForms() {
    let classifier = SSHCommandRiskClassifier()
    let freshCommands: [(String, String)] = [
        ("rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("/bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("/usr/bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sudo rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sudo /bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("env MODE=maintenance rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sh -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("sudo bash -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("echo \"$(rm -rf /tmp/a)\"", SSHFreshRules.filesystemDelete),
        ("printf '%s' `rm -rf /tmp/a`", SSHFreshRules.filesystemDelete),
        ("find /tmp -exec rm -rf {} \\;", SSHFreshRules.filesystemDelete),
        ("xargs rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("eval 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("bash -c 'reboot'", SSHFreshRules.powerControl),
        ("hostname && rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("uptime\nrm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("/sbin/reboot", SSHFreshRules.powerControl),
        ("docker system prune", SSHFreshRules.containerDestruction),
        ("docker rm web", SSHFreshRules.containerDestruction),
        ("zpool destroy tank", SSHFreshRules.storageRaidDestruction),
        ("mdadm --zero-superblock /dev/md0", SSHFreshRules.storageRaidDestruction),
        ("systemctl isolate rescue.target", SSHFreshRules.powerControl)
    ]
    for (command, expectedRule) in freshCommands {
        let match = classifier.matchFixedFreshRule(in: command)
        #expect(match == expectedRule, "command: \(command)")
    }
}

@Test func ordinaryFormsAreNeverPromotedByTheScanner() {
    let classifier = SSHCommandRiskClassifier()
    let ordinary = [
        "bash -c 'echo hello'",
        "python3 -c 'print(1)'",
        "find /tmp -exec echo {} \\;",
        "sudo systemctl restart jellyfin",
        "unknown-nas-command",
        "cd /tmp && df -h",
        "docker ps",
        "docker restart web",
        "systemctl stop jellyfin",
        "zpool status",
        "uptime\ndf -h",
        // Arguments and data must not be scanned as executable positions.
        "echo rm",
        "echo '$(rm -rf /tmp/not-executed)'",
        "echo \\$(rm -rf /tmp/not-executed)",
        "printf 'reboot\\n'",
        "cat /tmp/rm",
        "grep reboot logfile",
        "cat /backup/dd",
        // A heredoc body is input for `cat`, not a command stream.
        """
        cat <<'EOF'
        rm -rf /tmp/not-executed
        reboot
        EOF
        """
    ]
    for command in ordinary {
        #expect(classifier.matchFixedFreshRule(in: command) == nil, "command: \(command)")
        #expect(classifier.classify(command: command).authorizationRequirement == .reusableApproval, "command: \(command)")
    }
}

@Test func structuredArgumentsAreNeverTreatedAsExecutablePositions() {
    let classifier = SSHCommandRiskClassifier()

    let ordinarySpecs = [
        SSHCommandSpec(executable: "echo", arguments: ["rm"]),
        SSHCommandSpec(executable: "cat", arguments: ["/tmp/rm"]),
        SSHCommandSpec(executable: "grep", arguments: ["reboot", "logfile"]),
        SSHCommandSpec(executable: "printf", arguments: ["rm\\n"])
    ]
    for spec in ordinarySpecs {
        #expect(
            classifier.classify(spec: spec).authorizationRequirement == .reusableApproval,
            "spec: \(spec)"
        )
    }

    let shellScript = SSHCommandSpec(
        executable: "bash",
        arguments: ["-c", "rm -rf /tmp/a"]
    )
    #expect(
        classifier.classify(spec: shellScript).authorizationRequirement == .freshApprovalRequired
    )

    let wrappedSpecs = [
        SSHCommandSpec(executable: "sudo", arguments: ["rm", "-rf", "/tmp/a"]),
        SSHCommandSpec(executable: "doas", arguments: ["/bin/rm", "-rf", "/tmp/a"]),
        SSHCommandSpec(executable: "env", arguments: ["MODE=maintenance", "rm", "-rf", "/tmp/a"]),
        SSHCommandSpec(executable: "find", arguments: ["/tmp", "-exec", "rm", "-rf", "{}", ";"]),
        SSHCommandSpec(executable: "xargs", arguments: ["rm", "-rf", "/tmp/a"]),
        SSHCommandSpec(executable: "eval", arguments: ["rm -rf /tmp/a"])
    ]
    for spec in wrappedSpecs {
        #expect(
            classifier.classify(spec: spec).authorizationRequirement == .freshApprovalRequired,
            "spec: \(spec)"
        )
    }
}


// MARK: §47/§48 — structured batch counts (1/2/3/10/32) flow through every layer

@Test func structuredBatchesOfAnySizeUpToTheLimitFlowThroughPolicyAndPreflight() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    func descriptor(_ commands: [SSHCommandSpec]) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: commands),
            parameters: ["passwordRef": reference.description, "username": "admin"]
        )
    }

    let simple: [SSHCommandSpec] = [
        .init(executable: "uptime"),
        .init(executable: "cat", arguments: ["/proc/loadavg"]),
        .init(executable: "df", arguments: ["-h"]),
        .init(executable: "touch", arguments: ["/tmp/svlt-a"]),
        .init(executable: "mkdir", arguments: ["/tmp/svlt-b"]),
        .init(executable: "hostname"),
        .init(executable: "df", arguments: ["-h", "/share"]),
        .init(executable: "ls", arguments: ["/tmp"]),
        .init(executable: "cat", arguments: ["/etc/hostname"]),
        .init(executable: "whoami")
    ]
    let executor = LocalSecretOperationExecutor()

    for count in [1, 2, 3, 10, 32] {
        let filler = Array(repeating: SSHCommandSpec(executable: "echo", arguments: ["ok"]), count: max(0, count - simple.count))
        let commands = (simple + filler).prefix(count)
        let d = descriptor(Array(commands))
        let decision = engine.evaluate(d, metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "batch size \(count)")
        #expect(!decision.technicalFailure, "batch size \(count)")
        #expect(executor.preflight(d) == .supported, "batch size \(count)")
    }

    // Over the technical limit: a validation error, never a policy refusal.
    let oversized = Array(repeating: SSHCommandSpec(executable: "echo", arguments: ["ok"]), count: 33)
    let oversizedDecision = engine.evaluate(descriptor(oversized), metadata: metadata)
    #expect(oversizedDecision.technicalFailure)
}
