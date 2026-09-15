import Foundation
import Testing
import VaultCore
import VaultExecution
@testable import VaultAuthorization

// Intent-first authorization tests.
//
// The deterministic classifier still describes the concrete operation and
// enforces technical/identity failures plus a deliberately small hard floor.
// For every other Secret-bearing operation, the structured semantic assessment
// is the final authorization recommendation. These tests intentionally avoid
// the retired model where every lexical "dangerous" category was itself a
// non-downgradable approval decision.

@Test func ordinarySSHCanExecuteAutomaticallyWhenSemanticsAreClear() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Read the host name requested by the user"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.risk == .silent)
    #expect(!decision.requiredApproval)
    #expect(decision.policyRuleID.hasSuffix("+intent-first"))
    #expect(decision.reasons.contains { $0.contains("mainAgent") })
}

@Test func interpreterRiskFollowsDeclaredEffectInsteadOfExecutableName() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    let analysis = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "python3 inspect_moviepilot.py",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "The script only reads and summarizes the requested service state"
        )
    )
    let automatic = engine().evaluate(analysis, metadata: metadata)
    #expect(automatic.authorizationRequirement == .none)

    let unresolved = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "python3 maintenance.py",
        agentAssessment: semanticAssessment(
            recommendation: .uncertain,
            alignment: .unclear,
            severity: .unknown,
            reversibility: .unknown,
            secretHandling: .unknown,
            confidence: 0.2,
            reason: "The script body and final effect are unavailable"
        )
    )
    let unresolvedPreflight = engine().semanticPreflight(unresolved, metadata: metadata)
    #expect(unresolvedPreflight.route == .gray)
    #expect(engine().evaluate(unresolved, metadata: metadata).authorizationRequirement == .freshApprovalRequired)

    let lowConfidenceBounded = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "cat /etc/os-release",
        agentAssessment: semanticAssessment(
            recommendation: .freshApproval,
            confidence: 0.64,
            reason: "The command appears bounded but the effect assessment is below the confidence threshold"
        )
    )
    #expect(engine().semanticPreflight(lowConfidenceBounded, metadata: metadata).route == .gray)
}

@Test func semanticRecommendationDirectlySelectsOrdinaryApprovalLevel() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    func decision(_ recommendation: AgentRiskAssessment.ExecutionRecommendation) -> PolicyDecision {
        engine().evaluate(
            SecretOperationDescriptor(
                actionType: .sshCommand,
                secretReferences: [reference],
                destination: "nas.local",
                port: 22,
                protocolType: .ssh,
                command: "mkdir /share/svlt-test",
                agentAssessment: semanticAssessment(
                    recommendation: recommendation,
                    severity: .minor,
                    reversibility: .easy,
                    reason: "Create one requested working directory"
                )
            ),
            metadata: metadata
        )
    }

    #expect(decision(.automatic).authorizationRequirement == .none)
    // The compatibility enum is not an approval class anymore, and a
    // conservative main-Agent recommendation cannot override a bounded,
    // recoverable effect proof.
    #expect(decision(.reusableApproval).authorizationRequirement == .none)
    #expect(decision(.freshApproval).authorizationRequirement == .none)
    #expect(decision(.uncertain).authorizationRequirement == .freshApprovalRequired)
}

@Test func independentJudgeUsesTheSameStructuredAuthorizationContract() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "systemctl status jellyfin",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Independent review found only a read-only status query"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.reasons.contains { $0.contains("independentJudge") })
    #expect(decision.reasons.contains { $0.contains("Independent review") })
}

@Test func lexicalFilesystemDeletionCanBeReducedByVerifiedJudgeSemantics() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/svlt-test",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "Independent review confirms one bounded task-owned directory"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.risk == .silent)
    #expect(decision.policyRuleID == "\(SSHFreshRules.filesystemDelete)+intent-first")
}

@Test func lexicalContainerDestructionCanBeReducedByVerifiedJudgeSemantics() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "docker rm old-preview-container",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "Independent review confirms one disposable preview container"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.policyRuleID == "\(SSHSemanticGrayRules.containerLifecycleRemoval)+intent-first")
}

@Test func powerControlRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "reboot",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .minor,
            reversibility: .easy,
            reason: "Even an optimistic semantic assessment cannot bypass power control"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SSHFreshRules.powerControl)+intent-first")
}

@Test func poweroffAndShutdownRemainNonDowngradableHardFloors() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    for command in ["poweroff", "shutdown -h now", "halt"] {
        let decision = engine().evaluate(
            SecretOperationDescriptor(
                actionType: .sshCommand,
                secretReferences: [reference],
                destination: "nas.local",
                port: 22,
                protocolType: .ssh,
                command: command,
                agentAssessment: semanticAssessment(
                    recommendation: .automatic,
                    severity: .none,
                    reversibility: .readOnly,
                    reason: "Power control must remain owner-approved"
                )
            ),
            metadata: metadata
        )
        #expect(decision.authorizationRequirement == .freshApprovalRequired, "command: \(command)")
        #expect(decision.policyRuleID == "\(SSHFreshRules.powerControl)+intent-first", "command: \(command)")
    }
}

@Test func destructiveDockerVolumeRemovalRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let decision = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "docker volume rm moviepilot-data",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .none,
                reversibility: .readOnly,
                reason: "A semantic recommendation cannot bypass volume destruction"
            )
        ),
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SSHFreshRules.containerDestruction)+intent-first")
}

@Test func conservativeMainAgentFreshRecommendationDoesNotForceApprovalForBoundedSSH() throws {
    let reference = try testReference()
    let decision = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "cat /etc/moviepilot/config.json",
            agentAssessment: semanticAssessment(
                recommendation: .freshApproval,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "The main Agent is conservatively requesting review"
            )
        ),
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.risk == .silent)
}

@Test func blockDeviceDestructionRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkfs.ext4 /dev/sda1",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .minor,
            reversibility: .easy,
            reason: "Hard floor must override this deliberately optimistic assessment"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SSHFreshRules.blockDeviceFilesystem)+intent-first")
}

@Test func storageRaidDestructionRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "zpool destroy tank",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .minor,
            reversibility: .easy,
            reason: "Hard floor must override this deliberately optimistic assessment"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SSHFreshRules.storageRaidDestruction)+intent-first")
}

@Test func httpsCredentialUseCanBeAutomaticWhenSemanticsAreOrdinary() throws {
    let reference = try testReference()
    let descriptor = httpDescriptor(
        reference: reference,
        method: "GET",
        url: "https://qnap.local:8080/api/status",
        assessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Read the requested service status using its credential"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.HTTPFreshRules.secretNetworkSend)+intent-first")
}

@Test func ordinaryHTTPSWritesRemainAutomaticWhenEffectIsBounded() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])]

    for method in ["POST", "PUT", "PATCH"] {
        let decision = engine().evaluate(
            httpDescriptor(
                reference: reference,
                method: method,
                url: "https://qnap.local:8080/api/status",
                assessment: semanticAssessment(
                    recommendation: .automatic,
                    severity: .bounded,
                    reversibility: .recoverable,
                    reason: "Update one task-owned service record"
                )
            ),
            metadata: metadata
        )
        #expect(decision.authorizationRequirement == .none, "method: \(method)")
    }
}

@Test func httpDeleteIsASemanticSignalAfterVerifiedJudgeReview() throws {
    let reference = try testReference()
    let descriptor = httpDescriptor(
        reference: reference,
        method: "DELETE",
        url: "https://qnap.local:8080/api/items/temporary-1",
        assessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "Independent review confirms one disposable object"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.HTTPFreshRules.delete)+intent-first")
}

@Test func insecureHTTPSecretTransportRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status",
        parameters: ["tokenRef": reference.description],
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Transport safety remains a hard floor"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.HTTPFreshRules.insecureSecretTransport)+intent-first")
}

@Test func credentialInURLRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = httpDescriptor(
        reference: reference,
        method: "GET",
        url: "https://qnap.local:8080/api?token=abc",
        assessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "URL credential exposure remains a hard floor"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.HTTPFreshRules.credentialInURL)+intent-first")
}

@Test func databaseDataDeletionCanBeReducedByVerifiedJudgeSemantics() throws {
    let reference = try testReference()
    let descriptor = databaseDescriptor(
        reference: reference,
        statement: "DELETE FROM logs WHERE id = 1",
        assessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "Independent review confirms one task-owned row"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])
    ])

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.policyRuleID == "database.ordinary.automatic+intent-first")
}

@Test func databaseDestructiveStructureRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = databaseDescriptor(
        reference: reference,
        statement: "DROP TABLE logs",
        assessment: semanticAssessment(
            recommendation: .automatic,
            severity: .minor,
            reversibility: .easy,
            reason: "Hard floor must override the recommendation"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.DatabaseFreshRules.destructiveStructure)+intent-first")
}

@Test func databasePrivilegeAdministrationRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = databaseDescriptor(
        reference: reference,
        statement: "GRANT ALL ON app TO someone",
        assessment: semanticAssessment(
            recommendation: .automatic,
            severity: .minor,
            reversibility: .easy,
            reason: "Hard floor must override the recommendation"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "\(SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin)+intent-first")
}

@Test func dynamicOrUnknownDatabaseClassificationCanUseVerifiedJudgeDecision() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])]

    for statement in ["CALL rotate_credentials()", "MYSTERY_OPERATION 1"] {
        let decision = engine().evaluateWithVerifiedIndependentJudge(
            databaseDescriptor(
                reference: reference,
                statement: statement,
                assessment: semanticAssessment(
                    source: .independentJudge,
                    recommendation: .reusableApproval,
                    severity: .bounded,
                    reversibility: .recoverable,
                    reason: "The upstream semantic layer resolved the concrete task effect"
                )
            ),
            metadata: metadata
        )
        #expect(decision.authorizationRequirement == .none, "statement: \(statement)")
    }
}

@Test func sftpDeleteOverwriteAndWriteAreSemanticSignalsNotHardFloors() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["sftp"])]

    for operation in [SecretFileOperation.delete, .overwrite, .write] {
        let descriptor = SecretOperationDescriptor(
            actionType: .sftpTransfer,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .sftp,
            fileOperation: operation,
            fileTarget: "/share/task-owned-file",
            agentAssessment: semanticAssessment(
                source: .independentJudge,
                recommendation: .automatic,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "Independent review confirms bounded task-owned file mutation"
            )
        )

        let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: metadata)
        #expect(decision.authorizationRequirement == .none, "operation: \(operation)")
        #expect(decision.policyRuleID.hasSuffix("+intent-first"), "operation: \(operation)")
    }
}

@Test func ordinarySFTPWriteDoesNotNeedIndependentJudgeOrOwnerApproval() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sftpTransfer,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .sftp,
        fileOperation: .write,
        fileTarget: "/share/task-owned-result.json",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .bounded,
            reversibility: .recoverable,
            reason: "Save one task-owned analysis result"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["sftp"])
    ])
    #expect(decision.authorizationRequirement == .none)
    #expect(decision.policyRuleID == "sftp.ordinary.automatic+intent-first")
}

@Test func grayJudgeCanUpgradeAnUnresolvedEffectToFreshApproval() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/task-owned-temp",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .freshApproval,
            severity: .broad,
            reversibility: .difficult,
            reason: "Independent review found a broad, difficult-to-recover deletion"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func verifiedGrayJudgeCanKeepAProhibitedEffectDenied() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/task-owned-temp",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .denied,
            severity: .broad,
            reversibility: .irreversible,
            reason: "Independent review found the requested deletion is prohibited"
        )
    )

    let decision = engine().evaluateWithVerifiedIndependentJudge(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    ])
    #expect(decision.risk == .denied)
    #expect(decision.authorizationRequirement == .denied)
}

@Test func semanticHardFloorRoutesCredentialExposureToHardPreflight() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            secretHandling: .plaintextSecretExposure,
            reason: "The credential would be exposed"
        )
    )

    let preflight = engine().semanticPreflight(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )
    #expect(preflight.route == .hard)
}

@Test func ftpPlaintextCredentialTransportRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .ftpTransfer,
        secretReferences: [reference],
        destination: "nas.local",
        port: 21,
        protocolType: .ftp,
        fileOperation: .list,
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Transport safety remains a hard floor"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["nas.local"], protocols: ["ftp"])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "ftp.fresh.plaintext-transport+intent-first")
}

@Test func arbitraryLocalProcessSecretReleaseRemainsANonDowngradableHardFloor() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .localExecution,
        secretReferences: [reference],
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "The hard floor owns arbitrary local Secret release"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: [], protocols: [])
    ])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "local-execution.fresh.arbitrary-secret-release+intent-first")
}

@Test func technicalFailuresCannotBeOverriddenBySemanticAssessment() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let optimistic = semanticAssessment(
        recommendation: .automatic,
        severity: .none,
        reversibility: .readOnly,
        reason: "Deliberately optimistic"
    )

    let empty = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "",
            agentAssessment: optimistic
        ),
        metadata: metadata
    )
    #expect(empty.authorizationRequirement == .denied)
    #expect(empty.risk == .denied)
    #expect(empty.technicalFailure)

    let oversized = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: String(repeating: "a", count: 65_537),
            agentAssessment: optimistic
        ),
        metadata: metadata
    )
    #expect(oversized.authorizationRequirement == .denied)
    #expect(oversized.technicalFailure)
}

@Test func identityAndDescriptorMismatchesCannotBeOverriddenBySemantics() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local",
        protocolType: .https,
        httpMethod: "GET",
        url: "https://evil.example/status",
        parameters: ["tokenRef": reference.description],
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Semantic assessment cannot repair an invalid descriptor"
        )
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])
    ])

    #expect(decision.authorizationRequirement == .denied)
    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "http.destination-mismatch")
}

@Test func duplicateAndMissingSecretMetadataRemainTechnicalFailures() throws {
    let reference = try testReference()
    let assessment = semanticAssessment(
        recommendation: .automatic,
        severity: .none,
        reversibility: .readOnly,
        reason: "Semantic assessment cannot repair Secret identity failures"
    )

    let duplicate = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference, reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "hostname",
            agentAssessment: assessment
        ),
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )
    #expect(duplicate.authorizationRequirement == .denied)
    #expect(duplicate.policyRuleID == "secret-reference.duplicate")

    let missing = engine().evaluate(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "hostname",
            agentAssessment: assessment
        ),
        metadata: []
    )
    #expect(missing.authorizationRequirement == .denied)
    #expect(missing.policyRuleID == "secret-metadata.missing")
}

@Test func deterministicSSHClassifierStillDetectsConcreteRiskFamilies() {
    let classifier = SSHCommandRiskClassifier()
    let cases: [(String, String)] = [
        ("rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sudo bash -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("reboot", SSHFreshRules.powerControl),
        ("mkfs.ext4 /dev/sda1", SSHFreshRules.blockDeviceFilesystem),
        ("docker rm web", SSHSemanticGrayRules.containerLifecycleRemoval),
        ("docker volume rm app-data", SSHFreshRules.containerDestruction),
        ("zpool destroy tank", SSHFreshRules.storageRaidDestruction)
    ]

    for (command, expectedRule) in cases {
        let classification = classifier.classify(command: command)
        #expect(classification.authorizationRequirement == .freshApprovalRequired, "command: \(command)")
        #expect(classification.ruleID == expectedRule, "command: \(command)")
    }
}

@Test func nestedDockerEffectIsClassifiedFromTheInnerOperationNotTheWrapper() {
    let classifier = SSHCommandRiskClassifier()

    let read = classifier.classify(command: "docker exec moviepilot cat /etc/app/config.json")
    #expect(read.authorizationRequirement == .none)

    let destructive = classifier.classify(command: "docker exec moviepilot rm -rf /data/cache")
    #expect(destructive.authorizationRequirement == .freshApprovalRequired)
    #expect(destructive.ruleID == SSHFreshRules.filesystemDelete)

    let dryRun = classifier.classify(command: "docker exec moviepilot rm -rf --dry-run /data/cache")
    #expect(dryRun.authorizationRequirement == .none)
}

@Test func ordinarySSHClassifierInputsRemainOrdinary() {
    let classifier = SSHCommandRiskClassifier()
    let commands = [
        "hostname",
        "df -h",
        "sudo systemctl restart jellyfin",
        "systemctl stop jellyfin",
        "docker restart web",
        "cat /etc/passwd",
        "mkdir /tmp/svlt-test",
        "touch /tmp/svlt-test"
    ]

    for command in commands {
        let classification = classifier.classify(command: command)
        #expect(classification.authorizationRequirement == .none, "command: \(command)")
    }
}

@Test func databaseClassifierStillDescribesConcreteSQLRiskWithoutOwningFinalSemanticDecision() {
    let classifier = DatabaseStatementClassifier()

    #expect(classifier.classify("SELECT 1").requirement == .none)
    #expect(classifier.classify("INSERT INTO logs VALUES (1)").requirement == .none)
    #expect(classifier.classify("INSERT INTO logs VALUES (1) ON CONFLICT (id) DO UPDATE SET value = 2").requirement == .none)
    #expect(classifier.classify("WITH inserted AS (INSERT INTO audit VALUES (1) RETURNING id) DELETE FROM logs USING inserted WHERE logs.id = inserted.id").requirement == .freshApprovalRequired)
    #expect(classifier.classify("DELETE FROM logs WHERE id = 1").ruleID == "database.ordinary.automatic")
    #expect(classifier.classify("DELETE FROM logs").ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite)
    #expect(classifier.classify("DROP TABLE logs").ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.destructiveStructure)
    #expect(classifier.classify("GRANT ALL ON app TO someone").ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin)
    #expect(classifier.classify("CALL rotate_credentials()").ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution)
    #expect(classifier.classify("MYSTERY_OPERATION 1").ruleID == SecretOperationPolicyEngine.DatabaseFreshRules.unknown)
}

@Test func structuredSSHBatchLimitsRemainTechnicalBoundaries() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let assessment = semanticAssessment(
        recommendation: .automatic,
        severity: .none,
        reversibility: .readOnly,
        reason: "Read-only structured batch"
    )

    for count in [1, 2, 3, 10, 32] {
        let commands = Array(repeating: SSHCommandSpec(executable: "hostname"), count: count)
        let descriptor = SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: commands),
            agentAssessment: assessment
        )
        let decision = engine().evaluate(descriptor, metadata: metadata)
        #expect(decision.authorizationRequirement == .none, "batch size \(count)")
        #expect(!decision.technicalFailure, "batch size \(count)")
    }

    let oversized = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(
            commands: Array(repeating: SSHCommandSpec(executable: "hostname"), count: 33)
        ),
        agentAssessment: assessment
    )
    let oversizedDecision = engine().evaluate(oversized, metadata: metadata)
    #expect(oversizedDecision.authorizationRequirement == .denied)
    #expect(oversizedDecision.technicalFailure)
}

@Test func operationHashIgnoresSemanticAssessmentWordingAndRecommendation() throws {
    let reference = try testReference()
    let base = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local:8080/api/status",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "First wording"
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
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .freshApproval,
            severity: .broad,
            reversibility: .difficult,
            reason: "Completely different semantic wording"
        )
    )

    #expect(base.operationHash == reworded.operationHash)
}

@Test func metadataOnlyOperationsRemainSilentWithoutSemanticAuthorization() {
    let decision = engine().evaluate(
        SecretOperationDescriptor(actionType: .vaultStatus),
        metadata: []
    )

    #expect(decision.authorizationRequirement == .none)
    #expect(decision.risk == .silent)
    #expect(decision.policyRuleID == "metadata.silent")
}

@Test func legacyReusablePolicyDecisionNormalizesToAutomaticAtTheModelBoundary() {
    let decision = PolicyDecision(
        risk: .approvalRequired,
        reasons: ["legacy payload"],
        normalizedDestination: "nas.local",
        requiredApproval: true,
        policyRuleID: "legacy",
        authorizationRequirement: .reusableApproval
    )

    #expect(decision.risk == .silent)
    #expect(decision.authorizationRequirement == .none)
    #expect(decision.requiredApproval == false)
}

@Test func freshRuleRegistriesStayBounded() {
    #expect(SSHFreshRules.all.count <= 5)
    #expect(SecretOperationPolicyEngine.HTTPFreshRules.all.count <= 5)
    #expect(SecretOperationPolicyEngine.DatabaseFreshRules.all.count <= 5)
    #expect(SecretOperationPolicyEngine.SFTPFreshRules.all.count <= 5)
}


@Test func preflightRoutesOrdinaryHardAndGrayOperationsBeforeJudge() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let policy = engine()

    let fast = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "systemctl status jellyfin",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .none,
                reversibility: .readOnly,
                reason: "Read requested service status"
            )
        ),
        metadata: metadata
    )
    #expect(fast.route == .fast)

    let gray = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "rm -rf /share/photos",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "Deliberately optimistic main-Agent assessment"
            )
        ),
        metadata: metadata
    )
    #expect(gray.route == .gray)
    #expect(gray.blastRadius == .unknown)

    let hard = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "zpool destroy tank",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .minor,
                reversibility: .easy,
                reason: "Deliberately optimistic main-Agent assessment"
            )
        ),
        metadata: metadata
    )
    #expect(hard.route == .hard)
    #expect(hard.blastRadius == .systemic)
}

@Test func grayDeletionRequiresVerifiedIndependentJudgeReview() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    func descriptor(
        source: AgentRiskAssessment.Source,
        recommendation: AgentRiskAssessment.ExecutionRecommendation = .automatic
    ) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "rm -rf /share/task-owned-temp",
            agentAssessment: semanticAssessment(
                source: source,
                recommendation: recommendation,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "Delete one task-owned temporary directory"
            )
        )
    }
    #expect(engine().evaluate(descriptor(source: .mainAgent), metadata: metadata).authorizationRequirement == .freshApprovalRequired)
    #expect(engine().evaluate(descriptor(source: .mainAgent, recommendation: .reusableApproval), metadata: metadata).authorizationRequirement == .freshApprovalRequired)
    #expect(engine().evaluate(descriptor(source: .independentJudge), metadata: metadata).authorizationRequirement == .freshApprovalRequired)
    #expect(engine().evaluateWithVerifiedIndependentJudge(descriptor(source: .independentJudge), metadata: metadata).authorizationRequirement == .none)
}

@Test func unboundDestinationRoutesAutomaticRecommendationToGray() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "other-nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Read hostname from a newly targeted machine"
        )
    )
    let preflight = engine().semanticPreflight(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )
    #expect(preflight.route == .gray)
}

@Test func plaintextExportIsAlwaysFreshApproval() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .exportPlaintext,
        secretReferences: [reference],
        protocolType: .file,
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            secretHandling: .userVisibleSensitiveData,
            reason: "Explicit plaintext export remains owner-approved"
        )
    )
    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: [], protocols: [])]
    )
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func classifierRegressionCoverageSurvivesIntentFirstRouting() {
    let ssh = SSHCommandRiskClassifier()
    let dangerous: [(String, String)] = [
        ("/usr/bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sudo /bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("env MODE=maintenance rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sh -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("sudo bash -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("find /tmp -exec rm -rf {} \\;", SSHFreshRules.filesystemDelete),
        ("xargs rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("bash -c 'reboot'", SSHFreshRules.powerControl),
        ("docker system prune", SSHFreshRules.containerDestruction),
        ("zpool destroy tank", SSHFreshRules.storageRaidDestruction),
        ("mdadm --zero-superblock /dev/md0", SSHFreshRules.storageRaidDestruction),
        ("systemctl isolate rescue.target", SSHFreshRules.powerControl)
    ]
    for (command, rule) in dangerous {
        #expect(ssh.classify(command: command).ruleID == rule, "command: \(command)")
    }

    let ordinary = [
        "bash -c 'echo hello'", "python3 -c 'print(1)'", "find /tmp -exec echo {} \\;",
        "sudo systemctl restart jellyfin", "docker ps", "docker restart web", "zpool status",
        "echo rm", "grep reboot logfile", "cat /backup/dd"
    ]
    for command in ordinary {
        #expect(ssh.classify(command: command).authorizationRequirement == .none, "command: \(command)")
    }

    let sql = DatabaseStatementClassifier()
    let expected: [(String, String)] = [
        ("WITH doomed AS (SELECT id FROM logs) DELETE FROM logs USING doomed WHERE logs.id = doomed.id", SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite),
        ("MERGE INTO inventory AS target USING incoming AS source ON target.id = source.id WHEN MATCHED THEN UPDATE SET count = source.count", SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite),
        ("CREATE USER app_user IDENTIFIED BY 'fixture'", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("ALTER ROLE app_user SET statement_timeout = 0", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("GRANT SELECT ON app TO app_user", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("DO $$ BEGIN DELETE FROM logs; END $$", SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution),
        ("PREPARE purge AS DELETE FROM logs", SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution)
    ]
    for (statement, rule) in expected {
        #expect(sql.classify(statement).ruleID == rule, "statement: \(statement)")
    }
    for statement in ["-- DELETE FROM logs\nSELECT 1", "SELECT 'DROP TABLE logs'", "/* GRANT ALL */ SELECT 1"] {
        #expect(sql.classify(statement).scopeFamily == "database.read", "statement: \(statement)")
    }
}

private func engine() -> SecretOperationPolicyEngine {
    SecretOperationPolicyEngine()
}

private func testReference() throws -> SecretReference {
    try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
}

private func policyMetadata(
    _ reference: SecretReference,
    destinations: [String],
    protocols: [String]
) -> SecretPolicyMetadata {
    SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "test credential",
        allowedDestinations: destinations,
        allowedProtocols: protocols
    )
}

private func semanticAssessment(
    source: AgentRiskAssessment.Source = .mainAgent,
    recommendation: AgentRiskAssessment.ExecutionRecommendation,
    alignment: AgentRiskAssessment.IntentAlignment = .direct,
    severity: AgentRiskAssessment.EffectSeverity = .bounded,
    reversibility: AgentRiskAssessment.Reversibility = .recoverable,
    secretHandling: AgentRiskAssessment.SecretHandling = .credentialUse,
    confidence: Double = 0.95,
    reason: String
) -> AgentRiskAssessment {
    AgentRiskAssessment(
        source: source,
        declaredRisk: {
            switch recommendation {
            case .automatic: return .silent
            case .denied: return .denied
            case .reusableApproval, .freshApproval, .uncertain: return .approvalRequired
            }
        }(),
        reason: reason,
        userGoal: "Complete the user-requested operation",
        taskContext: "Focused test context for the concrete operation",
        intendedEffect: reason,
        expectedEffect: reason,
        expectedResult: "The requested task step completes",
        intentAlignment: alignment,
        effectSeverity: severity,
        reversibility: reversibility,
        secretHandling: secretHandling,
        executionRecommendation: recommendation,
        confidence: confidence
    )
}

private func httpDescriptor(
    reference: SecretReference,
    method: String,
    url: String,
    assessment: AgentRiskAssessment
) -> SecretOperationDescriptor {
    let components = URLComponents(string: url)
    let host = components?.host ?? "qnap.local"
    let port = components?.port ?? (components?.scheme == "https" ? 443 : 80)
    let destination = "\(host):\(port)"
    let protocolType: SecretOperationProtocol = components?.scheme == "https" ? .https : .http
    return SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: destination,
        port: port,
        protocolType: protocolType,
        httpMethod: method,
        url: url,
        parameters: ["tokenRef": reference.description],
        agentAssessment: assessment
    )
}

private func databaseDescriptor(
    reference: SecretReference,
    statement: String,
    assessment: AgentRiskAssessment
) -> SecretOperationDescriptor {
    SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [reference],
        destination: "db.local:5432",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: statement,
        agentAssessment: assessment
    )
}
