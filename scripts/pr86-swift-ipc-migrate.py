from pathlib import Path

path = Path("Tests/VaultIPCTests/IPCMessageTests.swift")
text = path.read_text()

# Keep one canonical operation descriptor so request round-trip coverage includes
# both the new daemon preflight request and the legacy execution request.
old_prefix = '''@Test func requestJSONRoundTripsEveryCase() throws {
    let pin = try ipcTestSSHHostKeyPin()
    let requests: [IPCRequest] = ['''
new_prefix = '''@Test func requestJSONRoundTripsEveryCase() throws {
    let pin = try ipcTestSSHHostKeyPin()
    let operationDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        requestedEffects: ["read-only"],
        parameters: ["passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS"],
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read-only diagnostic",
            intendedEffect: "read status"
        )
    )
    let requests: [IPCRequest] = ['''
if old_prefix not in text:
    raise SystemExit("request round-trip prefix marker missing")
text = text.replace(old_prefix, new_prefix, 1)

old_execute = '''        .executeSecretOperation(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
            destination: "qnap.local",
            port: 22,
            protocolType: .ssh,
            command: "hostname",
            requestedEffects: ["read-only"],
            parameters: ["passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS"],
            agentAssessment: AgentRiskAssessment(
                declaredRisk: .silent,
                reason: "read-only diagnostic",
                intendedEffect: "read status"
            )
        )),'''
new_execute = '''        .preflightSecretOperation(operationDescriptor),
        .executeSecretOperation(operationDescriptor),'''
if old_execute not in text:
    raise SystemExit("executeSecretOperation fixture marker missing")
text = text.replace(old_execute, new_execute, 1)

# Cover the new response wire case too.
response_marker = '''        .secretOperation(SecretOperationOutput(status: "COMPLETED", httpStatus: 200, contentType: "application/json", bodyPreview: "{\\"ok\\":true}")),'''
preflight_response = '''        .secretOperationPreflight(SecretOperationPreflight(
            route: .fast,
            policyRuleID: "test.fast",
            authorizationRequirement: .none,
            blastRadius: .tiny,
            reasons: ["routine bounded operation"]
        )),
''' + response_marker
if response_marker not in text:
    raise SystemExit("secretOperation response fixture marker missing")
text = text.replace(response_marker, preflight_response, 1)

# Some historical versions of this test used a hand-written pair switch for
# enum equality. If that form is present in the checked-out tree, migrate it as
# well. The current compact version uses synthesized Equatable, so this block is
# intentionally conditional.
if "switch (request, decoded)" in text and ".preflightSecretOperation" not in text[text.index("switch (request, decoded)"):]:
    switch_pos = text.index("switch (request, decoded)")
    case_pos = text.find("case", switch_pos)
    if case_pos == -1:
        raise SystemExit("request/decoded switch found without a case")
    insertion = '''            case let (.preflightSecretOperation(expected), .preflightSecretOperation(actual)):
                #expect(expected == actual)
'''
    text = text[:case_pos] + insertion + text[case_pos:]

path.write_text(text)
print("Swift IPC request/response fixtures migrated for preflight")
