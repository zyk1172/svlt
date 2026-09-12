import Foundation
import Testing
import VaultCore
@testable import AgentSecretVaultApp
@testable import VaultAuthorization

@Test func approvalTicketBindsExactOperationAndIsOneShot() async throws {
    let descriptor = operation(command: "docker ps", destination: "nas.local")
    let store = ApprovalTicketStore(lifetime: 90)
    let ticket = await store.issue(
        for: descriptor,
        now: Date(timeIntervalSinceReferenceDate: 10)
    )

    #expect(await store.consume(
        ticket,
        for: descriptor,
        now: Date(timeIntervalSinceReferenceDate: 20)
    ))
    #expect(!(await store.consume(
        ticket,
        for: descriptor,
        now: Date(timeIntervalSinceReferenceDate: 21)
    )))
}

@Test func approvalTicketRejectsChangedCommandOrDestination() async throws {
    let descriptor = operation(command: "docker ps", destination: "nas.local")
    let changedCommand = operation(command: "docker rm app", destination: "nas.local")
    let changedDestination = operation(command: "docker ps", destination: "10.0.0.2")
    let store = ApprovalTicketStore(lifetime: 90)

    let commandTicket = await store.issue(for: descriptor, now: Date(timeIntervalSinceReferenceDate: 100))
    #expect(!(await store.consume(
        commandTicket,
        for: changedCommand,
        now: Date(timeIntervalSinceReferenceDate: 101)
    )))

    let destinationTicket = await store.issue(for: descriptor, now: Date(timeIntervalSinceReferenceDate: 100))
    #expect(!(await store.consume(
        destinationTicket,
        for: changedDestination,
        now: Date(timeIntervalSinceReferenceDate: 101)
    )))
}

@Test func approvalTicketExpires() async throws {
    let descriptor = operation(command: "docker ps", destination: "nas.local")
    let store = ApprovalTicketStore(lifetime: 5)
    let ticket = await store.issue(for: descriptor, now: Date(timeIntervalSinceReferenceDate: 200))

    #expect(!(await store.consume(
        ticket,
        for: descriptor,
        now: Date(timeIntervalSinceReferenceDate: 205)
    )))
    #expect(await store.activeTicketCount(now: Date(timeIntervalSinceReferenceDate: 205)) == 0)
}

@Test func approvalNotificationGateAllowsOnlyOneDeliveryPerPresentedWindow() {
    var gate = ApprovalNotificationOnceGate()
    let firstWindow = UUID()
    let secondWindow = UUID()

    #expect(gate.shouldNotify(approvalID: firstWindow))
    #expect(!gate.shouldNotify(approvalID: firstWindow))
    #expect(gate.shouldNotify(approvalID: secondWindow))
}

@Test func approvalNotificationCopyIsFixedAndContainsNoOperationDetails() {
    #expect(ApprovalNotificationCopy.title == "SVLT 需要审批")
    #expect(ApprovalNotificationCopy.body == "有一项操作正在等待你的确认")
}

private func operation(command: String, destination: String) -> SecretOperationDescriptor {
    let reference = try! SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    return SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: destination,
        port: 22,
        protocolType: .ssh,
        command: command,
        parameters: ["passwordRef": reference.description]
    )
}
