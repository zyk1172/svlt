import Testing
import VaultCore
import VaultIPC
@testable import VaultService

private let plannerReferenceA = "secret://0123456789ABCDEFGHJKMNPQRS"
private let plannerReferenceB = "secret://0123456789ABCDEFGHJKMNPQRT"

@Test func plaintextPlannerBuildsBoundDescriptor() throws {
    let planner = CatalogPlaintextOperationPlanner()
    let context = RevealContext(
        reason: "export",
        template: "user={{0}} password={{1}}",
        ranges: [
            ReferenceRange(index: 0, placeholder: "{{0}}"),
            ReferenceRange(index: 1, placeholder: "{{1}}")
        ],
        destination: "/tmp/output.txt"
    )

    let descriptor = try planner.descriptor(
        action: .exportPlaintext,
        references: [plannerReferenceA, plannerReferenceB],
        context: context,
        effects: ["write-local-file"]
    )

    #expect(descriptor.actionType == .exportPlaintext)
    #expect(descriptor.secretReferences.map(\.description) == [plannerReferenceA, plannerReferenceB])
    #expect(descriptor.destination == "/tmp/output.txt")
    #expect(descriptor.requestedEffects == ["write-local-file"])
    #expect(descriptor.agentAssessment == context.agentAssessment)
}

@Test func plaintextPlannerRejectsDuplicateReferencesAndMalformedRanges() throws {
    let planner = CatalogPlaintextOperationPlanner()
    let duplicateContext = RevealContext(
        reason: "copy",
        template: "{{0}} {{1}}",
        ranges: [
            ReferenceRange(index: 0, placeholder: "{{0}}"),
            ReferenceRange(index: 1, placeholder: "{{1}}")
        ]
    )
    #expect(throws: VaultAppServicesRevealError.invalidReference) {
        try planner.validatedReferences(
            [plannerReferenceA, plannerReferenceA],
            context: duplicateContext
        )
    }

    let repeatedPlaceholderContext = RevealContext(
        reason: "copy",
        template: "{{0}} and {{0}}",
        ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
    )
    #expect(throws: VaultAppServicesRevealError.invalidRevealContext) {
        try planner.validatedReferences(
            [plannerReferenceA],
            context: repeatedPlaceholderContext
        )
    }
}

@Test func plaintextPlannerRejectsOverlappingPlaceholderTokens() throws {
    let planner = CatalogPlaintextOperationPlanner()
    let context = RevealContext(
        reason: "copy",
        template: "A={{0}} B={{0}}x",
        ranges: [
            ReferenceRange(index: 0, placeholder: "{{0}}"),
            ReferenceRange(index: 1, placeholder: "{{0}}x")
        ]
    )
    #expect(throws: VaultAppServicesRevealError.invalidRevealContext) {
        try planner.validatedReferences(
            [plannerReferenceA, plannerReferenceB],
            context: context
        )
    }
}

@Test func plaintextPlannerTemplateReplacementDoesNotReinterpretSecretText() throws {
    let planner = CatalogPlaintextOperationPlanner()
    let text = try planner.resolveTemplate(
        "A={{0}} B={{1}}",
        ranges: [
            ReferenceRange(index: 0, placeholder: "{{0}}"),
            ReferenceRange(index: 1, placeholder: "{{1}}")
        ],
        plaintexts: ["literal {{1}}", "second-secret"]
    )
    #expect(text == "A=literal {{1}} B=second-secret")
}
