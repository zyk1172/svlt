import Foundation
import VaultCore
import VaultIPC

/// Owns the pure, non-secret planning rules shared by reveal, copy,
/// and export operations. It validates opaque secret references and
/// placeholder structure, but never resolves metadata, plaintext, or keys.
struct CatalogPlaintextOperationPlanner: Sendable {
    func descriptor(
        action: SecretOperationAction,
        references: [String],
        context: RevealContext,
        effects: [String]
    ) throws -> SecretOperationDescriptor {
        let parsedReferences = try validatedReferences(references, context: context)
            .map { try SecretReference($0) }
        return SecretOperationDescriptor(
            actionType: action,
            secretReferences: parsedReferences,
            destination: context.destination,
            requestedEffects: effects,
            agentAssessment: context.agentAssessment
        )
    }

    func validatedReferences(
        _ references: [String],
        context: RevealContext
    ) throws -> [String] {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let validated: [String]
        do {
            validated = try references.map { try SecretReference($0).description }
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }
        guard Set(validated).count == validated.count else {
            throw VaultAppServicesRevealError.invalidReference
        }
        try validate(context, referenceCount: validated.count)
        return validated
    }

    func resolveTemplate(
        _ template: String,
        ranges: [ReferenceRange],
        plaintexts: [String]
    ) throws -> String {
        var replacements: [String: String] = [:]
        for range in ranges {
            guard plaintexts.indices.contains(range.index), !range.placeholder.isEmpty else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            guard replacements[range.placeholder] == nil else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            replacements[range.placeholder] = plaintexts[range.index]
        }
        return replacePlaceholders(in: template, replacements: replacements)
    }

    private func validate(_ context: RevealContext, referenceCount: Int) throws {
        guard context.ranges.count == referenceCount else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        var seenIndices: Set<Int> = []
        var seenPlaceholders: Set<String> = []
        for range in context.ranges {
            guard 0..<referenceCount ~= range.index,
                  !range.placeholder.isEmpty,
                  seenIndices.insert(range.index).inserted,
                  seenPlaceholders.insert(range.placeholder).inserted
            else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            guard countOccurrences(of: range.placeholder, in: context.template) == 1 else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
        }

        let placeholders = Array(seenPlaceholders)
        for lhsIndex in placeholders.indices {
            for rhsIndex in placeholders.indices where lhsIndex != rhsIndex {
                guard !placeholders[lhsIndex].contains(placeholders[rhsIndex]) else {
                    throw VaultAppServicesRevealError.invalidRevealContext
                }
            }
        }
    }

    private func countOccurrences(of needle: String, in haystack: String) -> Int {
        var count = 0
        var searchRange = haystack.startIndex..<haystack.endIndex
        while let range = haystack.range(of: needle, range: searchRange) {
            count += 1
            searchRange = range.upperBound..<haystack.endIndex
        }
        return count
    }

    private func replacePlaceholders(
        in template: String,
        replacements: [String: String]
    ) -> String {
        var result = ""
        var remaining = template[...]
        let placeholders = replacements.keys.sorted { lhs, rhs in
            if lhs.count == rhs.count { return lhs < rhs }
            return lhs.count > rhs.count
        }

        while !remaining.isEmpty {
            let nextMatch = placeholders.compactMap { placeholder -> (String, Range<String.Index>)? in
                guard let range = remaining.range(of: placeholder) else { return nil }
                return (placeholder, range)
            }
            .min { lhs, rhs in
                if lhs.1.lowerBound == rhs.1.lowerBound {
                    return lhs.0.count > rhs.0.count
                }
                return lhs.1.lowerBound < rhs.1.lowerBound
            }

            guard let nextMatch else {
                result.append(contentsOf: remaining)
                break
            }
            result.append(contentsOf: remaining[..<nextMatch.1.lowerBound])
            result.append(replacements[nextMatch.0] ?? "")
            remaining = remaining[nextMatch.1.upperBound...]
        }
        return result
    }
}
