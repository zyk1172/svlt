import Foundation
import VaultCore

/// A conservative cross-dialect lexical classification for database
/// statements.
///
/// This is deliberately not a SQL firewall or an executor. It supplies a
/// small effect signal to the policy engine. Quoted
/// literals, quoted identifiers, comments, PostgreSQL dollar-quoted bodies,
/// nested parentheses, and CTEs are handled so that dangerous keywords cannot
/// be hidden in a wrapper or accidentally read from a string. Dialect-specific
/// constructs that can change server semantics are handled conservatively so a
/// classifier/server parse mismatch cannot grant an automatic decision.
/// Anything that cannot be classified with this small grammar takes the
/// GRAY/fresh path instead of being granted automatic execution.
struct DatabaseStatementClassification: Equatable, Sendable {
    let requirement: AuthorizationRequirement
    let ruleID: String
    let reason: String
    let scopeFamily: String
}

struct DatabaseStatementClassifier: Sendable {
    private static let defaultMaximumLength = 65_536

    private let maximumLength: Int

    init(maximumLength: Int = DatabaseStatementClassifier.defaultMaximumLength) {
        self.maximumLength = max(1, maximumLength)
    }

    func classify(_ query: String) -> DatabaseStatementClassification {
        guard query.utf8.count <= maximumLength,
              let statements = tokenize(query),
              !statements.isEmpty else {
            return unknownClassification()
        }

        var ordinaryFamilies = Set<String>()
        var sawOrdinary = false
        var freshClassification: DatabaseStatementClassification?

        for statement in statements {
            switch classify(statement) {
            case .read:
                break
            case let .ordinary(family):
                sawOrdinary = true
                ordinaryFamilies.insert(family)
            case let .fresh(classification):
                if freshClassification == nil || classificationPriority(classification) > classificationPriority(freshClassification!) {
                    freshClassification = classification
                }
            case .unknown:
                return unknownClassification()
            }
        }

        if let freshClassification {
            return freshClassification
        }

        if sawOrdinary {
            let family = ordinaryFamilies.sorted().joined(separator: "+")
            return DatabaseStatementClassification(
                requirement: .none,
                ruleID: "database.ordinary.automatic",
                reason: "数据库语句属于普通操作（\(family)）；实际效果明确且任务对齐时无需额外认证",
                scopeFamily: "database.ordinary.\(family)"
            )
        }

        return DatabaseStatementClassification(
            requirement: .none,
            ruleID: "database.read-only.automatic",
            reason: "数据库语句被识别为只读操作；Secret 仅用于认证，不制造首次审批门槛",
            scopeFamily: "database.read"
        )
    }

    private enum StatementResult {
        case read
        case ordinary(String)
        case fresh(DatabaseStatementClassification)
        case unknown
    }

    private enum TokenKind {
        case word(String)
        case quotedIdentifier
        case stringLiteral
        case punctuation(UInt8)
        case other
    }

    private struct Token {
        let kind: TokenKind
        /// The parenthesis depth before this token. It is used to locate the
        /// real statement after a WITH/CTE prefix.
        let depth: Int
    }

    private func classify(_ tokens: [Token]) -> StatementResult {
        let words = tokens.compactMap { token -> String? in
            guard case let .word(word) = token.kind else { return nil }
            return word
        }
        guard let firstToken = tokens.first,
              case let .word(firstWord) = firstToken.kind else {
            return .unknown
        }

        let wordSet = Set(words)
        if containsDynamicExecution(words: words, wordSet: wordSet) {
            return .fresh(freshClassification(
                ruleID: SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution,
                reason: "数据库语句包含存储过程、动态执行或外部文件传输边界，每次都需要设备所有者重新认证",
                scopeFamily: "database.fresh.dynamic-execution"
            ))
        }
        if containsPrivilegeOrAdministration(words: words, wordSet: wordSet) {
            return .fresh(freshClassification(
                ruleID: SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin,
                reason: "数据库语句包含权限、账户或 vendor-specific 管理操作，每次都需要设备所有者重新认证",
                scopeFamily: "database.fresh.privilege-account-admin"
            ))
        }
        if containsDestructiveStructure(words: words, wordSet: wordSet) {
            return .fresh(freshClassification(
                ruleID: SecretOperationPolicyEngine.DatabaseFreshRules.destructiveStructure,
                reason: "数据库语句包含删除对象、清空数据或破坏性结构变更，每次都需要设备所有者重新认证",
                scopeFamily: "database.fresh.destructive-structure"
            ))
        }
        if containsDestructiveWrite(words: words, wordSet: wordSet) {
            return .fresh(freshClassification(
                ruleID: SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite,
                reason: "数据库语句可能造成无界数据变更或持有全局锁；具体效果未能证明为普通、可恢复 CRUD，进入 GRAY/一次性设备所有者认证路径",
                scopeFamily: "database.fresh.destructive-write"
            ))
        }

        let primaryOperation = primaryOperation(in: tokens, firstWord: firstWord)
        switch primaryOperation {
        case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "VALUES", "TABLE", "PRAGMA":
            // SELECT INTO creates a server-side object or variable rather
            // than being a pure read. It remains ordinary only when the
            // destination is not an external file, which was handled above.
            if wordSet.contains("INTO") {
                return .ordinary("select-into")
            }
            if containsSequence(words, ["FOR", "UPDATE"]) {
                return .ordinary("row-lock")
            }
            return .read
        case "WITH":
            // A WITH statement without a recognizable terminal operation is
            // not safe to treat as a read. The dangerous scans above already
            // catch mutation/admin/dynamic operations at any nesting depth.
            return .unknown
        case "INSERT":
            return .ordinary("insert")
        case "UPDATE":
            return .ordinary("update")
        case "DELETE":
            return .ordinary("delete")
        case "MERGE":
            return .ordinary("merge")
        case "REPLACE":
            return .ordinary("replace")
        case "LOCK":
            return .ordinary("lock")
        case "CREATE", "ALTER", "ANALYZE", "VACUUM", "OPTIMIZE", "REINDEX", "CHECK":
            return .ordinary("schema-maintenance")
        case "SET", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "USE", "DECLARE", "FETCH", "CLOSE", "END":
            return .ordinary("session")
        default:
            return .unknown
        }
    }

    private func primaryOperation(in tokens: [Token], firstWord: String) -> String? {
        guard firstWord == "WITH" else { return firstWord }

        let knownOperations: Set<String> = [
            "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "VALUES", "TABLE", "PRAGMA",
            "INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "ALTER", "DROP", "TRUNCATE",
            "SET", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "USE",
            "ANALYZE", "VACUUM", "OPTIMIZE", "REINDEX", "CHECK", "DECLARE", "FETCH", "CLOSE", "END"
        ]

        for token in tokens.dropFirst() where token.depth == 0 {
            guard case let .word(word) = token.kind else { continue }
            if word == "RECURSIVE" { continue }
            if knownOperations.contains(word) {
                return word
            }
        }
        return nil
    }

    private func containsDynamicExecution(words: [String], wordSet: Set<String>) -> Bool {
        if !wordSet.isDisjoint(with: ["CALL", "EXEC", "EXECUTE", "PREPARE", "DEALLOCATE", "COPY", "LOAD", "UNLOAD", "OUTFILE", "DUMPFILE"]) {
            return true
        }
        // PostgreSQL's `INSERT ... ON CONFLICT ... DO UPDATE` is an ordinary
        // upsert. The `DO` token in that grammar must not be confused with a
        // standalone procedural `DO` block.
        if wordSet.contains("DO") {
            let isUpsert = wordSet.contains("INSERT")
                && containsSequence(words, ["ON", "CONFLICT"])
                && containsSequence(words, ["DO", "UPDATE"])
            if !isUpsert {
                return true
            }
        }

        let createsProgrammableObject = wordSet.contains("CREATE")
            && !wordSet.isDisjoint(with: ["FUNCTION", "PROCEDURE", "TRIGGER", "EVENT"])
        let altersProgrammableObject = wordSet.contains("ALTER")
            && !wordSet.isDisjoint(with: ["FUNCTION", "PROCEDURE", "TRIGGER", "EVENT"])
        return createsProgrammableObject || altersProgrammableObject
    }

    private func containsPrivilegeOrAdministration(words: [String], wordSet: Set<String>) -> Bool {
        if !wordSet.isDisjoint(with: ["GRANT", "REVOKE", "INSTALL", "UNINSTALL", "SHUTDOWN", "KILL"]) {
            return true
        }

        // SET has materially different privilege boundaries across MySQL and
        // PostgreSQL. Only ordinary per-session configuration is reusable.
        // Anything that changes global/persisted configuration, credentials,
        // roles, or effective authorization identity must take a fresh owner
        // approval. Looking at words instead of punctuation also catches
        // MySQL forms such as SET @@PERSIST_ONLY.max_connections = 200.
        if containsSequence(words, ["SET", "GLOBAL"])
            || containsSequence(words, ["SET", "PERSIST"])
            || containsSequence(words, ["SET", "PERSIST_ONLY"])
            || containsSequence(words, ["SET", "ROLE"])
            || containsSequence(words, ["SET", "DEFAULT", "ROLE"])
            || containsSequence(words, ["SET", "LOCAL", "ROLE"])
            || containsSequence(words, ["SET", "SESSION", "ROLE"])
            || containsSequence(words, ["SET", "PASSWORD"])
            || containsSequence(words, ["SET", "SESSION", "AUTHORIZATION"])
            || containsSequence(words, ["ALTER", "SYSTEM"])
            || containsSequence(words, ["RESET", "MASTER"])
            || containsSequence(words, ["RESET", "PERSIST"])
        {
            return true
        }

        let accountObjects: Set<String> = [
            "USER", "ROLE", "LOGIN", "ACCOUNT", "DATABASE", "SCHEMA", "TABLESPACE",
            "SERVER", "SYSTEM", "INSTANCE", "EXTENSION", "PLUGIN"
        ]
        let administrationVerbPresent = !wordSet.isDisjoint(with: ["CREATE", "DROP", "ALTER", "RENAME"])
        return administrationVerbPresent && !wordSet.isDisjoint(with: accountObjects)
    }

    private func containsDestructiveStructure(words: [String], wordSet: Set<String>) -> Bool {
        if wordSet.contains("TRUNCATE") || wordSet.contains("DROP") {
            return true
        }
        return wordSet.contains("ALTER") && wordSet.contains("DROP")
    }

    private func containsDestructiveWrite(words: [String], wordSet: Set<String>) -> Bool {
        // Ordinary CRUD is not an approval class. A bounded predicate or
        // limit gives the semantic layer a concrete, recoverable effect to
        // assess. Only an unbounded mutation remains a local gray signal;
        // the judge may still downgrade it when the supplied task context
        // proves a bounded server-side scope.
        // `INSERT ... ON CONFLICT/ DUPLICATE KEY UPDATE` contains the word
        // UPDATE as part of its upsert clause, but its primary effect is an
        // ordinary insert/upsert. Do not mistake that grammar detail for an
        // unbounded standalone UPDATE. A blanket INSERT early return would
        // be unsafe because a data-modifying CTE can contain INSERT and a
        // destructive terminal DELETE/MERGE in the same statement.
        let isInsert = wordSet.contains("INSERT")
        let isUpsert = isInsert && (
            (containsSequence(words, ["ON", "CONFLICT"])
                && containsSequence(words, ["DO", "UPDATE"]))
                || containsSequence(words, ["ON", "DUPLICATE", "KEY", "UPDATE"])
        )
        if wordSet.contains("SELECT"),
           containsSequence(words, ["FOR", "UPDATE"]),
           !wordSet.contains("DELETE"),
           !wordSet.contains("MERGE")
        {
            return false
        }

        for mutation in ["DELETE", "UPDATE", "MERGE"] where wordSet.contains(mutation) {
            if mutation == "UPDATE", isUpsert {
                continue
            }
            if mutation == "DELETE", wordSet.contains("USING") {
                return true
            }
            if !wordSet.contains("WHERE") && !wordSet.contains("LIMIT") {
                return true
            }
        }

        // `LOCK TABLE` can block unrelated workloads. Row-level `FOR UPDATE`
        // and common upsert clauses are ordinary transaction effects and do
        // not become approval requirements merely because UPDATE is present.
        if wordSet.contains("LOCK") && !containsSequence(words, ["FOR", "UPDATE"]) {
            return true
        }
        return false
    }

    private func containsSequence(_ words: [String], _ sequence: [String]) -> Bool {
        guard sequence.count <= words.count else { return false }
        for start in 0...(words.count - sequence.count) {
            if Array(words[start..<(start + sequence.count)]) == sequence {
                return true
            }
        }
        return false
    }

    private func freshClassification(
        ruleID: String,
        reason: String,
        scopeFamily: String
    ) -> DatabaseStatementClassification {
        DatabaseStatementClassification(
            requirement: .freshApprovalRequired,
            ruleID: ruleID,
            reason: reason,
            scopeFamily: scopeFamily
        )
    }

    private func unknownClassification() -> DatabaseStatementClassification {
        DatabaseStatementClassification(
            requirement: .freshApprovalRequired,
            ruleID: SecretOperationPolicyEngine.DatabaseFreshRules.unknown,
            reason: "数据库语句无法被本地分类器可靠识别，进入 GRAY/一次性设备所有者认证路径；这不是自动拒绝，也不会自动执行",
            scopeFamily: "database.fresh.unknown"
        )
    }

    private func classificationPriority(_ classification: DatabaseStatementClassification) -> Int {
        switch classification.ruleID {
        case SecretOperationPolicyEngine.DatabaseFreshRules.unknown:
            return 0
        case SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite:
            return 1
        case SecretOperationPolicyEngine.DatabaseFreshRules.destructiveStructure:
            return 2
        case SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin:
            return 3
        case SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution:
            return 4
        default:
            return 0
        }
    }

    private func tokenize(_ query: String) -> [[Token]]? {
        let bytes = Array(query.utf8)
        var statements: [[Token]] = []
        var current: [Token] = []
        var index = 0
        var depth = 0

        func append(_ kind: TokenKind) {
            current.append(Token(kind: kind, depth: depth))
        }

        while index < bytes.count {
            let byte = bytes[index]

            if byte == 0 || (byte < 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D) {
                return nil
            }
            if isWhitespace(byte) {
                index += 1
                continue
            }

            // PostgreSQL accepts `--comment` without whitespace, while MySQL
            // only recognizes `--` as a comment when it is followed by
            // whitespace/control. Since the classifier is shared by both
            // engines, use the stricter MySQL rule. PostgreSQL no-whitespace
            // comments are then parsed conservatively rather than allowing a
            // MySQL expression such as `1--1` to hide a following statement.
            if byte == 0x2D,
               peek(bytes, index + 1) == 0x2D,
               isDashDashCommentStart(bytes, from: index) {
                index += 2
                while index < bytes.count, bytes[index] != 0x0A {
                    index += 1
                }
                continue
            }

            // `#` is a MySQL line-comment marker but is also part of valid
            // PostgreSQL JSON operators (`#>` / `#>>`). Treat it as a comment
            // only in unambiguous comment positions; otherwise keep it as an
            // ordinary token so PostgreSQL expressions remain visible to the
            // rest of the statement classifier.
            if byte == 0x23, isHashCommentStart(bytes, from: index) {
                index += 1
                while index < bytes.count, bytes[index] != 0x0A {
                    index += 1
                }
                continue
            }

            if byte == 0x2F, peek(bytes, index + 1) == 0x2A {
                // MySQL/MariaDB executable comments (`/*! ... */`, `/*M! ... */`)
                // are not comments from the server's perspective. Do not try
                // to emulate version-gated execution here: force the whole
                // query onto the conservative fresh/unknown path instead.
                guard !isExecutableBlockCommentStart(bytes, from: index),
                      let next = endOfBlockComment(bytes, from: index) else {
                    return nil
                }
                index = next
                continue
            }

            if byte == 0x27 {
                guard let next = endOfQuoted(bytes, from: index, quote: byte) else { return nil }
                append(.stringLiteral)
                index = next
                continue
            }
            if byte == 0x22 || byte == 0x60 || byte == 0x5B {
                let closingQuote: UInt8 = byte == 0x5B ? 0x5D : byte
                guard let next = endOfQuoted(bytes, from: index, quote: closingQuote) else { return nil }
                append(.quotedIdentifier)
                index = next
                continue
            }
            if byte == 0x24, isDollarQuoteStart(bytes, from: index) {
                guard let next = endOfDollarQuoted(bytes, from: index) else { return nil }
                append(.stringLiteral)
                index = next
                continue
            }

            if isWordStart(byte) {
                let start = index
                index += 1
                while index < bytes.count, isWordContinuation(bytes[index]) {
                    index += 1
                }
                let word = String(decoding: bytes[start..<index], as: UTF8.self).uppercased()
                append(.word(word))
                continue
            }

            if byte == 0x28 {
                append(.punctuation(byte))
                depth += 1
                index += 1
                continue
            }
            if byte == 0x29 {
                guard depth > 0 else { return nil }
                append(.punctuation(byte))
                depth -= 1
                index += 1
                continue
            }
            if byte == 0x3B, depth == 0 {
                if !current.isEmpty {
                    statements.append(current)
                    current = []
                }
                index += 1
                continue
            }

            append(byte == 0x2C || byte == 0x2E || byte == 0x3F
                ? .punctuation(byte)
                : .other)
            index += 1
        }

        guard depth == 0 else { return nil }
        if !current.isEmpty {
            statements.append(current)
        }
        return statements
    }

    private func endOfQuoted(_ bytes: [UInt8], from start: Int, quote: UInt8) -> Int? {
        var index = start + 1
        while index < bytes.count {
            if bytes[index] == 0 {
                return nil
            }
            if bytes[index] == quote {
                if peek(bytes, index + 1) == quote {
                    index += 2
                } else {
                    return index + 1
                }
            } else if bytes[index] == 0x5C, index + 1 < bytes.count {
                // MySQL strings and some PostgreSQL compatibility modes use
                // backslash escapes. Skipping the escaped byte is safe for
                // classification and prevents a fake keyword from leaking
                // out of the literal.
                index += 2
            } else {
                index += 1
            }
        }
        return nil
    }

    private func endOfBlockComment(_ bytes: [UInt8], from start: Int) -> Int? {
        var index = start + 2
        var nesting = 1
        while index + 1 < bytes.count {
            if bytes[index] == 0x2F, bytes[index + 1] == 0x2A {
                nesting += 1
                index += 2
            } else if bytes[index] == 0x2A, bytes[index + 1] == 0x2F {
                nesting -= 1
                index += 2
                if nesting == 0 { return index }
            } else {
                index += 1
            }
        }
        return nil
    }

    private func isExecutableBlockCommentStart(_ bytes: [UInt8], from start: Int) -> Bool {
        guard peek(bytes, start) == 0x2F, peek(bytes, start + 1) == 0x2A else {
            return false
        }
        if peek(bytes, start + 2) == 0x21 {
            return true
        }
        guard let marker = peek(bytes, start + 2), marker == 0x4D || marker == 0x6D else {
            return false
        }
        return peek(bytes, start + 3) == 0x21
    }

    private func isDashDashCommentStart(_ bytes: [UInt8], from start: Int) -> Bool {
        guard peek(bytes, start) == 0x2D, peek(bytes, start + 1) == 0x2D else {
            return false
        }
        guard let following = peek(bytes, start + 2) else {
            return true
        }
        return isWhitespace(following)
    }

    private func isHashCommentStart(_ bytes: [UInt8], from start: Int) -> Bool {
        guard peek(bytes, start) == 0x23 else { return false }

        // A # at the beginning of a physical line (allowing indentation) is
        // unambiguously a MySQL-style comment for the SQL shapes SVLT accepts.
        var cursor = start
        while cursor > 0 {
            let previous = bytes[cursor - 1]
            if previous == 0x0A || previous == 0x0D {
                return true
            }
            if previous == 0x20 || previous == 0x09 {
                cursor -= 1
                continue
            }
            break
        }
        if cursor == 0 {
            return true
        }

        // Inline MySQL comments normally use whitespace after #. This excludes
        // PostgreSQL's #> and #>> JSON operators from comment handling.
        guard let following = peek(bytes, start + 1) else {
            return true
        }
        return isWhitespace(following)
    }

    private func endOfDollarQuoted(_ bytes: [UInt8], from start: Int) -> Int? {
        var delimiterEnd = start + 1
        if peek(bytes, delimiterEnd) != 0x24 {
            guard delimiterEnd < bytes.count, isDollarTagStart(bytes[delimiterEnd]) else {
                return nil
            }
            delimiterEnd += 1
            while delimiterEnd < bytes.count, isDollarTagContinuation(bytes[delimiterEnd]) {
                delimiterEnd += 1
            }
            guard peek(bytes, delimiterEnd) == 0x24 else { return nil }
        }

        let delimiter = Array(bytes[start...delimiterEnd])
        var search = delimiterEnd + 1
        while search + delimiter.count <= bytes.count {
            if Array(bytes[search..<(search + delimiter.count)]) == delimiter {
                return search + delimiter.count
            }
            search += 1
        }
        return nil
    }

    private func isDollarQuoteStart(_ bytes: [UInt8], from start: Int) -> Bool {
        guard peek(bytes, start) == 0x24 else { return false }
        if peek(bytes, start + 1) == 0x24 {
            return true
        }
        guard let tagStart = peek(bytes, start + 1), isDollarTagStart(tagStart) else {
            return false
        }

        var delimiterEnd = start + 2
        while delimiterEnd < bytes.count, isDollarTagContinuation(bytes[delimiterEnd]) {
            delimiterEnd += 1
        }
        return peek(bytes, delimiterEnd) == 0x24
    }

    private func peek(_ bytes: [UInt8], _ index: Int) -> UInt8? {
        guard bytes.indices.contains(index) else { return nil }
        return bytes[index]
    }

    private func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x09 || byte == 0x0A || byte == 0x0D || byte == 0x20
    }

    private func isWordStart(_ byte: UInt8) -> Bool {
        (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte) || byte == 0x5F
    }

    private func isWordContinuation(_ byte: UInt8) -> Bool {
        isWordStart(byte) || (0x30...0x39).contains(byte) || byte == 0x24
    }

    private func isDollarTagStart(_ byte: UInt8) -> Bool {
        isWordStart(byte)
    }

    private func isDollarTagContinuation(_ byte: UInt8) -> Bool {
        isWordStart(byte) || (0x30...0x39).contains(byte)
    }
}
