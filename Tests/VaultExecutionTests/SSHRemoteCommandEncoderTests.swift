import Foundation
import Testing
import VaultCore
@testable import VaultExecution

// The encoder is a transport component, not an approval layer. Raw commands
// pass through byte-for-byte as one ssh remote-command argv element; only
// NUL, emptiness, and the size ceiling are technical failures.

@Test func structuredSSHArgumentsAreQuotedIndependentlyAtRemoteShellBoundary() throws {
    let payloads = [
        "a b",
        "a'b",
        "$(id)",
        "; rm -rf /",
        "| cat",
        "> file",
        "`id`",
        "$HOME",
        "通道参数"
    ]

    for payload in payloads {
        let command = SSHCommandSpec(executable: "printf", arguments: [payload])
        let encoded = try SSHRemoteCommandEncoder.encode(command)

        #expect(encoded == "'printf' \(SSHRemoteCommandEncoder.quote(payload))")
    }
}

@Test func structuredSSHNewlineIsQuotedAsALiteralArgument() throws {
    let command = SSHCommandSpec(executable: "printf", arguments: ["line1\nline2"])

    #expect(try SSHRemoteCommandEncoder.encode(command) == "'printf' 'line1\nline2'")
}

@Test func structuredSSHNulIsRejected() {
    let command = SSHCommandSpec(executable: "printf", arguments: ["line1\0line2"])

    do {
        _ = try SSHRemoteCommandEncoder.encode(command)
        Issue.record("NUL must not cross the process argument boundary.")
    } catch SSHCommandBatchValidationError.argumentContainsControlCharacter {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func shellExecutablesAreEncodedLikeAnyOtherExecutable() throws {
    // Interpreter choice belongs to the caller and the device owner, not the
    // encoder: `bash -c ...` and `python3 -c ...` are ordinary argv.
    for executable in ["sh", "/bin/bash", "zsh", "python3", "perl"] {
        let encoded = try SSHRemoteCommandEncoder.encode(
            SSHCommandSpec(executable: executable, arguments: ["-c", "id"])
        )
        #expect(encoded.hasPrefix("\(SSHRemoteCommandEncoder.quote(executable)) '-c'"))
    }
}

@Test func rawCommandPassesThroughByteForByte() throws {
    let commands = [
        "echo hello",
        "echo \"hello world\"",
        "cd /tmp && pwd",
        "cat /tmp/a | head -n 1",
        "echo hello > /tmp/file",
        "echo hello >> /tmp/file",
        "VAR=value command",
        "ls /tmp/*",
        "echo $HOME",
        "echo $(hostname)",
        "bash -c 'echo hello'",
        "python3 -c 'print(\"hello\")'",
        "find /tmp -exec echo {} \\;",
        "sudo systemctl restart example",
        "unknown-nas-command foo bar",
        "printf 'a\nb\n' | head -n 1"
    ]

    for command in commands {
        #expect(try SSHRemoteCommandEncoder.rawRemoteCommand(command) == command)
    }
}

@Test func rawMultilineConstructsPassThroughUnchanged() throws {
    let multiline = [
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
        """,
        "line1\nline2\nline3"
    ]

    for command in multiline {
        #expect(try SSHRemoteCommandEncoder.rawRemoteCommand(command) == command)
    }
}

@Test func rawCommandTechnicalLimits() throws {
    do {
        _ = try SSHRemoteCommandEncoder.rawRemoteCommand("")
        Issue.record("Empty command must be rejected.")
    } catch SSHRemoteCommandEncodingError.invalidCommand {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    do {
        _ = try SSHRemoteCommandEncoder.rawRemoteCommand("echo \u{0}hi")
        Issue.record("NUL must be rejected.")
    } catch SSHRemoteCommandEncodingError.invalidCommand {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    do {
        _ = try SSHRemoteCommandEncoder.rawRemoteCommand(String(repeating: "a", count: 65_537))
        Issue.record("Oversized command must be rejected.")
    } catch SSHRemoteCommandEncodingError.commandTooLong {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    // The ceiling itself is accepted.
    #expect(try SSHRemoteCommandEncoder.rawRemoteCommand(String(repeating: "a", count: 65_536)) == String(repeating: "a", count: 65_536))
}

@Test func executorExpectInputPreservesTheRawCommandAsOneField() {
    let command = """
    if [ -f /tmp/a ]; then
      echo "$HOME"
    fi
    """
    let input = String(decoding: LocalSecretOperationExecutor.expectSSHInput(
        host: "nas.local",
        port: 22,
        command: command,
        username: "admin",
        password: "secret-value",
        timeoutSeconds: 30
    ), as: UTF8.self)

    // Fields are hex-encoded lines, so newlines in the command survive the
    // frame boundary and the wrapper can hand ssh one exact argument.
    // The host-key trust path contributes a dedicated known-hosts field.
    let lines = input.split(separator: "\n").map(String.init)
    #expect(lines.count == 9)
    let decodedCommand = String(decoding: Array(hexString: lines[2]), as: UTF8.self)
    #expect(decodedCommand == command)
}

private extension Array where Element == UInt8 {
    init(hexString: String) {
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2, limitedBy: hexString.endIndex) ?? hexString.endIndex
            bytes.append(UInt8(hexString[index..<next], radix: 16) ?? 0)
            index = next
        }
        self = bytes
    }
}
