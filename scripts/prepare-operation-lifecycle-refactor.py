from pathlib import Path

path = Path(__file__).with_name("apply-operation-lifecycle-refactor.py")
text = path.read_text()
old = '''text = replace_once(
    text,
    """            if commit == .needsFreshApproval {\\n                authorizationPath = try await authorizeAgentExecution(\\n""",
    """            if commit == .needsFreshApproval {\\n                await noteTrackedSecretOperationState(.awaitingApproval)\\n                authorizationPath = try await authorizeAgentExecution(\\n""",
    path,
)
'''
new = '''old_reapproval = """            if commit == .needsFreshApproval {\\n                authorizationPath = try await authorizeAgentExecution(\\n"""
new_reapproval = """            if commit == .needsFreshApproval {\\n                await noteTrackedSecretOperationState(.awaitingApproval)\\n                authorizationPath = try await authorizeAgentExecution(\\n"""
reapproval_count = text.count(old_reapproval)
if reapproval_count != 2:
    raise RuntimeError(f"VaultAppServices.swift: expected two reapproval anchors, found {reapproval_count}")
text = text.replace(old_reapproval, new_reapproval)
'''
if text.count(old) != 1:
    raise RuntimeError("patch-script reapproval block not found exactly once")
text = text.replace(old, new, 1)

anchor = '# Wire-model round trips.\n'
budget_trim = '''# Keep the lifecycle extraction budget-negative by compressing legacy comments
# whose invariants are already expressed by the surrounding generation checks.
path = "Sources/VaultService/VaultAppServices.swift"
text = read(path)
text = replace_once(
    text,
    """        // Policy metadata is intentionally read and evaluated again after\\n        // approval (or an execution-window hit). The actor can be reentrant\\n        // while LocalAuthentication is suspended, so a previously approved\\n        // decision must never be reused after a binding or policy mutation.\\n""",
    """        // Re-read policy after approval because actor reentrancy may change bindings.\\n""",
    path,
)
text = replace_once(
    text,
    """        // A re-evaluation may promote a previously reusable operation to a\\n        // fresh-approval requirement while the first approval was suspended.\\n        // Do not let the original scope commit a reusable lease in that case:\\n        // discard the in-flight/active scoped authorization, obtain the\\n        // exact one-shot decision, and re-read policy once more before key\\n        // resolution or execution.\\n""",
    """        // A stricter re-evaluation discards reusable scope before fresh approval.\\n""",
    path,
)
write(path, text)

'''
if text.count(anchor) != 1:
    raise RuntimeError("wire-model anchor not found exactly once")
text = text.replace(anchor, budget_trim + anchor, 1)
path.write_text(text)
