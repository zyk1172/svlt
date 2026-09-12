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
path.write_text(text.replace(old, new, 1))
