from pathlib import Path

path = Path("scripts/pr86-complete.py")
text = path.read_text()

old_marker = """response_marker = '  z.object({ type: z.literal(\"secretOperation\"), output: SecretOperationOutput }).strict(),'
if response_marker not in text:
    raise SystemExit(\"protocol secretOperation response marker missing\")
text = text.replace(response_marker, response_marker + '\\n  z.object({ type: z.literal(\"secretOperationPreflight\"), result: SecretOperationPreflight }).strict(),', 1)"""
new_marker = """response_marker = '''  z
    .object({
      type: z.literal(\"secretOperation\"),
      output: SecretOperationOutput
    })
    .strict(),'''
if response_marker not in text:
    raise SystemExit(\"protocol secretOperation response marker missing\")
text = text.replace(response_marker, response_marker + '\\n  z.object({ type: z.literal(\"secretOperationPreflight\"), result: SecretOperationPreflight }).strict(),', 1)"""
if old_marker not in text:
    raise SystemExit("protocol repair target not found")
text = text.replace(old_marker, new_marker, 1)

old_removal = '''# Remove obsolete TypeScript-only routing functions.
for function_name in ["semanticGrayReason", "looksSemanticallyOpaque"]:
    token = f"function {function_name}("
    if token in text:
        s = text.index(token)
        brace = text.index("{", s)
        depth = 0
        i = brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    while i < len(text) and text[i] in "\\r\\n":
                        i += 1
                    text = text[:s] + text[i:]
                    break
            i += 1
        else:
            raise SystemExit(f"could not remove {function_name}")
# Keep high-impact normalization only as a judge-output invariant.
if "function isClearlyHighImpact" not in text:
    raise SystemExit("isClearlyHighImpact unexpectedly missing")
write(path, text)'''
new_removal = '''# Remove all TypeScript-only routing helpers. Daemon preflight is authoritative.
routing_start = text.find("function semanticGrayReason(")
routing_end = text.find("async function judgeOperation(", routing_start)
if routing_start >= 0 and routing_end > routing_start:
    text = text[:routing_start] + text[routing_end:]
text = text.replace(
    '  if (isClearlyHighImpact(assessment)) executionRecommendation = "freshApproval";',
    '  if (assessment.executionRecommendation === "automatic" && (assessment.effectSeverity === "broad" || assessment.effectSeverity === "systemic" || assessment.reversibility === "irreversible" || assessment.secretHandling === "thirdPartyExposure" || assessment.secretHandling === "plaintextSecretExposure")) executionRecommendation = "freshApproval";',
    1,
)
write(path, text)'''
if old_removal not in text:
    raise SystemExit("routing repair target not found")
text = text.replace(old_removal, new_removal, 1)

path.write_text(text)
