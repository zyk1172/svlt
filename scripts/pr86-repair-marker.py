from pathlib import Path

path = Path("scripts/pr86-complete.py")
text = path.read_text()
old = """response_marker = '  z.object({ type: z.literal(\"secretOperation\"), output: SecretOperationOutput }).strict(),'
if response_marker not in text:
    raise SystemExit(\"protocol secretOperation response marker missing\")
text = text.replace(response_marker, response_marker + '\\n  z.object({ type: z.literal(\"secretOperationPreflight\"), result: SecretOperationPreflight }).strict(),', 1)"""
new = """response_marker = '''  z
    .object({
      type: z.literal(\"secretOperation\"),
      output: SecretOperationOutput
    })
    .strict(),'''
if response_marker not in text:
    raise SystemExit(\"protocol secretOperation response marker missing\")
text = text.replace(response_marker, response_marker + '\\n  z.object({ type: z.literal(\"secretOperationPreflight\"), result: SecretOperationPreflight }).strict(),', 1)"""
if old not in text:
    raise SystemExit("repair target not found")
path.write_text(text.replace(old, new, 1))
