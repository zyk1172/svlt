from pathlib import Path

path = Path("mcp-server/test/tools.test.ts")
text = path.read_text()
text = text.replace('  "secret_export_resolved_text"\n]);', '  "export_resolved_text_to_local_file"\n]);', 1)
old = '''        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "approvalRequired",
          reason: "Main Agent did not provide a semantic assessment",
          userGoal: "Complete the requested Secret-backed operation",
          taskContext: "No additional task context supplied",
          intendedEffect: "Perform the requested operation",
          expectedEffect: "Unknown until independently reviewed",
          expectedResult: "Complete the user's requested task",
          intentAlignment: "unclear",
          effectSeverity: "unknown",
          reversibility: "unknown",
          secretHandling: "unknown",
          executionRecommendation: "uncertain",
          confidence: 0
        }
'''
new = '''        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "silent",
          reason: "test fixture: routine user-aligned operation",
          userGoal: "Complete the requested test operation",
          taskContext: "MCP contract test fixture",
          intendedEffect: "Perform the bounded requested operation",
          expectedEffect: "Only the requested bounded target changes",
          expectedResult: "The requested operation completes",
          intentAlignment: "direct",
          effectSeverity: "minor",
          reversibility: "easy",
          secretHandling: "credentialUse",
          executionRecommendation: "automatic",
          confidence: 0.95
        }
'''
if old not in text:
    raise SystemExit("export assessment expectation marker missing")
text = text.replace(old, new, 1)
path.write_text(text)
print("PR86 export test migration completed")
