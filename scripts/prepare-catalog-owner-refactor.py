from pathlib import Path

path = Path('.github/workflows/ci.yml')
text = path.read_text(encoding='utf-8')
old = '''      - name: Enforce large-file architecture budgets
        run: bash scripts/check-architecture-budgets.sh
      - name: Enforce app runtime mutation boundary
        run: bash scripts/check-runtime-mutation-boundary.sh
      - name: Check whitespace
'''
new = '''      - name: Enforce large-file architecture budgets
        run: bash scripts/check-architecture-budgets.sh
      - name: Check whitespace
      - name: Enforce app runtime mutation boundary
        run: bash scripts/check-runtime-mutation-boundary.sh
'''
if text.count(old) != 1:
    raise SystemExit('unexpected CI security-step layout')
path.write_text(text.replace(old, new, 1), encoding='utf-8')
