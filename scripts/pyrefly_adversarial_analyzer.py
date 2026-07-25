import json
import subprocess
import sys
from pathlib import Path

def run_pyrefly():
    pyrefly_bin = Path(".venv/Scripts/pyrefly.exe")
    cmd = [str(pyrefly_bin) if pyrefly_bin.exists() else "pyrefly", "check", "--output-format", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    
    raw = res.stdout.strip()
    if not raw and res.stderr:
        # Find JSON block in output
        raw = res.stderr.strip()
        
    start_idx = raw.find("{")
    end_idx = raw.rfind("}")
    if start_idx != -1 and end_idx != -1:
        json_str = raw[start_idx:end_idx+1]
        try:
            return json.loads(json_str)
        except Exception as e:
            print(f"Error parsing JSON: {e}", file=sys.stderr)
            return None
    return None

def analyze(report):
    if not report or "errors" not in report:
        print("No diagnostics found.")
        return

    diagnostics = report["errors"]
    by_file = {}
    by_rule = {}

    for d in diagnostics:
        path = d.get("path", "unknown")
        rule = d.get("name", "general")
        
        by_file.setdefault(path, []).append(d)
        by_rule.setdefault(rule, []).append(d)

    print(f"=== PYREFLY ADVERSARIAL ANALYSIS SUMMARY ===")
    print(f"Total Errors/Warnings: {len(diagnostics)}")
    print(f"Affected Files: {len(by_file)}")
    print(f"Unique Error Rules: {len(by_rule)}\n")

    print("--- Top Error Rules ---")
    for rule, items in sorted(by_rule.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  [{rule}]: {len(items)} occurrences")

    print("\n--- Files Needing Audit ---")
    for path, items in sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {path}: {len(items)} issues")

def generate_adversarial_prompt(report, target_path=None):
    if not report or "errors" not in report:
        return
    
    items = report["errors"]
    if target_path:
        items = [d for d in items if d.get("path") == target_path]

    print(f"\n=== ADVERSARIAL AUDIT PROMPT FOR {target_path or 'ALL FILES'} ===")
    print("Role: Adversarial Code Auditor & Type Safety Specialist")
    print("Task: Analyze the following Pyrefly diagnostics with a hostile lens.")
    print("Rules:")
    print("  1. Identify true runtime bugs vs type annotation gaps.")
    print("  2. Do NOT mask errors with `# pyrefly: ignore` unless third-party untyped limitation.")
    print("  3. For unhandled None/null subscripting or attribute access, craft regression test cases.")
    print("  4. Provide exact fix instructions.\n")

    for i, d in enumerate(items[:20], 1):
        print(f"Issue #{i}:")
        print(f"  File: {d.get('path')}:{d.get('line')}:{d.get('column')}")
        print(f"  Rule: {d.get('name')}")
        print(f"  Description: {d.get('concise_description')}")
        print(f"  Adversarial Question: What inputs/conditions trigger runtime crash at this line?\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    report = run_pyrefly()
    analyze(report)
    if target or "--prompt" in sys.argv:
        generate_adversarial_prompt(report, target)
