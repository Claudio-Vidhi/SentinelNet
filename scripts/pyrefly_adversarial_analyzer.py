import json
import subprocess
import sys
import argparse
from pathlib import Path

STATE_FILE = Path(".pyrefly_audit_state.json")

def run_pyrefly():
    pyrefly_bin = Path(".venv/Scripts/pyrefly.exe")
    cmd = [str(pyrefly_bin) if pyrefly_bin.exists() else "pyrefly", "check", "--output-format", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    
    raw = res.stdout.strip()
    if not raw and res.stderr:
        raw = res.stderr.strip()
        
    start_idx = raw.find("{")
    end_idx = raw.rfind("}")
    if start_idx != -1 and end_idx != -1:
        json_str = raw[start_idx:end_idx+1]
        try:
            return json.loads(json_str)
        except Exception as e:
            print(f"Error parsing Pyrefly JSON: {e}", file=sys.stderr)
            return None
    return None

def load_state():
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"resolved": [], "history": {}}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def analyze_and_group(report):
    if not report or "errors" not in report:
        return {}

    by_file = {}
    for err in report["errors"]:
        path = err.get("path", "unknown")
        by_file.setdefault(path, []).append(err)

    # Sort files by issue count ascending (smallest first)
    sorted_files = dict(sorted(by_file.items(), key=lambda x: len(x[1])))
    return sorted_files

def print_summary(grouped_files, state):
    total_issues = sum(len(errs) for errs in grouped_files.values())
    resolved = set(state.get("resolved", []))
    
    print("=" * 60)
    print("      PYREFLY ADVERSARIAL AUTONOMOUS & INTERACTIVE AUDITOR")
    print("=" * 60)
    print(f"Total Current Issues  : {total_issues}")
    print(f"Files With Issues     : {len(grouped_files)}")
    print(f"Previously Resolved   : {len(resolved)} files\n")

    print("Target Workload (Smallest to Largest Files):")
    for path, errs in grouped_files.items():
        status = "[FIXED]" if path in resolved else f"[FAILED] {len(errs)} issue(s)"
        print(f"  [{len(errs):2d} issues] {path:<45} {status}")
    print("=" * 60)

def generate_file_prompt(path, errors):
    print(f"\n" + "=" * 60)
    print(f"[TARGET] ADVERSARIAL AUDIT TARGET: {path} ({len(errors)} issue(s))")
    print("=" * 60)
    print("Adversarial Instructions for Subagent:")
    print("  1. Inspect source line and verify runtime validity.")
    print("  2. Refactor type signatures or add runtime checks (NO `# pyrefly: ignore`).")
    print("  3. Run pyrefly check + tests after fix.\n")
    
    for i, err in enumerate(errors, 1):
        print(f"--- Issue #{i} ---")
        print(f"  Line      : {err.get('line')}:{err.get('column')}")
        print(f"  Rule      : {err.get('name')}")
        print(f"  Message   : {err.get('concise_description')}")
        if "description" in err and err["description"] != err.get("concise_description"):
            print(f"  Detail    : {err.get('description').strip()}")
        print(f"  Challenge : What null/type payload crashes this code at runtime?\n")

def main():
    parser = argparse.ArgumentParser(description="Pyrefly Adversarial Autonomous & Interactive Auditor")
    parser.add_argument("--next", action="store_true", help="Fetch next smallest file needing fix")
    parser.add_argument("--file", type=str, help="Audit specific file")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive step-by-step audit mode")
    parser.add_argument("--reset-state", action="store_true", help="Reset audit tracking state")
    args = parser.parse_args()

    state = load_state()

    if args.reset_state:
        save_state({"resolved": [], "history": {}})
        print("Audit state reset.")
        return

    report = run_pyrefly()
    if not report:
        print("Failed to run Pyrefly or no output received.")
        return

    grouped = analyze_and_group(report)

    if not grouped:
        print("[SUCCESS] Zero Pyrefly errors found across codebase!")
        return

    if args.file:
        target_path = args.file.replace("\\", "/")
        errs = grouped.get(target_path, [])
        if not errs:
            print(f"No active Pyrefly issues found in {target_path}!")
        else:
            generate_file_prompt(target_path, errs)
        return

    if args.next:
        # Get first (smallest error count) file
        next_file, errs = next(iter(grouped.items()))
        generate_file_prompt(next_file, errs)
        return

    if args.interactive:
        for path, errs in grouped.items():
            generate_file_prompt(path, errs)
            choice = input(f"\nAction for {path} [(n)ext / (s)kip / (q)uit]: ").strip().lower()
            if choice == "q":
                break
            elif choice == "s":
                continue
        return

    # Default: summary overview
    print_summary(grouped, state)

if __name__ == "__main__":
    main()

