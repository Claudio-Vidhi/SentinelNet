---
name: pyrefly-adversarial-audit
description: Adversarially audit Pyrefly type errors and warnings to identify true bugs, null-pointer crashes, and invalid signatures, and propose strict type-safe fixes without resorting to error suppressions.
---

# Pyrefly Adversarial Audit Skill

This skill guides subagents in auditing Python code using `pyrefly` type checker diagnostics through an adversarial security/quality lens.

## Audit Objective
Do not blindly fix syntax or insert `# pyrefly: ignore`. Act as a hostile code reviewer seeking edge cases where Pyrefly warnings indicate real runtime defects, unhandled `None` dereferences, schema drift, or broken API contracts.

## Workflow

### Step 1: Generate Scoped Diagnostics
Run the Pyrefly analyzer script targeting a specific file or module:
```bash
.\.venv\Scripts\python.exe scripts/pyrefly_adversarial_analyzer.py <target_file_path>
```

### Step 2: Categorize Diagnostics
For each reported diagnostic:
1. **Critical Defect (Red)**:
   - `missing-attribute` or `unsupported-operation` on `NoneType` or dynamic objects.
   - Triggers `AttributeError` or `TypeError` under boundary conditions.
2. **Type/Contract Drift (Yellow)**:
   - `bad-argument-type` or `bad-assignment`.
   - Mismatch between caller pass value and function definition (e.g. `Optional[str]` vs `str`).
3. **Mock/Test Artefact (Blue)**:
   - Positional parameter name mismatch or incomplete test mocks.

### Step 3: Adversarial Challenge Rules
- **No Silencing**: `# pyrefly: ignore` or `# type: ignore` is strictly forbidden unless referencing an external untyped C-extension or third-party dependency.
- **Null Safety**: Any `Optional[...]` or potential `None` return must be handled with explicit guard clauses or assertion checks before accessing attributes.
- **Contract Enforcement**: Update type annotations across both caller and target function to maintain signature parity.

### Step 4: Verification
After applying fixes:
1. Re-run `pyrefly`:
   ```bash
   .\.venv\Scripts\pyrefly.exe check
   ```
2. Run test suite to verify no regressions:
   ```bash
   .\.venv\Scripts\python.exe -m pytest
   ```
