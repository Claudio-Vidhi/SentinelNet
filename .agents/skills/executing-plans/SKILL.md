---
name: superpowers:executing-plans
description: A structured workflow for systematically executing multi-step markdown implementation plans task-by-task.
---

# Executing Plans Workflow

When you are asked to execute an implementation plan (usually provided as a markdown file), you MUST follow this systematic approach:

1. **Read the Full Context**: Read the entire plan first to understand the global constraints, architecture decisions, and testing requirements before modifying any code.
2. **Task-by-Task Execution**: Do not attempt multiple tasks at once. Focus on exactly ONE task at a time.
3. **Track Progress**: 
    - If the plan contains markdown checkboxes (`- [ ]`), update the file to mark them as in-progress (`- [/]`) and then completed (`- [x]`) as you work.
    - If no checkboxes are provided, create a `task.md` artifact to track your progress.
4. **Follow Verbatim Constraints**: If the plan mandates verbatim moves or specific constraints (like "Zero behavior change"), follow them absolutely. Do not opportunistically fix bugs unless instructed.
5. **Continuous Verification**: At the end of every task, run the required verification commands (e.g., tests, parity checks) as specified in the plan. 
6. **Commit Regularly**: If the plan instructs you to commit at the end of each task, execute the `git commit` commands precisely as provided.
7. **Pause on Failure**: If a test fails after a task or the plan's instructions cannot be followed, STOP immediately. Document the failure in a clear summary and ask the user for guidance before proceeding.
