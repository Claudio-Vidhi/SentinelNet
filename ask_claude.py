import os
import json
import requests

with open('c_api_key.txt', 'r', encoding='utf-8') as f:
    api_key = f.read().strip()

try:
    with open('destructure.diff', 'r', encoding='utf-16') as f:
        destructure_diff = f.read()
except Exception as e:
    destructure_diff = f"Error reading: {e}"

try:
    with open('ui-revamp.diff', 'r', encoding='utf-16') as f:
        ui_revamp_diff = f.read()
except Exception as e:
    ui_revamp_diff = f"Error reading: {e}"

# Truncate to avoid hitting 200k token limits (approx 300k chars each)
if len(destructure_diff) > 300000:
    destructure_diff = destructure_diff[:300000] + "\n...[TRUNCATED]"
if len(ui_revamp_diff) > 300000:
    ui_revamp_diff = ui_revamp_diff[:300000] + "\n...[TRUNCATED]"

prompt = f"""
We have two git worktrees/branches: 'ui-revamp' and 'destructure'.
We need to merge them into a new branch 'new_dev'.

Here is the diff for the 'destructure' branch from master:
```diff
{destructure_diff}
```

Here is the diff for the 'ui-revamp' branch from master:
```diff
{ui_revamp_diff}
```

Please manage this by creating a detailed implementation plan for merging these two branches into 'new_dev'. Provide step-by-step instructions on what files to modify and how to resolve potential conflicts.
"""

url = "https://api.anthropic.com/v1/messages"
headers = {
    "x-api-key": api_key,
    "anthropic-version": "2023-06-01",
    "content-type": "application/json"
}

def ask_claude(model):
    data = {
        "model": model,
        "max_tokens": 4096,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    return requests.post(url, headers=headers, json=data)

response = ask_claude("claude-opus-4-8")
if response.status_code != 200:
    print(f"Failed with claude-opus-4-8: {response.text}")
    print("Falling back to claude-3-opus-20240229...")
    response = ask_claude("claude-3-opus-20240229")

if response.status_code == 200:
    content = response.json()['content'][0]['text']
    with open('claude_plan.md', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Plan created successfully and saved to claude_plan.md")
else:
    print("Error:", response.status_code, response.text)
