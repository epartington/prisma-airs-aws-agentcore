# Tutorial 00 — Getting Started

## Overview

This tutorial introduces the baseline AgentCore customer support agent and
shows the minimal diff required to add Prisma AIRS protection.

| File | Description |
|------|-------------|
| `main_original.py` | Unmodified baseline — no security scanning |
| `main_with_airs.py` | AIRS-protected version — 4 insertion points added |

## What Changed

```diff
+ from security_layer import airs_protected_tool, AIRSBlockedError
+ from security_layer import scan_prompt

+ @airs_protected_tool   ← PreToolUse + PostToolUse on get_return_policy
  @tool
  def get_return_policy(...):

+ @airs_protected_tool   ← PreToolUse + PostToolUse on get_product_info
  @tool
  def get_product_info(...):

  async def invoke(payload, context):
+     pre = scan_prompt(user_prompt, source="user-prompt-submit")
+     if pre.blocked:
+         yield f"[AIRS BLOCKED] {pre.category}"
+         return
```

## Quick Test

```bash
# From repo root
export $(cat .env.example | grep -v '#' | xargs)  # fill in real values first
python3 tutorials/00-getting-started/main_with_airs.py
```
