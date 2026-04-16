# Tutorial 01 — AgentCore Runtime

## Overview

AgentCore Runtime is AWS's serverless runtime for deploying AI agents.  This
tutorial shows how to host a Strands agent on AgentCore Runtime **with Prisma
AIRS scanning on every tool call**.

## Key Concepts

- `BedrockAgentCoreApp` — the runtime container that handles HTTP and lifecycle
- `@app.entrypoint` — marks the async generator that processes requests
- `@tool` — registers a Python function as an LLM-callable tool
- `@airs_protected_tool` — wraps any `@tool` with AIRS Pre/PostToolUse scanning

## AIRS Integration Points

| Hook | Where | Purpose |
|------|-------|---------|
| UserPromptSubmit | `invoke()` before LLM call | Block malicious prompts before token spend |
| PreToolUse | `@airs_protected_tool` wrapper | Inspect tool args for injection/DLP |
| PostToolUse | `@airs_protected_tool` wrapper | Inspect tool output for injection/leakage |

## Quick Start

```bash
# 1. Install dependencies
pip install -r ../../requirements.txt

# 2. Set credentials
cp ../../.env.example .env
# Edit .env with your real PRISMA_AIRS_API_KEY and AWS credentials

# 3. Run locally using the demo server
cd ../..
./start_demo.sh
```

## Source Reference

Based on: `awslabs/agentcore-samples/01-tutorials/01-AgentCore-runtime/`
AIRS changes: see `security_layer/agentcore_hooks.py` for the decorator implementation.
