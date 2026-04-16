# Tutorial 03 — AgentCore Identity

## Overview

AgentCore Identity provides OAuth 2.0 / OIDC-based authentication for agents.
This tutorial covers machine-to-machine (M2M) auth so that agents can call
downstream services with verified identities.

## Why AIRS Matters Here

Identity tokens are high-value targets.  An agent with credential access is
a prime attack surface for:

- **Token exfiltration** — a malicious tool returning an OAuth token in its
  output (caught by PostToolUse scan)
- **Prompt injection via identity claims** — an attacker embedding instructions
  in a JWT subject claim or user profile that the agent reads
- **Over-privileged tool calls** — tool arguments requesting broader scopes
  than needed (caught by PreToolUse scan + IAM policies)

## AIRS Integration Points

```python
# Any tool that reads identity tokens or user profiles should be wrapped:
@airs_protected_tool
@tool
def get_user_profile(user_id: str) -> str:
    # AIRS scans the output for credential leakage before the LLM sees it
    ...

@airs_protected_tool
@tool
def exchange_token(code: str, scope: str) -> str:
    # AIRS scans the input args for injection in the 'scope' parameter
    ...
```

## Source Reference

Based on: `awslabs/agentcore-samples/01-tutorials/03-AgentCore-identity/`
