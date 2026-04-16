# Tutorial 05 — AgentCore Tools

## Overview

AgentCore Tools provides managed, hosted versions of common agent capabilities:
browser, code interpreter, file system, and computer use.

## Why AIRS Matters Here

Managed tools interact with the outside world — web pages, code execution
environments, file systems.  Each is an ingress point for attacker-controlled
content.

| Tool | Attack Vector | AIRS Hook |
|------|---------------|-----------|
| Browser Tool | Malicious webpage injects instructions via HTML/JS | PostToolUse |
| Code Interpreter | Prompt tricks agent into running attacker code | PreToolUse |
| File System | File contains hidden `<!-- IGNORE INSTRUCTIONS -->` | PostToolUse |
| Computer Use | Screen content contains injected text | PostToolUse |

## AIRS Integration for Browser Tool

```python
from security_layer import airs_protected_tool
from strands import tool

@airs_protected_tool   # scans URL args (pre) and page content (post)
@tool
def fetch_webpage(url: str) -> str:
    """Fetch and return the text content of a web page."""
    import requests
    resp = requests.get(url, timeout=10)
    return resp.text[:10_000]
```

## AIRS Integration for Code Interpreter

```python
@airs_protected_tool   # scans code string (pre) for malicious patterns
@tool
def execute_python(code: str) -> str:
    """Execute Python code in a sandboxed environment."""
    # ... sandboxed execution
```

## Source Reference

Based on: `awslabs/agentcore-samples/01-tutorials/05-AgentCore-tools/`
