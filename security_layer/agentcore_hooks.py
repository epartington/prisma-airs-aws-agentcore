"""
security_layer/agentcore_hooks.py
─────────────────────────────────────────────────────────────────────────────
Prisma AIRS hook decorators for AWS Bedrock AgentCore Strands tools.

UNDERSTANDING PRE/POST TOOL INTERCEPTS
───────────────────────────────────────
AgentCore (powered by the Strands framework) uses a tool-call lifecycle:

    1. The LLM decides to call a tool and produces tool arguments.
    2. The framework calls the Python function decorated with @tool.
    3. The function result is fed back to the LLM.

Prisma AIRS needs to inspect at steps 1 and 3.  In Claude Code these are
implemented as shell hooks (PreToolUse / PostToolUse in settings.json).
Here we replicate the same semantic in pure Python using a decorator.

HOW @airs_protected_tool WORKS
────────────────────────────────

    @airs_protected_tool      ← outer decorator — adds AIRS scanning
    @tool                     ← inner decorator — registers with Strands
    def my_tool(arg: str) -> str:
        ...

When the LLM calls my_tool("some input"):

    ┌──────────────────────────────────────────────────────┐
    │ wrapper() [this file]                                │
    │   ① serialize_inputs(args, kwargs) → input_repr     │
    │   ② scan_prompt(input_repr)                          │ ← PreToolUse
    │      if blocked → raise AIRSBlockedError             │
    │   ③ result = fn(*args, **kwargs)    ← tool runs      │
    │   ④ scan_response(str(result))                       │ ← PostToolUse
    │      if blocked → raise AIRSBlockedError             │
    │   ⑤ return result to LLM                             │
    └──────────────────────────────────────────────────────┘

FAIL-CLOSED DESIGN
───────────────────
If the AIRS API is unreachable (network error, timeout, 5xx), the decorator
raises RuntimeError and the tool does NOT execute.  This "fail-closed" design
means a security outage prevents tool execution rather than allowing it.

Change the except blocks to `logger.warning` + `pass` if you need
fail-open behaviour (not recommended for production).
"""

import functools
import logging
import uuid
from typing import Any, Callable

from .airs_client import scan_prompt, scan_response, ScanResult

logger = logging.getLogger(__name__)


class AIRSBlockedError(Exception):
    """Raised when Prisma AIRS returns action='block' for a tool call.

    Attributes:
        phase   — "pre" (input blocked before tool ran) or
                  "post" (output blocked after tool ran)
        result  — the full ScanResult from AIRS including scan_id and detections
    """

    def __init__(self, phase: str, result: ScanResult):
        self.phase  = phase
        self.result = result
        detections  = ", ".join(result.detections) if result.detections else result.category
        super().__init__(
            f"[AIRS-{phase.upper()}] Blocked: {result.category} "
            f"(detections: {detections}, scan_id: {result.scan_id})"
        )


def airs_protected_tool(fn: Callable) -> Callable:
    """Decorator: wrap a Strands @tool with Prisma AIRS Pre/PostToolUse scanning.

    Apply ABOVE @tool so the decorator chain is:
        airs_protected_tool → tool → your function

    The wrapper preserves the function signature so Strands can still
    introspect the docstring and parameter types.

    Example:
        from security_layer import airs_protected_tool
        from strands import tool

        @airs_protected_tool   # ← must come first (outermost)
        @tool
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs) -> Any:
        tool_name  = fn.__name__
        # One shared session_id links the pre and post scan in AIRS reports
        session_id = str(uuid.uuid4())

        # ── Step ①②: PreToolUse — scan the tool arguments ──────────────────
        # We serialize args + kwargs to a readable string.  For most Strands
        # tools this is just the keyword arguments (e.g. "path=/tmp/data.csv").
        input_repr = _serialize_inputs(args, kwargs)
        try:
            pre_result = scan_prompt(
                prompt     = input_repr,
                session_id = session_id,
                source     = "pre-tool-use",
                tool_name  = tool_name,
            )
            logger.info(
                "[AIRS-PRE] tool=%s action=%s detections=%s scan_id=%s",
                tool_name, pre_result.action, pre_result.detections, pre_result.scan_id,
            )
            if pre_result.blocked:
                # The tool arguments contain something AIRS flagged (e.g. prompt
                # injection hidden in a user-supplied filename, DLP in args, etc.)
                raise AIRSBlockedError("pre", pre_result)

        except AIRSBlockedError:
            raise   # re-raise without wrapping

        except Exception as exc:
            # AIRS API call failed — fail closed: block execution
            logger.error(
                "[AIRS-PRE] scan failed for %s: %s — blocking (fail-closed)",
                tool_name, exc,
            )
            raise RuntimeError(f"AIRS pre-scan failed for {tool_name}: {exc}") from exc

        # ── Step ③: Execute the actual tool ─────────────────────────────────
        result = fn(*args, **kwargs)

        # ── Step ④⑤: PostToolUse — scan the tool output ──────────────────
        # Convert output to string.  Tool output may contain:
        #   • Indirect prompt injection in fetched web documents
        #   • Leaked credentials returned by a misconfigured database
        #   • Encoded exfiltration payloads embedded by a malicious MCP server
        response_str = str(result) if result is not None else ""
        try:
            post_result = scan_response(
                response   = response_str,
                session_id = session_id,   # same session → linked in AIRS dashboard
                tool_name  = tool_name,
            )
            logger.info(
                "[AIRS-POST] tool=%s action=%s detections=%s scan_id=%s",
                tool_name, post_result.action, post_result.detections, post_result.scan_id,
            )
            if post_result.blocked:
                raise AIRSBlockedError("post", post_result)

        except AIRSBlockedError:
            raise

        except Exception as exc:
            logger.error(
                "[AIRS-POST] scan failed for %s: %s — blocking (fail-closed)",
                tool_name, exc,
            )
            raise RuntimeError(f"AIRS post-scan failed for {tool_name}: {exc}") from exc

        return result

    return wrapper


def _serialize_inputs(args: tuple, kwargs: dict) -> str:
    """Produce a human-readable string of tool arguments for the AIRS scan.

    Positional args are included as bare values; keyword args as key=value.
    This string is what AIRS actually scans — keep it representative of the
    real tool invocation so AIRS can detect injections in any parameter.
    """
    parts = [str(a) for a in args]
    parts += [f"{k}={v}" for k, v in kwargs.items()]
    return " | ".join(parts) if parts else "(no args)"
