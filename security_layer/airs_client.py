"""
security_layer/airs_client.py
─────────────────────────────────────────────────────────────────────────────
Prisma AIRS (AI Runtime Security) client for AWS Bedrock AgentCore.

WHAT THIS FILE DOES
───────────────────
This module wraps Palo Alto Networks Prisma AIRS Sync Scan API into two
simple Python functions:

    scan_prompt()   → called BEFORE a tool runs (PreToolUse)
    scan_response() → called AFTER  a tool runs (PostToolUse)

Both return a ScanResult dataclass with:
    .action   — "allow" or "block"
    .blocked  — True when the AIRS policy engine decided to stop execution
    .category — human-readable reason (e.g. "prompt_injection", "dlp")
    .detections — list of specific threat types detected

HOW IT FITS INTO THE AGENTCORE FLOW
─────────────────────────────────────
  User Prompt
      │
      ▼
  [scan_prompt]  ← UserPromptSubmit check
      │
      ▼
  AgentCore LLM decides to call a tool
      │
      ▼
  [scan_prompt]  ← PreToolUse check (tool arguments inspected)
      │
      ▼
  Tool executes (filesystem, web, MCP server, etc.)
      │
      ▼
  [scan_response] ← PostToolUse check (tool output inspected)
      │
      ▼
  LLM receives tool output → generates final answer

If AIRS returns action="block" at any step, execution stops and the
blocking reason is returned to the caller instead.

REQUIRED ENVIRONMENT VARIABLES
───────────────────────────────
    PRISMA_AIRS_API_KEY          — API token from Prisma AIRS console
    PRISMA_AIRS_PROFILE_NAME     — Security profile name (preferred)
    PRISMA_AIRS_PROFILE_ID       — Security profile UUID (fallback)
    PRISMA_AIRS_URL              — Base URL (default shown below)

See .env.example for the exact export syntax.
"""

import os
import uuid
import logging
import requests
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Endpoint configuration ────────────────────────────────────────────────────
# The sync scan API returns a verdict in a single HTTP round-trip (< 200 ms
# typical). The async API exists but requires polling — sync is better here
# because we need the verdict before the tool can run.
AIRS_URL = os.environ.get(
    "PRISMA_AIRS_URL",
    "https://service.api.aisecurity.paloaltonetworks.com",
).rstrip("/")
AIRS_SCAN_ENDPOINT = f"{AIRS_URL}/v1/scan/sync/request"

# ── Credentials (never hardcode — always read from environment) ───────────────
API_KEY      = os.environ.get("PRISMA_AIRS_API_KEY", "")
PROFILE_NAME = os.environ.get("PRISMA_AIRS_PROFILE_NAME", "")
PROFILE_ID   = os.environ.get("PRISMA_AIRS_PROFILE_ID", "")
APP_NAME     = os.environ.get("AIRS_APP_NAME", "Agentcore-AIRS-POV")


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Parsed response from a single AIRS sync scan call.

    The AIRS API returns a JSON object.  This dataclass flattens the
    nested structure into the fields most useful for gate logic.
    """
    action:            str              # "allow" | "block"
    category:          str              # e.g. "prompt_injection", "dlp", "malicious_url"
    scan_id:           str              # UUID assigned by AIRS — use for log correlation
    report_id:         str              # UUID for the full report (available in AIRS console)
    prompt_detected:   dict = field(default_factory=dict)   # threat flags for prompt content
    response_detected: dict = field(default_factory=dict)   # threat flags for response content
    tool_detected:     dict = field(default_factory=dict)   # threat flags for tool events
    raw:               dict = field(default_factory=dict)   # full raw API response for debugging

    @property
    def blocked(self) -> bool:
        """True when AIRS decided to stop this request."""
        return self.action == "block"

    @property
    def detections(self) -> list[str]:
        """Flat list of every threat category that fired (deduped)."""
        found = []
        for detection_dict in (self.prompt_detected, self.response_detected, self.tool_detected):
            found += [k for k, v in detection_dict.items() if v]
        return list(set(found))


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ai_profile() -> dict:
    """Build the ai_profile block for the API payload.

    AIRS uses the profile to look up which security rules to apply.
    We prefer profile_name (human-readable) over profile_id (UUID) because
    the profile_name stays stable even if the profile is re-created.
    """
    if PROFILE_NAME:
        return {"profile_name": PROFILE_NAME}
    if PROFILE_ID:
        return {"profile_id": PROFILE_ID}
    raise RuntimeError(
        "Neither PRISMA_AIRS_PROFILE_NAME nor PRISMA_AIRS_PROFILE_ID is set. "
        "Export one of these before running the demo."
    )


def _headers() -> dict:
    """HTTP headers for every AIRS API call."""
    if not API_KEY:
        raise RuntimeError(
            "PRISMA_AIRS_API_KEY is not set. "
            "Export it from .env.example before running the demo."
        )
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-pan-token": API_KEY,   # Prisma AIRS bearer token header
    }


def _parse(raw: dict) -> ScanResult:
    """Convert raw JSON dict → ScanResult, tolerating missing keys."""
    return ScanResult(
        action            = raw.get("action")           or "unknown",
        category          = raw.get("category")         or "unknown",
        scan_id           = raw.get("scan_id")          or "",
        report_id         = raw.get("report_id")        or "",
        prompt_detected   = raw.get("prompt_detected")  or {},
        response_detected = raw.get("response_detected") or {},
        tool_detected     = raw.get("tool_detected")    or {},
        raw               = raw,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def scan_prompt(
    prompt: str,
    session_id: Optional[str] = None,
    source: str = "pre-tool-use",
    tool_name: Optional[str] = None,
) -> ScanResult:
    """Scan a user prompt or tool input BEFORE any action is taken.

    Called at two points in the AgentCore lifecycle:
        1. UserPromptSubmit  — the raw user message before the LLM sees it
        2. PreToolUse        — the serialized tool arguments before the tool runs

    Args:
        prompt:     The text to scan.  For tool inputs, pass a serialized
                    representation of the tool arguments.
        session_id: Optional UUID to correlate multiple scans in one session.
                    If omitted, a new UUID is generated.
        source:     Freeform label included in AIRS metadata.  Use
                    "user-prompt-submit" or "pre-tool-use" so reports
                    clearly show where in the pipeline the scan fired.
        tool_name:  Name of the tool about to be called (optional but helps
                    AIRS build richer reports).

    Returns:
        ScanResult — check .blocked before proceeding.

    Raises:
        RuntimeError if credentials are not set.
        requests.HTTPError on non-2xx AIRS API response.
    """
    tr_id = session_id or str(uuid.uuid4())

    # The AIRS sync scan request payload follows the documented schema at
    # https://pan.dev/ai-runtime-security/api/create-ai-security-sync-scan/
    payload: dict = {
        "tr_id": tr_id,
        "ai_profile": _ai_profile(),
        "metadata": {
            "app_user": "agentcore-demo-user",
            "app_name": APP_NAME,
            "source": source,
        },
        "contents": [{"prompt": prompt}],
    }
    if tool_name:
        payload["metadata"]["tool_name"] = tool_name

    logger.debug("[AIRS] scan_prompt tr_id=%s source=%s tool=%s", tr_id, source, tool_name)
    resp = requests.post(AIRS_SCAN_ENDPOINT, headers=_headers(), json=payload, timeout=15)
    resp.raise_for_status()
    result = _parse(resp.json())
    logger.info(
        "[AIRS-PRE] action=%s category=%s detections=%s scan_id=%s",
        result.action, result.category, result.detections, result.scan_id,
    )
    return result


def scan_response(
    response: str,
    session_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    mcp_server: Optional[str] = None,
    mcp_tool: Optional[str] = None,
    tool_input: Optional[str] = None,
) -> ScanResult:
    """Scan a tool response AFTER the tool has run but BEFORE the LLM sees it.

    Called during PostToolUse.  The response string may contain:
    - Indirect prompt injection hidden in fetched documents
    - Leaked credentials returned by a misconfigured API
    - Encoded exfiltration payloads in MCP tool output
    - Malicious content generated by an untrusted tool

    Args:
        response:   The raw tool output (truncated to 20 000 chars internally).
        session_id: Correlate with the preceding scan_prompt call by passing
                    the same session_id.
        tool_name:  Name of the tool that produced this response.
        mcp_server: For MCP tools — the server name (e.g. "aws-tools").
        mcp_tool:   For MCP tools — the tool name (e.g. "s3_get_object").
        tool_input: For MCP tools — the serialized input that triggered the
                    tool call, included in the AIRS tool_event block.

    Returns:
        ScanResult — check .blocked before passing response to the LLM.
    """
    tr_id = session_id or str(uuid.uuid4())

    # Main content block always has the response text
    content: dict = {"response": response[:20_000]}

    # When scanning MCP tool output, include a structured tool_event block.
    # This gives AIRS richer context: which server/tool produced the output,
    # what input triggered it, and the ecosystem ("mcp").
    if mcp_server and mcp_tool:
        content["tool_event"] = {
            "metadata": {
                "ecosystem": "mcp",
                "method": "tools/call",
                "server_name": mcp_server,
                "tool_invoked": mcp_tool,
            },
            "input":  tool_input or "",
            "output": response[:20_000],
        }

    payload: dict = {
        "tr_id": tr_id,
        "ai_profile": _ai_profile(),
        "metadata": {
            "app_user": "agentcore-demo-user",
            "app_name": APP_NAME,
            "source": "post-tool-use",
        },
        "contents": [content],
    }
    if tool_name:
        payload["metadata"]["tool_name"] = tool_name

    logger.debug("[AIRS] scan_response tr_id=%s tool=%s", tr_id, tool_name)
    resp = requests.post(AIRS_SCAN_ENDPOINT, headers=_headers(), json=payload, timeout=15)
    resp.raise_for_status()
    result = _parse(resp.json())
    logger.info(
        "[AIRS-POST] action=%s category=%s detections=%s scan_id=%s",
        result.action, result.category, result.detections, result.scan_id,
    )
    return result


# ── Convenience class (wraps module-level functions for dependency injection) ─

class PrismaAIRSClient:
    """Object-oriented wrapper around scan_prompt / scan_response.

    Useful when you need to inject a mock client in tests or when you
    want per-instance configuration (different profiles for different agents).

    Usage:
        client = PrismaAIRSClient()
        result = client.scan_prompt("Tell me how to make explosives")
        if result.blocked:
            raise SecurityError(result.category)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        profile_id: Optional[str] = None,
        base_url: Optional[str] = None,
        app_name: str = "Agentcore-AIRS-POV",
    ):
        # Override module-level globals when explicitly supplied
        if api_key:
            import security_layer.airs_client as _m
            _m.API_KEY = api_key
        if profile_name:
            import security_layer.airs_client as _m
            _m.PROFILE_NAME = profile_name
        if profile_id:
            import security_layer.airs_client as _m
            _m.PROFILE_ID = profile_id
        if base_url:
            import security_layer.airs_client as _m
            _m.AIRS_URL = base_url.rstrip("/")
            _m.AIRS_SCAN_ENDPOINT = f"{_m.AIRS_URL}/v1/scan/sync/request"
        if app_name:
            import security_layer.airs_client as _m
            _m.APP_NAME = app_name

    def scan_prompt(self, prompt: str, **kwargs) -> ScanResult:
        return scan_prompt(prompt, **kwargs)

    def scan_response(self, response: str, **kwargs) -> ScanResult:
        return scan_response(response, **kwargs)
