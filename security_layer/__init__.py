"""
security_layer — Prisma AIRS integration for AWS Bedrock AgentCore.

Public API:
    PrismaAIRSClient      — low-level scan wrapper (scan_prompt / scan_response)
    airs_protected_tool   — @decorator for Strands @tool functions
    AIRSBlockedError      — raised when AIRS returns action=block
"""

from .airs_client import PrismaAIRSClient, ScanResult, scan_prompt, scan_response
from .agentcore_hooks import airs_protected_tool, AIRSBlockedError

__all__ = [
    "PrismaAIRSClient",
    "ScanResult",
    "scan_prompt",
    "scan_response",
    "airs_protected_tool",
    "AIRSBlockedError",
]
