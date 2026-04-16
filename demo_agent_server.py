#!/usr/bin/env python3
"""
Prisma AIRS + AgentCore — Live Demo Agent Server
=================================================
Runs a local FastAPI server on http://localhost:8080 that mimics the
AgentCore /invocations endpoint.  Every prompt and tool response is
inspected by Prisma AIRS before it reaches the LLM or is returned
to the caller.

Start:
    python3 demo_agent_server.py

Endpoints:
    GET  /health         → liveness check
    POST /invocations    → {"prompt": "..."} → agent response string

Required env vars (see .env.example):
    PRISMA_AIRS_API_KEY
    PRISMA_AIRS_PROFILE_NAME
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_DEFAULT_REGION      (default: us-west-2)
"""

import os
import sys
import time
import uuid
import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule

# ── Import security_layer (lives at repo root) ────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from security_layer.airs_client import scan_prompt, scan_response, ScanResult

# ── Strands / Bedrock ─────────────────────────────────────────────────────────
from strands import Agent, tool
from strands.models import BedrockModel

console = Console()

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
BEDROCK_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")

# ── Product data (mirrors 00-getting-started/main.py) ────────────────────────

RETURN_POLICIES = {
    "electronics": {"window": "30 days",  "condition": "Original packaging, unused or defective", "refund": "Full refund"},
    "accessories": {"window": "14 days",  "condition": "Original packaging, unused",              "refund": "Store credit or exchange"},
    "audio":       {"window": "30 days",  "condition": "Defective only after 15 days",            "refund": "Full refund ≤15 days, replacement after"},
}
PRODUCTS = {
    "PROD-001": {"name": "Wireless Headphones", "price": 79.99,  "category": "audio",       "description": "Noise-cancelling BT headphones, 30h battery",    "warranty_months": 12},
    "PROD-002": {"name": "Smart Watch",         "price": 249.99, "category": "electronics", "description": "Fitness tracker, HR monitor, GPS, 5-day battery", "warranty_months": 24},
    "PROD-003": {"name": "Laptop Stand",        "price": 39.99,  "category": "accessories", "description": "Adjustable aluminium ergonomic stand",             "warranty_months": 6},
    "PROD-004": {"name": "USB-C Hub",           "price": 54.99,  "category": "accessories", "description": "7-in-1: HDMI, USB-A, SD, ethernet",               "warranty_months": 12},
    "PROD-005": {"name": "Mechanical Keyboard", "price": 129.99, "category": "electronics", "description": "RGB, Cherry MX switches",                          "warranty_months": 24},
}


# ── Console helpers ───────────────────────────────────────────────────────────

def _log_scan_start(phase: str, preview: str):
    airs_url = os.environ.get(
        "PRISMA_AIRS_URL",
        "https://service.api.aisecurity.paloaltonetworks.com",
    )
    console.print()
    console.print(Rule(f"[bold cyan]AIRS ▶ {phase}[/]", style="cyan"))
    console.print(f"[dim]  Payload:[/] [italic]{preview[:120]}{'…' if len(preview) > 120 else ''}[/]")
    console.print(f"[dim]  Calling:[/] [cyan]{airs_url}/v1/scan/sync/request[/]")


def _log_scan_result(phase: str, result: ScanResult, elapsed_ms: int):
    if result.blocked:
        verdict_text = Text("🚫  BLOCKED", style="bold red")
        panel_style  = "red"
    else:
        verdict_text = Text("✅  ALLOWED", style="bold green")
        panel_style  = "green"

    detections = ", ".join(result.detections) if result.detections else "none"
    body = (
        f"{verdict_text}\n"
        f"  Category   : [bold]{result.category}[/]\n"
        f"  Detections : [yellow]{detections}[/]\n"
        f"  Scan ID    : [dim]{result.scan_id}[/]\n"
        f"  Elapsed    : [dim]{elapsed_ms} ms[/]"
    )
    console.print(Panel(body, title=f"Prisma AIRS — {phase}", style=panel_style, expand=False))


# ── AIRS-instrumented tools ───────────────────────────────────────────────────

@tool
def get_return_policy(product_category: str) -> str:
    """Get return policy for a product category (electronics, accessories, audio)."""
    _log_scan_start("PreToolUse: get_return_policy", product_category)
    t0 = time.time()
    r = scan_prompt(product_category, source="pre-tool-use", tool_name="get_return_policy")
    _log_scan_result("PreToolUse", r, int((time.time() - t0) * 1000))
    if r.blocked:
        return f"[AIRS BLOCKED] Tool input blocked: {r.category}"

    cat = product_category.lower()
    if cat in RETURN_POLICIES:
        p = RETURN_POLICIES[cat]
        result = (f"Policy for {cat}: Window {p['window']} | "
                  f"{p['condition']} | Refund: {p['refund']}")
    else:
        result = f"No policy found for '{product_category}'. Contact support."

    _log_scan_start("PostToolUse: get_return_policy", result)
    t0 = time.time()
    r2 = scan_response(result, tool_name="get_return_policy")
    _log_scan_result("PostToolUse", r2, int((time.time() - t0) * 1000))
    return result if not r2.blocked else f"[AIRS BLOCKED] Tool response blocked: {r2.category}"


@tool
def get_product_info(query: str) -> str:
    """Search products by name, ID (e.g. PROD-001), or keyword."""
    _log_scan_start("PreToolUse: get_product_info", query)
    t0 = time.time()
    r = scan_prompt(query, source="pre-tool-use", tool_name="get_product_info")
    _log_scan_result("PreToolUse", r, int((time.time() - t0) * 1000))
    if r.blocked:
        return f"[AIRS BLOCKED] Tool input blocked: {r.category}"

    q = query.lower()
    if query.upper() in PRODUCTS:
        p = PRODUCTS[query.upper()]
        result = (f"{p['name']} ({query.upper()}): ${p['price']}, {p['category']}, "
                  f"{p['description']}, {p['warranty_months']}mo warranty")
    else:
        hits = [
            f"{pid}: {p['name']} ${p['price']} — {p['description']}"
            for pid, p in PRODUCTS.items()
            if q in p["name"].lower() or q in p["description"].lower() or q in p["category"].lower()
        ]
        result = ("Found:\n" + "\n".join(hits)) if hits else f"No products found for '{query}'."

    _log_scan_start("PostToolUse: get_product_info", result[:120])
    t0 = time.time()
    r2 = scan_response(result, tool_name="get_product_info")
    _log_scan_result("PostToolUse", r2, int((time.time() - t0) * 1000))
    return result if not r2.blocked else f"[AIRS BLOCKED] Tool response blocked: {r2.category}"


# ── Agent singleton ───────────────────────────────────────────────────────────

_agent = None


def get_agent() -> Agent:
    global _agent
    if _agent is None:
        model = BedrockModel(model_id=BEDROCK_MODEL_ID, region_name=BEDROCK_REGION)
        _agent = Agent(
            model=model,
            system_prompt=(
                "You are a helpful customer support assistant for an e-commerce company. "
                "Use get_return_policy() and get_product_info() tools to answer questions accurately. "
                "Be concise and professional. All tool calls are security-scanned by Prisma AIRS."
            ),
            tools=[get_return_policy, get_product_info],
        )
        console.print(f"[bold green]✔ Agent ready[/] — model: [cyan]{BEDROCK_MODEL_ID}[/]")
    return _agent


# ── FastAPI app ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(application: FastAPI):
    console.print()
    console.print(Panel(
        "[bold white]Prisma AIRS × AWS Bedrock AgentCore[/]\n"
        "[dim]Local Demo Agent Server[/]\n\n"
        f"[cyan]Model  :[/] {BEDROCK_MODEL_ID}\n"
        f"[cyan]Region :[/] {BEDROCK_REGION}\n"
        f"[cyan]Profile:[/] {os.environ.get('PRISMA_AIRS_PROFILE_NAME', 'NOT SET — check .env.example')}\n"
        f"[cyan]Listen :[/] http://localhost:8080",
        title="🛡  AIRS Demo Server", style="bold blue", expand=False,
    ))
    get_agent()
    yield
    console.print("[dim]Server shutting down.[/]")


app = FastAPI(title="AIRS AgentCore Demo", lifespan=lifespan)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": BEDROCK_MODEL_ID,
        "airs_profile": os.environ.get("PRISMA_AIRS_PROFILE_NAME"),
    }


@app.post("/invocations")
async def invocations(request: Request):
    body       = await request.json()
    prompt     = body.get("prompt", "").strip()
    session_id = body.get("session_id", str(uuid.uuid4()))

    if not prompt:
        return JSONResponse({"error": "missing 'prompt' field"}, status_code=400)

    console.print()
    console.print(Rule("[bold white]NEW INVOCATION[/]", style="white"))
    console.print(f"[dim]Session:[/] {session_id}")
    console.print(f"[bold]Prompt :[/] {prompt[:200]}")

    # ── Gate 1: UserPromptSubmit scan ─────────────────────────────────────────
    _log_scan_start("UserPromptSubmit", prompt)
    t0      = time.time()
    pre     = scan_prompt(prompt, session_id=session_id, source="user-prompt-submit")
    elapsed = int((time.time() - t0) * 1000)
    _log_scan_result("UserPromptSubmit", pre, elapsed)

    if pre.blocked:
        msg = (
            f"🚫 Your request was blocked by Prisma AIRS.\n"
            f"   Category   : {pre.category}\n"
            f"   Detections : {', '.join(pre.detections)}\n"
            f"   Scan ID    : {pre.scan_id}"
        )
        console.print("[bold red]⛔  Request blocked at UserPromptSubmit[/]")
        return JSONResponse({
            "response": msg,
            "airs_action": "block",
            "airs_scan_id": pre.scan_id,
            "airs_detections": pre.detections,
            "airs_category": pre.category,
        })

    # ── Gates 2 + 3 handled inline inside each @tool ──────────────────────────
    console.print(f"\n[bold green]▶  Routing to agent...[/]")
    try:
        agent    = get_agent()
        loop     = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: str(agent(prompt)))
    except Exception as exc:
        console.print(f"[bold red]Agent error:[/] {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)

    # ── Gate 4: final response scan ───────────────────────────────────────────
    _log_scan_start("PostResponse (final output)", response[:200])
    t0      = time.time()
    post    = scan_response(response, session_id=session_id)
    elapsed = int((time.time() - t0) * 1000)
    _log_scan_result("PostResponse (final output)", post, elapsed)

    if post.blocked:
        msg = (
            f"🚫 Agent response was blocked by Prisma AIRS.\n"
            f"   Category   : {post.category}\n"
            f"   Detections : {', '.join(post.detections)}\n"
            f"   Scan ID    : {post.scan_id}"
        )
        return JSONResponse({
            "response": msg,
            "airs_action": "block",
            "airs_scan_id": post.scan_id,
            "airs_detections": post.detections,
            "airs_category": post.category,
        })

    console.print(Rule("[bold green]RESPONSE DELIVERED[/]", style="green"))
    return JSONResponse({"response": response, "airs_action": "allow", "airs_scan_id": pre.scan_id})


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
