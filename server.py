import json
import os
import re
import sys
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

from vault import SecretVault, SSEStreamDemasker

# ANSI Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Load config
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
config: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8765,
    "upstreams": {
        "agentrouter": "https://agentrouter.org/v1",
        "aegis": "https://aegis-ubuntu.tailcfa41a.ts.net/v1"
    },
    "allowed_hosts": [
        "agentrouter.org",
        "aegis-ubuntu.tailcfa41a.ts.net"
    ],
    "secrets_file": "secrets.json"
}

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config.update(json.load(f))

# Initialize Vault
secrets_path = os.path.join(os.path.dirname(__file__), config.get("secrets_file", "secrets.json"))
vault = SecretVault(secrets_path)

app = FastAPI(title="ZCode Secret Masking Proxy", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def log_shield(msg: str):
    print(f"{CYAN}{BOLD}[SHIELD]{RESET} {msg}")

def log_mask(msg: str):
    print(f"{YELLOW}{BOLD}[MASK 🔒]{RESET} {msg}")

def log_demask(msg: str):
    print(f"{GREEN}{BOLD}[DEMASK 🔓]{RESET} {msg}")

def log_warn(msg: str):
    print(f"{RED}{BOLD}[WARN ⚠️]{RESET} {msg}")


def check_domain_allowed(host: str) -> bool:
    allowed = config.get("allowed_hosts", [])
    if not allowed:
        return True
    return any(host == a or host.endswith("." + a) for a in allowed)


def resolve_target_url(upstream_name_or_scheme: str, subpath: str) -> str:
    """Resolves target URL based on upstream alias or explicit scheme/host."""
    upstreams = config.get("upstreams", {})

    # Case 1: Known named upstream (e.g. /agentrouter/chat/completions)
    if upstream_name_or_scheme in upstreams:
        base_url = upstreams[upstream_name_or_scheme].rstrip("/")
        subpath = subpath.lstrip("/")

        # Handle deduplication of /v1 if base ends in /v1 and subpath starts with v1/
        if base_url.endswith("/v1") and subpath.startswith("v1/"):
            subpath = subpath[3:]

        return f"{base_url}/{subpath}" if subpath else base_url

    # Case 2: Explicit scheme (e.g. /proxy/https/agentrouter.org/v1/chat/completions)
    if upstream_name_or_scheme in ("http", "https"):
        scheme = upstream_name_or_scheme
        return f"{scheme}://{subpath}"

    raise HTTPException(status_code=400, detail=f"Unknown upstream or scheme: {upstream_name_or_scheme}")


async def proxy_request_handler(target_url: str, request: Request) -> Response:
    parsed = urlparse(target_url)
    target_host = parsed.netloc

    if not check_domain_allowed(target_host):
        log_warn(f"Domain '{target_host}' is NOT in allowed_hosts list! Request blocked for security.")
        raise HTTPException(status_code=403, detail=f"Host '{target_host}' not in allowed_hosts")

    log_shield(f"{request.method} -> {target_url}")

    # 1. Read and mask request body
    raw_body = await request.body()
    masked_body = raw_body

    if raw_body:
        try:
            body_json = json.loads(raw_body.decode("utf-8"))
            masked_json, count = vault.mask_payload(body_json)
            if count > 0:
                log_mask(f"Replaced {count} secret(s) with placeholders before sending to {target_host}")
            masked_body = json.dumps(masked_json).encode("utf-8")
        except Exception:
            # Fallback to plain text masking
            try:
                body_str = raw_body.decode("utf-8")
                masked_str, count = vault.mask_text(body_str)
                if count > 0:
                    log_mask(f"Replaced {count} secret(s) in raw text before sending to {target_host}")
                masked_body = masked_str.encode("utf-8")
            except Exception:
                pass

    # 2. Prepare headers (forward Authorization, Content-Type, etc.)
    forward_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ("host", "content-length", "connection", "accept-encoding"):
            forward_headers[k] = v

    forward_headers["Host"] = target_host

    # 3. Forward request to upstream
    client = httpx.AsyncClient(timeout=180.0, follow_redirects=True)

    try:
        # Build query string
        query = str(request.url.query)
        req_url = f"{target_url}?{query}" if query else target_url

        upstream_req = client.build_request(
            method=request.method,
            url=req_url,
            headers=forward_headers,
            content=masked_body
        )
        upstream_resp = await client.send(upstream_req, stream=True)

        content_type = upstream_resp.headers.get("content-type", "")

        # 4. Handle Streaming SSE Responses
        if "text/event-stream" in content_type:
            log_shield(f"Streaming SSE response from {target_host}...")
            sse_demasker = SSEStreamDemasker(vault)

            async def sse_generator():
                try:
                    async for chunk_bytes in upstream_resp.aiter_bytes():
                        chunk_str = chunk_bytes.decode("utf-8", errors="replace")
                        demasked_part = sse_demasker.process_raw_chunk(chunk_str)
                        if demasked_part:
                            yield demasked_part.encode("utf-8")

                    final_part = sse_demasker.flush()
                    if final_part:
                        yield final_part.encode("utf-8")
                finally:
                    await upstream_resp.aclose()
                    await client.aclose()

            resp_headers = {
                k: v for k, v in upstream_resp.headers.items()
                if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")
            }
            return StreamingResponse(
                sse_generator(),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type="text/event-stream"
            )

        # 5. Handle Non-Streaming Responses (Normal JSON / Text)
        resp_bytes = await upstream_resp.aread()
        await upstream_resp.aclose()
        await client.aclose()

        resp_text = resp_bytes.decode("utf-8", errors="replace")
        demasked_text, demask_count = vault.demask_text(resp_text)
        if demask_count > 0:
            log_demask(f"Restored {demask_count} secret placeholder(s) in response body!")

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")
        }

        return Response(
            content=demasked_text.encode("utf-8"),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=content_type or "application/json"
        )

    except Exception as e:
        await client.aclose()
        log_warn(f"Proxy error forwarding to {target_url}: {e}")
        raise HTTPException(status_code=502, detail=f"Proxy error: {str(e)}")


@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "ZCode Secret Masking Proxy",
        "vault_secrets_count": len(vault.secret_to_placeholder),
        "registered_placeholders": list(vault.placeholder_to_secret.keys()),
        "upstreams": list(config.get("upstreams", {}).keys()),
        "allowed_hosts": config.get("allowed_hosts", [])
    }


@app.get("/vault/status")
async def vault_status():
    return {
        "count": len(vault.secret_to_placeholder),
        "mappings": [
            {"placeholder": p, "secret_prefix": s[:7] + "..." if len(s) > 10 else "***"}
            for p, s in vault.placeholder_to_secret.items()
        ]
    }


# Universal proxy route: /proxy/https/agentrouter.org/v1/chat/completions
@app.api_route("/proxy/{scheme}/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def universal_proxy(scheme: str, subpath: str, request: Request):
    target_url = resolve_target_url(scheme, subpath)
    return await proxy_request_handler(target_url, request)


# Named upstream route: /{upstream_name}/{subpath:path}
# e.g. /agentrouter/v1/chat/completions
@app.api_route("/{upstream_name}/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def named_upstream_proxy(upstream_name: str, subpath: str, request: Request):
    if upstream_name in config.get("upstreams", {}):
        target_url = resolve_target_url(upstream_name, subpath)
        return await proxy_request_handler(target_url, request)
    raise HTTPException(status_code=404, detail=f"Upstream '{upstream_name}' not found")


if __name__ == "__main__":
    host = config.get("host", "127.0.0.1")
    port = int(config.get("port", 8765))
    print(f"\n{CYAN}{BOLD}=================================================={RESET}")
    print(f"{CYAN}{BOLD}   🛡️  ZCode Secret Masking Proxy v1.0.0   {RESET}")
    print(f"{CYAN}{BOLD}=================================================={RESET}")
    print(f"Server starting on: {GREEN}http://{host}:{port}{RESET}")
    print(f"Registered upstreams: {YELLOW}{list(config.get('upstreams', {}).keys())}{RESET}")
    print(f"Allowed target hosts: {YELLOW}{config.get('allowed_hosts', [])}{RESET}")
    print(f"Vault loaded: {GREEN}{len(vault.secret_to_placeholder)} static secrets{RESET}\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")
