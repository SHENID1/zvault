import json
import os
import re
import sys
import hmac
import codecs
import secrets
import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from typing import Dict, Any, Optional

# Ensure sys.stdout and sys.stderr are valid when running in background under pythonw
if sys.stdout is None or sys.stderr is None:
    try:
        _log_f = open(os.path.join(os.path.dirname(__file__), "proxy.log"), "a", encoding="utf-8", buffering=1)
    except Exception:
        _log_f = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = _log_f
    if sys.stderr is None:
        sys.stderr = _log_f

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import uvicorn

from vault import SecretVault, SSEStreamDemasker
from injection_guard import PromptInjectionGuard, InjectionResult

# ANSI Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Load config
PROXY_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROXY_DIR, "config.json")
TOKEN_FILE = os.path.join(PROXY_DIR, ".vault_token")
DEFAULT_CONFIG_TOKEN_PREFIX = "zvault_sec_local_d98f"

# Async lock for safe serialized file persistence
file_write_lock = asyncio.Lock()
MAX_BODY_SIZE = 20 * 1024 * 1024  # 20 MB max body size to protect against DoS

config: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8765,
    "upstreams": {
        "agentrouter": "https://agentrouter.org/v1",
        "bigmodel": "https://open.bigmodel.cn/api/paas/v4"
    },
    "allowed_hosts": [
        "agentrouter.org",
        "open.bigmodel.cn",
        "api.openai.com",
        "api.anthropic.com"
    ],
    "secrets_file": "secrets.json"
}

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    except Exception as e:
        print(f"[WARN] Error reading config.json: {e}")


def get_or_generate_vault_token() -> str:
    """
    Retrieves or generates a secure random vault token.
    Priority:
    1. .vault_token file (git-ignored, 0o600)
    2. config.json ("vault_token")
    3. Generate new random token and save to .vault_token with 0o600 atomically.
    """
    # 1. Check .vault_token
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                saved = f.read().strip()
                if saved:
                    return saved
        except Exception:
            pass

    # 2. Check config.json
    cfg_token = config.get("vault_token")
    if cfg_token and not cfg_token.startswith(DEFAULT_CONFIG_TOKEN_PREFIX):
        return cfg_token

    # 3. Generate a strong unique token and create file with 0o600 atomically
    new_token = f"zv_{secrets.token_hex(24)}"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        if sys.platform != "win32":
            fd = os.open(TOKEN_FILE, flags, mode)
            with open(fd, "w", encoding="utf-8") as f:
                f.write(new_token)
        else:
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(new_token)
    except Exception as e:
        print(f"[WARN] Failed to write .vault_token file: {e}")

    return new_token


CURRENT_VAULT_TOKEN = get_or_generate_vault_token()

# Initialize Vault & Injection Guard
secrets_path = os.path.join(PROXY_DIR, config.get("secrets_file", "secrets.json"))
state_file_path = os.path.join(PROXY_DIR, config.get("state_file", ".vault_state.json"))
raw_env_files = config.get("env_files", [".env"])
env_files = [
    ef if os.path.isabs(ef) else os.path.normpath(os.path.join(PROXY_DIR, ef))
    for ef in raw_env_files
]
state_ttl = int(config.get("state_ttl", 86400))
vault = SecretVault(secrets_path, env_files=env_files, state_file=state_file_path, state_ttl=state_ttl)
vault.on_demask = lambda ph, sec: log_demask(f"Restored placeholder {ph} in response stream!")

injection_cfg = config.get("injection_guard", {"enabled": True, "action": "block", "sensitivity": 0.65})
injection_guard = PromptInjectionGuard(sensitivity=float(injection_cfg.get("sensitivity", 0.65)))


async def periodic_cleanup():
    while True:
        try:
            await asyncio.sleep(60)
            await asyncio.to_thread(vault.cleanup_expired)
        except asyncio.CancelledError:
            break
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(timeout=180.0, follow_redirects=False)
    cleanup_task = asyncio.create_task(periodic_cleanup())
    yield
    cleanup_task.cancel()
    await app.state.client.aclose()


app = FastAPI(title="ZCode Secret Masking Proxy", version="1.1.1", lifespan=lifespan)


def log_shield(msg: str):
    print(f"{CYAN}{BOLD}[SHIELD]{RESET} {msg}")

def log_mask(msg: str):
    print(f"{YELLOW}{BOLD}[MASK 🔒]{RESET} {msg}")

def log_demask(msg: str):
    print(f"{GREEN}{BOLD}[DEMASK 🔓]{RESET} {msg}")

def log_warn(msg: str):
    print(f"{RED}{BOLD}[WARN ⚠️]{RESET} {msg}")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1. Host header & DNS rebinding protection (supports IPv6 brackets e.g. [::1]:8765)
    host_header = request.headers.get("host", "").strip()
    if host_header.startswith("["):
        req_host = host_header.split("]")[0].strip("[").lower()
    else:
        req_host = host_header.split(":")[0].strip().lower()

    configured_host = str(config.get("host", "127.0.0.1")).lower().strip("[]")
    allowed_server_hosts = {"127.0.0.1", "localhost", "::1", "testserver", configured_host}

    if req_host not in allowed_server_hosts:
        return Response(
            content="Forbidden: Invalid Host header (DNS rebinding protection)",
            status_code=403
        )

    # 2. CSRF & Cross-Origin browser protection (Sec-Fetch-Site and Origin header checks)
    sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if sec_fetch_site in ("cross-site", "same-site"):
        return Response(content="Forbidden: Browser cross-origin request rejected", status_code=403)

    origin = request.headers.get("origin")
    if origin:
        parsed_origin = urlparse(origin)
        orig_host = (parsed_origin.hostname or "").lower().strip("[]")
        orig_port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
        configured_port = int(config.get("port", 8765))

        # Reject any cross-origin request from different ports (e.g. localhost:3000) or untrusted hosts
        if orig_host not in allowed_server_hosts or orig_port != configured_port:
            return Response(content="Forbidden: Cross-origin request blocked (origin/port mismatch)", status_code=403)

    return await call_next(request)


def verify_vault_token(request: Request):
    """
    Authenticates requests to management and test endpoints (/vault/*, /test-echo)
    using constant-time comparison to prevent timing attacks.
    """
    token = request.headers.get("X-Vault-Token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized: valid X-Vault-Token required")

    try:
        is_valid = hmac.compare_digest(token.encode("utf-8"), CURRENT_VAULT_TOKEN.encode("utf-8"))
    except Exception:
        is_valid = False

    if not is_valid:
        raise HTTPException(status_code=401, detail="Unauthorized: valid X-Vault-Token required")


def check_domain_allowed(target_url: str) -> bool:
    """
    Validates target URL:
    - Rejects credentials (userinfo) in authority
    - Enforces https:// scheme (except for local testing on 127.0.0.1/localhost)
    - Validates target hostname format strictly against regex [a-zA-Z0-9.-]+
    - Matches hostname against explicit allowed_hosts whitelist
    """
    parsed = urlparse(target_url)
    if parsed.username or parsed.password:
        log_warn(f"Target URL '{target_url}' contains credentials in authority! Request blocked.")
        return False

    scheme = (parsed.scheme or "").lower()
    target_host = (parsed.hostname or "").lower()

    if not target_host or not re.match(r"^[a-z0-9.-]+$", target_host):
        log_warn(f"Invalid target hostname format: '{target_host}'")
        return False

    # Disallow unencrypted http:// for external upstreams
    if scheme != "https" and target_host not in ("127.0.0.1", "localhost"):
        log_warn(f"Unencrypted HTTP upstream disallowed for security: '{target_url}'")
        return False

    allowed = config.get("allowed_hosts", [])
    if not allowed:
        return False

    return any(target_host == a.lower() or target_host.endswith("." + a.lower()) for a in allowed)


def resolve_target_url(upstream_name_or_scheme: str, subpath: str) -> str:
    upstreams = config.get("upstreams", {})

    if upstream_name_or_scheme in upstreams:
        base_url = upstreams[upstream_name_or_scheme].rstrip("/")
        subpath = subpath.lstrip("/")

        if base_url.endswith("/v1") and subpath.startswith("v1/"):
            subpath = subpath[3:]

        return f"{base_url}/{subpath}" if subpath else base_url

    if upstream_name_or_scheme in ("http", "https"):
        scheme = upstream_name_or_scheme
        return f"{scheme}://{subpath}"

    raise HTTPException(status_code=400, detail=f"Unknown upstream or scheme: {upstream_name_or_scheme}")


def process_multipart_payload(
    raw_body: bytes,
    content_type: str,
    vault: SecretVault,
    guard: PromptInjectionGuard,
    injection_cfg: dict,
    target_host: str
) -> bytes:
    """
    Parses multipart/form-data payload, scans textual parts/files for prompt injection,
    and masks secrets with placeholders, preserving binary parts (images/audio) intact.
    Fails closed if the multipart structure is malformed.
    """
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.IGNORECASE)
    if not m:
        raise HTTPException(status_code=400, detail="Invalid multipart/form-data: missing boundary")

    boundary_str = m.group(1) or m.group(2)
    boundary_marker = b"--" + boundary_str.encode("latin-1")

    parts = raw_body.split(boundary_marker)
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid multipart/form-data: malformed parts")

    new_parts = []
    total_masked = 0

    for idx, part in enumerate(parts):
        # Preamble or closing delimiter
        if idx == 0 and part.strip() == b"":
            new_parts.append(part)
            continue
        if part.strip() == b"--" or part.startswith(b"--\r\n") or part.startswith(b"--\n"):
            new_parts.append(part)
            continue

        sep = b"\r\n\r\n" if b"\r\n\r\n" in part else (b"\n\n" if b"\n\n" in part else None)
        if not sep:
            new_parts.append(part)
            continue

        header_bytes, body_bytes = part.split(sep, 1)

        # Check for binary data (null bytes in the payload)
        if b"\x00" in body_bytes[:1024]:
            new_parts.append(part)
            continue

        try:
            body_text = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Binary part, pass through unmodified
            new_parts.append(part)
            continue

        # Scan textual part for prompt injections
        if injection_cfg.get("enabled", True):
            inj_res = guard.scan_text(body_text)
            if inj_res.is_malicious:
                action = injection_cfg.get("action", "block").lower()
                if action == "block":
                    log_warn(f"🛑 BLOCKED PROMPT INJECTION in multipart file/field! Risk: {inj_res.risk_score}")
                    raise HTTPException(
                        status_code=400,
                        detail=f"Request blocked by ZVault Prompt Injection Guard (multipart): {inj_res.category}"
                    )
                else:
                    log_warn(f"🚨 SUSPICIOUS PROMPT INJECTION in multipart! Risk: {inj_res.risk_score}")

        # Mask secrets in textual part
        masked_text, count = vault.mask_text(body_text)
        if count > 0:
            total_masked += count
            new_parts.append(header_bytes + sep + masked_text.encode("utf-8"))
        else:
            new_parts.append(part)

    if total_masked > 0:
        log_mask(f"Replaced {total_masked} secret(s) in multipart payload before sending to {target_host}")

    return boundary_marker.join(new_parts)


async def proxy_request_handler(target_url: str, request: Request) -> Response:
    # Optional authorization on proxy routes
    if config.get("require_proxy_token", False):
        verify_vault_token(request)

    # Strip URL fragment if present
    target_url = target_url.split("#")[0]
    safe_target_url = target_url.split("?")[0]
    parsed = urlparse(target_url)
    target_host = parsed.netloc

    if not check_domain_allowed(target_url):
        log_warn(f"Target URL '{safe_target_url}' is NOT in allowed_hosts list! Request blocked for security.")
        raise HTTPException(status_code=403, detail="Target host not in allowed_hosts or invalid")

    log_shield(f"{request.method} -> {safe_target_url}")

    # Enforce cleanup of expired dynamic secrets
    await asyncio.to_thread(vault.cleanup_expired)

    # Enforce request body size limit to protect from DoS / memory exhaustion
    cl_header = request.headers.get("content-length")
    if cl_header:
        try:
            if int(cl_header) > MAX_BODY_SIZE:
                raise HTTPException(status_code=413, detail="Payload Too Large: request body exceeds 20MB limit")
        except ValueError:
            pass

    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_SIZE:
        raise HTTPException(status_code=413, detail="Payload Too Large: request body exceeds 20MB limit")

    masked_body = raw_body

    req_ct = request.headers.get("content-type", "").lower()
    is_multipart = req_ct.startswith("multipart/")
    is_binary = (
        req_ct.startswith(("image/", "audio/", "video/"))
        or req_ct == "application/pdf"
    )

    if raw_body and not is_multipart and not is_binary:
        try:
            body_text = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            # FAIL-CLOSED: Non-binary payload failing UTF-8 decoding is rejected (prevents unmasked leaks via UTF-16, Latin-1, etc.)
            raise HTTPException(
                status_code=400,
                detail="Invalid request body: expected valid UTF-8 textual payload"
            )

        try:
            body_json = json.loads(body_text)

            # Deep-scan entire payload for prompt injections & jailbreaks in background worker thread
            if injection_cfg.get("enabled", True):
                block_tr = bool(injection_cfg.get("block_tool_results", False))
                inj_res = await asyncio.to_thread(
                    injection_guard.scan_payload, body_json, block_tool_results=block_tr
                )
                if inj_res.is_malicious:
                    action = injection_cfg.get("action", "block").lower()
                    if action == "block" and inj_res.should_block:
                        log_warn(f"🛑 BLOCKED PROMPT INJECTION! Risk: {inj_res.risk_score}, Category: {inj_res.category}, Matches: {inj_res.matched_patterns} (Source: {inj_res.source})")
                        raise HTTPException(status_code=400, detail=f"Request blocked by ZVault Prompt Injection Guard: {inj_res.category}")
                    else:
                        log_warn(f"🚨 SUSPICIOUS PROMPT INJECTION (Warning only)! Risk: {inj_res.risk_score}, Category: {inj_res.category}, Matches: {inj_res.matched_patterns} (Source: {inj_res.source})")

            masked_json, count = await asyncio.to_thread(vault.mask_payload, body_json)
            if count > 0:
                log_mask(f"Replaced {count} secret(s) with placeholders before sending to {target_host}")
            masked_body = json.dumps(masked_json, ensure_ascii=False).encode("utf-8")
        except HTTPException:
            raise
        except Exception:
            try:
                masked_str, count = await asyncio.to_thread(vault.mask_text, body_text)
                if count > 0:
                    log_mask(f"Replaced {count} secret(s) in raw text before sending to {target_host}")
                masked_body = masked_str.encode("utf-8")
            except Exception as ex:
                log_warn(f"Masking pipeline failed: {ex}")
                raise HTTPException(
                    status_code=500,
                    detail="Masking pipeline failure: refusing to forward potentially unmasked payload"
                )
    elif raw_body and is_multipart:
        masked_body = await asyncio.to_thread(
            process_multipart_payload, raw_body, req_ct, vault, injection_guard, injection_cfg, target_host
        )

    # 2. Prepare headers (strip internal and hop-by-hop headers)
    forward_headers = {}
    strip_hdrs = {
        "host", "content-length", "connection", "accept-encoding",
        "x-vault-token", "te", "upgrade", "keep-alive", "proxy-authenticate", "proxy-authorization"
    }
    for k, v in request.headers.items():
        if k.lower() not in strip_hdrs:
            forward_headers[k] = v

    forward_headers["Host"] = parsed.hostname or target_host

    # 3. Forward request to upstream
    client: httpx.AsyncClient = getattr(request.app.state, "client", None)
    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=180.0, follow_redirects=False)
        own_client = True

    try:
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
                decoder = codecs.getincrementaldecoder("utf-8")()
                try:
                    async for chunk_bytes in upstream_resp.aiter_bytes():
                        chunk_str = decoder.decode(chunk_bytes, final=False)
                        if chunk_str:
                            demasked_part = sse_demasker.process_raw_chunk(chunk_str)
                            if demasked_part:
                                yield demasked_part.encode("utf-8")

                    final_str = decoder.decode(b"", final=True)
                    if final_str:
                        demasked_part = sse_demasker.process_raw_chunk(final_str)
                        if demasked_part:
                            yield demasked_part.encode("utf-8")

                    final_part = sse_demasker.flush()
                    if final_part:
                        yield final_part.encode("utf-8")
                finally:
                    await upstream_resp.aclose()
                    if own_client:
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

        # 5. Handle Non-Streaming Responses (Normal JSON / Text vs Binary Images/Audio/Files)
        try:
            resp_bytes = await upstream_resp.aread()
        finally:
            await upstream_resp.aclose()
            if own_client:
                await client.aclose()

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")
        }

        # Check if content type is textual or JSON
        resp_ct = (upstream_resp.headers.get("content-type") or "").lower()
        is_textual = (
            "json" in resp_ct
            or any(t in resp_ct for t in ("text/", "xml", "javascript", "yaml", "csv"))
            or (not resp_ct and (resp_bytes.startswith(b"{") or resp_bytes.startswith(b"[") or b"\x00" not in resp_bytes[:1024]))
        )

        if not is_textual:
            # Pass raw binary content (images, audio, downloads) untouched
            return Response(
                content=resp_bytes,
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type=upstream_resp.headers.get("content-type")
            )

        resp_text = resp_bytes.decode("utf-8", errors="replace")
        demasked_text, demask_count = await asyncio.to_thread(vault.demask_json_str, resp_text)
        if demask_count > 0:
            log_demask(f"Restored {demask_count} secret placeholder(s) in response body!")

        return Response(
            content=demasked_text.encode("utf-8"),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=content_type or "application/json"
        )

    except HTTPException:
        raise
    except Exception as e:
        if own_client:
            await client.aclose()
        log_warn(f"Proxy error forwarding to {safe_target_url}: {e}")
        raise HTTPException(status_code=502, detail=f"Proxy error: {str(e)}")


@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "ZCode Secret Masking Proxy",
        "upstreams": list(config.get("upstreams", {}).keys()),
        "allowed_hosts": config.get("allowed_hosts", [])
    }


@app.get("/vault/status")
async def vault_status(request: Request):
    verify_vault_token(request)
    return {
        "count": len(vault.secret_to_placeholder),
        "env_files": config.get("env_files", []),
        "placeholders": list(vault.placeholder_to_secret.keys())
    }


@app.post("/vault/add-secret")
async def add_secret_endpoint(request: Request):
    verify_vault_token(request)
    data = await request.json()
    secret = data.get("secret", "").strip()
    label = data.get("label", "").strip() or None

    if not secret:
        raise HTTPException(status_code=400, detail="Secret string cannot be empty")

    already_existed = secret in vault.secret_to_placeholder
    placeholder = vault.register_secret(secret, label)

    async with file_write_lock:
        try:
            stored = {}
            if os.path.exists(secrets_path):
                with open(secrets_path, "r", encoding="utf-8") as f:
                    stored = json.load(f)
            stored[placeholder] = secret
            tmp_sec = f"{secrets_path}.tmp_{os.getpid()}"
            with open(tmp_sec, "w", encoding="utf-8") as f:
                json.dump(stored, f, indent=2, ensure_ascii=False)
            if hasattr(os, "chmod") and sys.platform != "win32":
                try:
                    os.chmod(tmp_sec, 0o600)
                except Exception:
                    pass
            os.replace(tmp_sec, secrets_path)
        except Exception as e:
            log_warn(f"Failed to persist secret to secrets.json: {e}")

    log_shield(f"Registered secret string -> {placeholder} (Existing: {already_existed})")

    return {
        "status": "ok",
        "placeholder": placeholder,
        "already_existed": already_existed,
        "total_vault_secrets": len(vault.secret_to_placeholder)
    }


@app.post("/vault/add-env")
async def add_env_endpoint(request: Request):
    verify_vault_token(request)
    data = await request.json()
    raw_path = str(data.get("path", "")).strip()

    if not raw_path:
        raise HTTPException(status_code=400, detail="Missing 'path' in body")

    path = raw_path if os.path.isabs(raw_path) else os.path.normpath(os.path.join(PROXY_DIR, raw_path))

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    loaded_count = vault.load_env_file(path)

    async with file_write_lock:
        try:
            disk_config = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    disk_config = json.load(f)
            env_list = disk_config.setdefault("env_files", [])
            if path not in env_list and raw_path not in env_list:
                env_list.append(path)
                tmp_cfg = f"{CONFIG_FILE}.tmp_{os.getpid()}_{time.time_ns()}"
                with open(tmp_cfg, "w", encoding="utf-8") as f:
                    json.dump(disk_config, f, indent=2, ensure_ascii=False)
                if hasattr(os, "chmod") and sys.platform != "win32":
                    try:
                        os.chmod(tmp_cfg, 0o600)
                    except Exception:
                        pass
                os.replace(tmp_cfg, CONFIG_FILE)
            config.setdefault("env_files", []).append(path)
        except Exception as e:
            log_warn(f"Failed to update config.json: {e}")

    log_shield(f"Dynamically registered .env: {path} (+{loaded_count} secrets)")
    return {
        "status": "ok",
        "path": path,
        "loaded_secrets": loaded_count,
        "total_vault_secrets": len(vault.secret_to_placeholder)
    }


@app.post("/test-echo")
async def test_echo(request: Request):
    verify_vault_token(request)
    raw_body = await request.body()
    try:
        body_json = json.loads(raw_body.decode("utf-8"))
        inj_res = await asyncio.to_thread(injection_guard.scan_payload, body_json)

        masked_json, mask_count = await asyncio.to_thread(vault.mask_payload, body_json)
        _, demask_count = await asyncio.to_thread(vault.demask_payload, masked_json)

        return {
            "status": "success",
            "secrets_detected": mask_count,
            "prompt_injection_guard": {
                "is_malicious": inj_res.is_malicious,
                "risk_score": inj_res.risk_score,
                "category": inj_res.category,
                "matched_patterns": inj_res.matched_patterns,
                "has_obfuscation": inj_res.has_obfuscation
            },
            "1_what_untrusted_api_sees": masked_json,
            "2_demask_verified": True,
            "restorable_placeholders_count": demask_count
        }
    except Exception as e:
        return {"error": str(e)}


@app.api_route("/proxy/{scheme}/{subpath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def universal_proxy(scheme: str, subpath: str, request: Request):
    target_url = resolve_target_url(scheme, subpath)
    return await proxy_request_handler(target_url, request)


@app.api_route("/{upstream_name}/{subpath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def named_upstream_proxy(upstream_name: str, subpath: str, request: Request):
    if upstream_name in config.get("upstreams", {}):
        target_url = resolve_target_url(upstream_name, subpath)
        return await proxy_request_handler(target_url, request)
    raise HTTPException(status_code=404, detail=f"Upstream '{upstream_name}' not found")


if __name__ == "__main__":
    host = config.get("host", "127.0.0.1")
    port = int(config.get("port", 8765))
    print(f"\n{CYAN}{BOLD}=================================================={RESET}")
    print(f"{CYAN}{BOLD}   🛡️  ZCode Secret Masking Proxy v1.1.1   {RESET}")
    print(f"{CYAN}{BOLD}=================================================={RESET}")
    print(f"Server starting on: {GREEN}http://{host}:{port}{RESET}")
    print(f"Registered upstreams: {YELLOW}{list(config.get('upstreams', {}).keys())}{RESET}")
    print(f"Allowed target hosts: {YELLOW}{config.get('allowed_hosts', [])}{RESET}")
    print(f"Vault loaded: {GREEN}{len(vault.secret_to_placeholder)} static secrets{RESET}\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")
