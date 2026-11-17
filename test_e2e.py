import asyncio
import json
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import pytest

# Mock Upstream Server
mock_app = FastAPI()
received_payloads = []

@mock_app.post("/v1/responses")
async def mock_responses(request: Request):
    body = await request.json()
    received_payloads.append(body)

    # In ZCode openai-responses, user message is in input or messages
    text = str(body)
    reply_text = f'API_KEY = "{body["input"] if "input" in body else body["messages"][-1]["content"]}"'

    async def event_generator():
        # Stream response.output_text.delta events (ZCode protocol)
        half = len(reply_text) // 2
        p1 = reply_text[:half]
        p2 = reply_text[half:]

        e1 = {"type": "response.output_text.delta", "item_id": "i1", "output_index": 0, "content_index": 0, "delta": p1}
        yield f"data: {json.dumps(e1)}\n\n".encode("utf-8")

        e2 = {"type": "response.output_text.delta", "item_id": "i1", "output_index": 0, "content_index": 0, "delta": p2}
        yield f"data: {json.dumps(e2)}\n\n".encode("utf-8")

        yield b"data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@mock_app.post("/v1/chat/completions")
async def mock_chat(request: Request):
    body = await request.json()
    received_payloads.append(body)

    is_stream = body.get("stream", False)

    # Check if the incoming request contains any placeholder
    messages = body.get("messages", [])
    user_msg = messages[-1].get("content", "")

    # The mock model echoes the user's placeholder in its code reply
    reply_text = f"Here is your code: const mySecret = '{user_msg}';"

    if is_stream:
        async def event_generator():
            # Send in 2 split chunks
            half = len(reply_text) // 2
            chunk1 = reply_text[:half]
            chunk2 = reply_text[half:]

            c1 = {"choices": [{"index": 0, "delta": {"content": chunk1}}]}
            yield f"data: {json.dumps(c1)}\n\n".encode("utf-8")

            c2 = {"choices": [{"index": 0, "delta": {"content": chunk2}}]}
            yield f"data: {json.dumps(c2)}\n\n".encode("utf-8")

            yield b"data: [DONE]\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    return JSONResponse({
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": reply_text
            }
        }]
    })

@mock_app.get("/v1/models")
async def mock_models():
    return {
        "object": "list",
        "data": [{"id": "gpt-4o", "object": "model"}]
    }

async def run_e2e_tests():
    from server import app as proxy_app, vault, config

    # Configure proxy to point 'mock' upstream to our mock server on port 9999
    config["upstreams"]["mock"] = "http://127.0.0.1:9999/v1"
    config["allowed_hosts"].append("127.0.0.1")

    # Start mock upstream server
    server_config = uvicorn.Config(mock_app, host="127.0.0.1", port=9999, log_level="error")
    mock_server = uvicorn.Server(server_config)
    mock_task = asyncio.create_task(mock_server.serve())

    # Wait for mock server to be ready
    await asyncio.sleep(0.5)

    try:
        # Use httpx.AsyncClient with ASGI transport to talk directly to the proxy app
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=proxy_app), base_url="http://127.0.0.1:8765") as client:
            # 1. Test root status
            r = await client.get("/")
            assert r.status_code == 200
            print("✓ [PASS] Proxy root status OK")

            # 2. Test Non-streaming request with real sensitive secret
            secret_token = "sk-live-confidential-secret-9876543210-test"
            payload = {
                "model": "gpt-4o",
                "stream": False,
                "messages": [
                    {"role": "user", "content": secret_token}
                ]
            }

            resp = await client.post("/mock/chat/completions", json=payload)
            assert resp.status_code == 200, f"Status: {resp.status_code}, {resp.text}"
            resp_data = resp.json()

            # Verify: Upstream NEVER saw the real secret
            upstream_received = received_payloads[-1]
            received_user_content = upstream_received["messages"][0]["content"]
            assert secret_token not in received_user_content, "LEAK DETECTED! Real secret reached upstream!"
            assert "__VAULT_" in received_user_content, "Placeholder was not injected into upstream request!"
            print(f"✓ [PASS] Leak prevention confirmed: Upstream received placeholder '{received_user_content}'")

            # Verify: Client got back the real secret restored
            reply_content = resp_data["choices"][0]["message"]["content"]
            assert secret_token in reply_content, "Secret was not restored in non-streaming response!"
            print(f"✓ [PASS] Secret restoration confirmed in non-streaming response: '{reply_content}'")

            # 3. Test Streaming request (chat/completions)
            payload_stream = {
                "model": "gpt-4o",
                "stream": True,
                "messages": [
                    {"role": "user", "content": secret_token}
                ]
            }
            resp_stream = await client.post("/mock/chat/completions", json=payload_stream)
            assert resp_stream.status_code == 200
            stream_body = resp_stream.text

            # Parse stream delta content
            client_received_stream_content = ""
            for line in stream_body.splitlines():
                line = line.strip()
                if line.startswith("data:") and line != "data: [DONE]":
                    data = json.loads(line[5:].strip())
                    for c in data.get("choices", []):
                        delta = c.get("delta", {})
                        if "content" in delta:
                            client_received_stream_content += delta["content"]

            assert secret_token in client_received_stream_content, "Secret was not restored in streaming SSE response!"
            print(f"✓ [PASS] Secret restoration confirmed in streaming SSE response: '{client_received_stream_content}'")

            # 3b. Test ZCode /v1/responses format (openai-responses protocol)
            resp_responses = await client.post("/mock/responses", json=payload_stream)
            assert resp_responses.status_code == 200
            responses_body = resp_responses.text

            zcode_received_delta = ""
            for line in responses_body.splitlines():
                line = line.strip()
                if line.startswith("data:") and line != "data: [DONE]":
                    data = json.loads(line[5:].strip())
                    if "delta" in data and isinstance(data["delta"], str):
                        zcode_received_delta += data["delta"]

            assert secret_token in zcode_received_delta, "Secret was not restored in ZCode responses stream!"
            print(f"✓ [PASS] ZCode /v1/responses stream restoration confirmed: '{zcode_received_delta}'")

            # 4. Test Domain Binding (Blocking unallowed hosts)
            r_blocked = await client.post("/proxy/https/evil-attacker.com/v1/chat/completions", json=payload)
            assert r_blocked.status_code == 403, f"Expected 403 Forbidden, got {r_blocked.status_code}"
            print("✓ [PASS] Domain binding protection confirmed: Unregistered host blocked with 403 Forbidden")

        print("\n🎉 ALL E2E INTEGRATION TESTS PASSED SUCCESSFULLY!")

    finally:
        mock_server.should_exit = True
        await mock_task

if __name__ == "__main__":
    asyncio.run(run_e2e_tests())
