"""
Regression tests: thinking/reasoning symmetry must be scoped by block `type`,
not by generic key names. Run: python -m unittest test_key_scope -v
"""
import json
import unittest

from vault import SecretVault, SSEStreamDemasker

REAL = "sk-REALKEYREALKEYREALKEY123"


def make_vault():
    v = SecretVault(None)
    ph = v.register_secret(REAL, "API_KEY")
    return v, ph


def stream(v, events):
    dm = SSEStreamDemasker(v)
    out = ""
    for ev in events:
        out += dm.process_raw_chunk("data: " + json.dumps(ev) + "\n\n")
    out += dm.flush()
    return [json.loads(l[5:]) for l in out.split("\n")
            if l.startswith("data:") and "[DONE]" not in l]


class MaskGenericKeys(unittest.TestCase):
    """Ordinary dicts must be masked even if keys are named like thinking fields."""

    def test_tool_use_input_data(self):
        v, ph = make_vault()
        body = {"messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "http",
             "input": {"url": "https://x.io", "data": REAL}}]}]}
        out, n = v.mask_payload(body)
        self.assertNotIn(REAL, json.dumps(out))
        self.assertGreaterEqual(n, 1)

    def test_summary_reasoning_thinking_keys(self):
        v, _ = make_vault()
        for key in ("summary", "reasoning", "thinking", "data", "content"):
            out, _ = v.mask_payload({"args": {key: f"token {REAL}"}})
            self.assertNotIn(REAL, json.dumps(out), key)

    def test_dict_with_signature_key_still_masked(self):
        v, _ = make_vault()
        out, _ = v.mask_payload({"payload": {"signature": "abc", "body": f"key {REAL}"}})
        self.assertNotIn(REAL, json.dumps(out))

    def test_reasoning_content_outside_message_is_masked(self):
        v, _ = make_vault()
        out, _ = v.mask_payload({"metadata": {"reasoning_content": f"x {REAL}"}})
        self.assertNotIn(REAL, json.dumps(out))


class DemaskGenericKeys(unittest.TestCase):
    """Client-bound tool calls must receive real values in `data`/`summary` fields."""

    def test_anthropic_tool_use_input_data(self):
        v, ph = make_vault()
        resp = {"content": [{"type": "tool_use", "id": "t", "name": "http",
                             "input": {"data": ph, "summary": ph}}]}
        out = json.loads(v.demask_json_str(json.dumps(resp))[0])
        inp = out["content"][0]["input"]
        self.assertEqual(inp["data"], REAL)
        self.assertEqual(inp["summary"], REAL)

    def test_sse_content_block_start_tool_use(self):
        v, ph = make_vault()
        ev = stream(v, [{"type": "content_block_start", "index": 1,
                         "content_block": {"type": "tool_use", "id": "t", "name": "x",
                                           "input": {"data": ph}}}])
        self.assertEqual(ev[0]["content_block"]["input"]["data"], REAL)

    def test_openai_tool_call_arguments_string(self):
        v, ph = make_vault()
        resp = {"choices": [{"message": {"tool_calls": [{"function": {
            "name": "f", "arguments": json.dumps({"summary": ph})}}]}}]}
        out = json.loads(v.demask_json_str(json.dumps(resp))[0])
        args = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertIn(REAL, args)


class ThinkingSymmetry(unittest.TestCase):
    """Thinking/reasoning blocks: never demasked, never masked -> no leak, signature intact."""

    def test_anthropic_thinking_roundtrip(self):
        v, ph = make_vault()
        resp = {"content": [{"type": "thinking", "thinking": f"use {ph}", "signature": "SIG=="},
                            {"type": "text", "text": f"key {ph}"}]}
        client = json.loads(v.demask_json_str(json.dumps(resp))[0])
        self.assertEqual(client["content"][0]["thinking"], f"use {ph}")
        self.assertEqual(client["content"][0]["signature"], "SIG==")
        self.assertEqual(client["content"][1]["text"], f"key {REAL}")
        upstream, _ = v.mask_payload({"messages": [{"role": "assistant", "content": client["content"]}]})
        self.assertNotIn(REAL, json.dumps(upstream))
        self.assertEqual(upstream["messages"][0]["content"][0]["thinking"], f"use {ph}")

    def test_redacted_thinking_data_untouched(self):
        v, ph = make_vault()
        blk = {"type": "redacted_thinking", "data": f"opaque {ph}"}
        self.assertEqual(v.demask_payload(blk)[0], blk)
        self.assertEqual(v.mask_payload(blk)[0], blk)

    def test_responses_reasoning_item(self):
        v, ph = make_vault()
        item = {"type": "reasoning", "id": "rs_1", "encrypted_content": "ENC",
                "summary": [{"type": "summary_text", "text": f"using {ph}"}],
                "content": [{"type": "reasoning_text", "text": f"also {ph}"}]}
        client = v.demask_payload({"output": [item]})[0]["output"][0]
        self.assertEqual(client, item)
        up = v.mask_payload({"input": [client]})[0]["input"][0]
        self.assertEqual(up, item)
        self.assertNotIn(REAL, json.dumps(up))

    def test_chat_reasoning_content_roundtrip(self):
        v, ph = make_vault()
        resp = {"choices": [{"message": {"role": "assistant",
                                         "reasoning_content": f"use {ph}",
                                         "content": f"key {ph}"}}]}
        client = json.loads(v.demask_json_str(json.dumps(resp))[0])
        msg = client["choices"][0]["message"]
        self.assertEqual(msg["reasoning_content"], f"use {ph}")
        self.assertEqual(msg["content"], f"key {REAL}")
        up, _ = v.mask_payload({"messages": [msg]})
        self.assertNotIn(REAL, json.dumps(up))

    def test_sse_thinking_events_not_demasked(self):
        v, ph = make_vault()
        cases = [
            ({"type": "content_block_delta", "index": 0,
              "delta": {"type": "thinking_delta", "thinking": f"use {ph}"}},
             lambda e: e["delta"]["thinking"]),
            ({"choices": [{"index": 0, "delta": {"reasoning_content": f"use {ph}"}}]},
             lambda e: e["choices"][0]["delta"]["reasoning_content"]),
            ({"type": "response.reasoning_summary_text.delta", "delta": f"use {ph}"},
             lambda e: e["delta"]),
        ]
        for event, getter in cases:
            got = getter(stream(v, [event])[0])
            self.assertEqual(got, f"use {ph}")


if __name__ == "__main__":
    unittest.main()
