import unittest
import json
from vault import SecretVault, SSEStreamDemasker

class TestVaultMasking(unittest.TestCase):
    def setUp(self):
        self.vault = SecretVault()
        # Register a known secret
        self.vault.register_secret("sk-live-1234567890abcdef1234567890abcdef", "OPENAI")
        self.vault.register_secret("ghp_myfakepersonalaccesstoken123456789", "GITHUB")

    def test_known_secret_masking(self):
        text = "My OpenAI key is sk-live-1234567890abcdef1234567890abcdef and it works."
        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn("sk-live-1234567890abcdef1234567890abcdef", masked)
        self.assertIn("__VAULT_OPENAI_", masked)

        # Restore
        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_dynamic_pattern_masking(self):
        # A new key that wasn't registered in advance
        unknown_key = "sk-ant-api03-abcdef1234567890abcdef1234567890-test"
        text = f"const client = new Anthropic({{ apiKey: '{unknown_key}' }});"

        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn(unknown_key, masked)
        self.assertIn("__VAULT_API_KEY_", masked)

        # Demask
        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_json_payload_masking(self):
        payload = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helper."},
                {"role": "user", "content": "Here is my token: ghp_myfakepersonalaccesstoken123456789. Please use it."}
            ]
        }
        masked_payload, count = self.vault.mask_payload(payload)
        self.assertEqual(count, 1)
        self.assertNotIn("ghp_myfakepersonalaccesstoken123456789", masked_payload["messages"][1]["content"])
        self.assertIn("__VAULT_GITHUB_", masked_payload["messages"][1]["content"])

    def test_streaming_demasker_split_chunks(self):
        # Simulate LLM generating the placeholder across multiple SSE delta chunks
        placeholder = self.vault.secret_to_placeholder["sk-live-1234567890abcdef1234567890abcdef"]
        real_key = "sk-live-1234567890abcdef1234567890abcdef"

        half = len(placeholder) // 2
        p1 = placeholder[:half]
        p2 = placeholder[half:]

        demasker = SSEStreamDemasker(self.vault)

        # Chunk 1: starts placeholder in delta content
        chunk1 = f'data: {{"choices": [{{"index": 0, "delta": {{"content": "const key = \'{p1}"}}}}]}}\n\n'
        # Chunk 2: finishes placeholder in delta content
        chunk2 = f'data: {{"choices": [{{"index": 0, "delta": {{"content": "{p2}\';"}}}}]}}\n\n'
        # Chunk 3: [DONE]
        chunk3 = "data: [DONE]\n\n"

        out1 = demasker.process_raw_chunk(chunk1)
        out2 = demasker.process_raw_chunk(chunk2)
        out3 = demasker.process_raw_chunk(chunk3)
        out_final = demasker.flush()

        full_output = out1 + out2 + out3 + out_final

        # Parse all emitted SSE chunks and concatenate the delta content as a client would
        assembled_content = ""
        for line in full_output.splitlines():
            line = line.strip()
            if line.startswith("data:") and line != "data: [DONE]":
                try:
                    payload = json.loads(line[5:].strip())
                    for choice in payload.get("choices", []):
                        delta = choice.get("delta", {})
                        if "content" in delta:
                            assembled_content += delta["content"]
                except Exception:
                    pass

        # The client receives the complete reconstructed secret
        self.assertIn(real_key, assembled_content)
        self.assertEqual(assembled_content, f"const key = '{real_key}';")


if __name__ == "__main__":
    unittest.main()
