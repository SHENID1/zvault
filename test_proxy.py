import unittest
import json
from vault import SecretVault, SSEStreamDemasker

class TestVaultMasking(unittest.TestCase):
    def setUp(self):
        self.vault = SecretVault()
        self.vault.register_secret("sk-live-1234567890abcdef1234567890abcdef", "OPENAI")
        self.vault.register_secret("ghp_myfakepersonalaccesstoken123456789", "GITHUB")

    def test_known_secret_masking(self):
        text = "My OpenAI key is sk-live-1234567890abcdef1234567890abcdef and it works."
        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn("sk-live-1234567890abcdef1234567890abcdef", masked)
        self.assertIn("__VAULT_OPENAI_", masked)

        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_dynamic_pattern_masking(self):
        unknown_key = "sk-ant-api03-abcdef1234567890abcdef1234567890-test"
        text = f"const authHeader = 'Bearer {unknown_key}';"

        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn(unknown_key, masked)
        self.assertIn("__VAULT_ANTHROPIC_KEY_", masked)

        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_smart_scanner_assignment_context(self):
        # Secret without any well-known prefix, but assigned to a sensitive variable
        custom_pwd = "MySuperSecretPassword99!"
        text = f'const DB_PASSWORD = "{custom_pwd}";'

        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn(custom_pwd, masked)
        self.assertIn("__VAULT_DB_PASSWORD_", masked)

        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_smart_scanner_shannon_entropy(self):
        # A raw random key without any prefix (like LZ0Z0rE1WyLbqLZGgp51OcEcHCHegk5BCkJMw6U5tvb3KXWS)
        raw_key = "LZ0Z0rE1WyLbqLZGgp51OcEcHCHegk5BCkJMw6U5tvb3KXWS"
        text = f"Here is the token: {raw_key} use it."

        masked, count = self.vault.mask_text(text)
        self.assertEqual(count, 1)
        self.assertNotIn(raw_key, masked)
        self.assertIn("__VAULT_ENTROPY_KEY_", masked)

        restored, demask_count = self.vault.demask_text(masked)
        self.assertEqual(demask_count, 1)
        self.assertEqual(restored, text)

    def test_openai_responses_sse_streaming(self):
        # Exact format used by ZCode with api.type == "openai-responses"!
        placeholder = self.vault.secret_to_placeholder["sk-live-1234567890abcdef1234567890abcdef"]
        real_key = "sk-live-1234567890abcdef1234567890abcdef"

        half = len(placeholder) // 2
        p1 = placeholder[:half]
        p2 = placeholder[half:]

        demasker = SSEStreamDemasker(self.vault)

        # Event 1: response.output_text.delta with split placeholder
        event1 = f'data: {{"type": "response.output_text.delta", "item_id": "item_1", "output_index": 0, "content_index": 0, "delta": "API_KEY = \\"{p1}"}}\n\n'
        # Event 2: response.output_text.delta finishing placeholder
        event2 = f'data: {{"type": "response.output_text.delta", "item_id": "item_1", "output_index": 0, "content_index": 0, "delta": "{p2}\\"\\nprint(API_KEY)"}}\n\n'
        # Event 3: [DONE]
        event3 = "data: [DONE]\n\n"

        out1 = demasker.process_raw_chunk(event1)
        out2 = demasker.process_raw_chunk(event2)
        out3 = demasker.process_raw_chunk(event3)
        out_final = demasker.flush()

        full_output = out1 + out2 + out3 + out_final

        assembled_delta = ""
        for line in full_output.splitlines():
            line = line.strip()
            if line.startswith("data:") and line != "data: [DONE]":
                payload = json.loads(line[5:].strip())
                if "delta" in payload and isinstance(payload["delta"], str):
                    assembled_delta += payload["delta"]

        self.assertNotIn(placeholder, assembled_delta)
        self.assertIn(real_key, assembled_delta)
        self.assertEqual(assembled_delta, f'API_KEY = "{real_key}"\nprint(API_KEY)')


if __name__ == "__main__":
    unittest.main()
