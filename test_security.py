import unittest
import json
from fastapi.testclient import TestClient
from server import app, config, CURRENT_VAULT_TOKEN


class TestServerSecurity(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app, base_url="http://127.0.0.1:8765")
        self.token = CURRENT_VAULT_TOKEN

    def test_dns_rebinding_forbidden(self):
        """Host header not matching localhost/127.0.0.1 must be rejected with 403."""
        resp = self.client.get("/", headers={"Host": "evil-attacker.com"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("DNS rebinding", resp.text)

    def test_dns_rebinding_allowed(self):
        """Localhost and 127.0.0.1 must be accepted."""
        resp = self.client.get("/", headers={"Host": "127.0.0.1:8765"})
        self.assertEqual(resp.status_code, 200)

    def test_vault_status_requires_auth(self):
        """Endpoints under /vault/* must reject unauthenticated requests with 401."""
        resp_unauth = self.client.get("/vault/status")
        self.assertEqual(resp_unauth.status_code, 401)

        resp_auth = self.client.get("/vault/status", headers={"X-Vault-Token": self.token})
        self.assertEqual(resp_auth.status_code, 200)

    def test_test_echo_requires_auth_and_no_plain_secrets(self):
        """
        /test-echo must require auth and must NOT return unmasked plaintext secrets.
        """
        body = {"messages": [{"role": "user", "content": "sk-test-secret-value-1234567890abcdef"}]}

        resp_unauth = self.client.post("/test-echo", json=body)
        self.assertEqual(resp_unauth.status_code, 401)

        resp_auth = self.client.post("/test-echo", json=body, headers={"X-Vault-Token": self.token})
        self.assertEqual(resp_auth.status_code, 200)
        data = resp_auth.json()
        self.assertTrue(data.get("2_demask_verified"))
        self.assertNotIn("2_what_zcode_receives_back", data)

    def test_whitelist_rejection(self):
        """Requests to unlisted hosts must be blocked with 403."""
        resp = self.client.post("/proxy/https/untrusted-malicious-site.com/v1/chat/completions", json={})
        self.assertEqual(resp.status_code, 403)

    def test_userinfo_in_url_rejected(self):
        """Requests with credentials in target URL authority must be blocked."""
        resp = self.client.post("/proxy/https/user:password@agentrouter.org/v1/chat/completions", json={})
        self.assertEqual(resp.status_code, 403)

    def test_insecure_http_rejected(self):
        """Plain http:// to external upstreams must be rejected with 403."""
        resp = self.client.post("/proxy/http/agentrouter.org/v1/chat/completions", json={})
        self.assertEqual(resp.status_code, 403)

    def test_invalid_hostname_format_rejected(self):
        """Malformed hostnames like evil.com\\.agentrouter.org must be rejected."""
        resp = self.client.post("/proxy/https/evil.com\\.agentrouter.org/v1/chat/completions", json={})
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
