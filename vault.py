import re
import json
import os
import math
from collections import Counter
from typing import Dict, List, Tuple, Any, Optional, Callable


def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy for string s."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Non-sensitive environment variable names to ignore when loading .env
IGNORE_ENV_KEYS = {
    "NODE_ENV", "PORT", "HOST", "DEBUG", "LOG_LEVEL", "ENV", "ENVIRONMENT",
    "PUBLIC_URL", "APP_ENV", "MODE", "BROWSER", "HTTPS", "TZ", "LANG", "CI",
    "PATH", "SHELL", "USER", "HOME", "HOSTNAME"
}


class SecretVault:
    def __init__(self, secrets_file: Optional[str] = None, env_files: Optional[List[str]] = None):
        self.secrets_file = secrets_file
        self.secret_to_placeholder: Dict[str, str] = {}
        self.placeholder_to_secret: Dict[str, str] = {}
        self._next_id = 1
        self.on_demask: Optional[Callable[[str, str], None]] = None
        self.on_mask: Optional[Callable[[str, str], None]] = None

        # Signatures for well-known API formats (more specific patterns first)
        self.signature_patterns = [
            # SSH Private Keys (OpenSSH, RSA, DSA, EC, ED25519)
            (r"(-----BEGIN (?:OPENSSH|RSA|DSA|EC|ECDSA|ED25519) PRIVATE KEY-----[\s\S]+?-----END (?:OPENSSH|RSA|DSA|EC|ECDSA|ED25519) PRIVATE KEY-----)", "SSH_PRIV_KEY"),
            # General Private Keys
            (r"(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)", "PRIVATE_KEY"),
            # SSH Public Keys (ssh-rsa, ssh-ed25519, ecdsa-sha2-*)
            (r"\b((?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9\-]+)\s+[A-Za-z0-9+/]{30,}[=]{0,3}(?:\s+[\w\.\@\-]+)?)\b", "SSH_PUB_KEY"),
            # Anthropic specific AI keys
            (r"\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b", "ANTHROPIC_KEY"),
            # OpenAI / General AI keys
            (r"\b(sk-[a-zA-Z0-9_\-]{20,})\b", "API_KEY"),
            # Google AI Studio / Maps / Cloud API Key
            (r"\b(AIza[0-9A-Za-z\-_]{35})\b", "GOOGLE_API_KEY"),
            # GitHub Personal Access Tokens
            (r"\b(ghp_[a-zA-Z0-9]{36})\b", "GITHUB_PAT"),
            (r"\b(github_pat_[a-zA-Z0-9_]{82})\b", "GITHUB_PAT"),
            # Telegram Bot Tokens
            (r"\b(\d{9,10}:[A-Za-z0-9_-]{35})\b", "TG_BOT_TOKEN"),
            # AWS Access Key ID
            (r"\b(AKIA[0-9A-Z]{16})\b", "AWS_KEY"),
            # Slack Tokens
            (r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b", "SLACK_TOKEN"),
            # Stripe API Keys
            (r"\b([rs]k_(?:live|test)_[0-9a-zA-Z]{24,})\b", "STRIPE_KEY"),
            # JSON Web Tokens (JWT)
            (r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b", "JWT_TOKEN"),
            # Database URIs with passwords
            (r"(?:postgres|postgresql|mongodb|mysql|redis):\/\/[^:\/\s]+:([^@\/\s]{4,})@", "DB_PASSWORD"),
        ]

        # IPv4 pattern (with optional CIDR prefix e.g. /24)
        self.ipv4_pattern = re.compile(
            r"\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\/\d{1,2})?)\b"
        )
        self.ipv4_exempt = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}

        # IPv6 pattern
        self.ipv6_pattern = re.compile(
            r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b"
        )

        # Contextual assignment patterns (e.g. DB_PASSWORD = "...", apiKey: "...", token = "...")
        self.assignment_pattern = re.compile(
            r"""(?i)\b([a-zA-Z0-9_]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)[a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']{6,})["']"""
        )

        # Environment variable export pattern (e.g. export STRIPE_KEY=...)
        self.env_pattern = re.compile(
            r"""(?i)\bexport\s+([A-Z0-9_]+)\s*=\s*["']?([^"'\s]{8,})["']?"""
        )

        if secrets_file and os.path.exists(secrets_file):
            self.load_secrets_file(secrets_file)

        if env_files:
            for ef in env_files:
                if os.path.exists(ef):
                    self.load_env_file(ef)

    def load_env_file(self, path: str) -> int:
        """Loads secrets from a .env file, ignoring non-sensitive config keys."""
        loaded = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip("\"'").strip()

                        # Skip non-sensitive keys
                        if key.upper() in IGNORE_ENV_KEYS:
                            continue
                        # Skip booleans and nulls
                        if val.lower() in ("true", "false", "null", "undefined", "yes", "no"):
                            continue
                        # Skip short port numbers or single digits
                        if val.isdigit() and len(val) < 8:
                            continue
                        # Only mask meaningful values >= 5 chars
                        if len(val) >= 5:
                            self.register_secret(val, key)
                            loaded += 1
            print(f"[Vault] Loaded {loaded} secret(s) from .env file: {path}")
        except Exception as e:
            print(f"[Vault] Error loading .env from {path}: {e}")
        return loaded

    def load_secrets_file(self, path: str):
        """Loads static secrets from a JSON or line-based text file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return

                if content.startswith("{"):
                    data = json.loads(content)
                    for k, v in data.items():
                        if isinstance(v, str) and (len(v) > len(k) or v.startswith("sk-") or v.startswith("ghp_")):
                            self.register_secret(v, k)
                        else:
                            self.register_secret(k, str(v))
                else:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.register_secret(line)
        except Exception as e:
            print(f"[Vault] Error loading secrets from {path}: {e}")

    def register_secret(self, secret: str, label: Optional[str] = None) -> str:
        """
        Registers a secret and returns its placeholder.
        Supports exact custom placeholders (e.g. '__home_net__') or generates '__VAULT_{LABEL}_{ID}__'.
        """
        if not secret or len(secret) < 3:
            return secret

        if secret in self.secret_to_placeholder:
            return self.secret_to_placeholder[secret]

        if label:
            # If user explicitly passed an exact placeholder format like '__home_net__'
            if label.startswith("__") and label.endswith("__") and len(label) > 4:
                clean_tag = re.sub(r"[^A-Za-z0-9_]", "_", label[2:-2])
                placeholder = f"__{clean_tag}__"
            else:
                clean_label = re.sub(r"[^A-Za-z0-9_]", "_", label).upper()
                placeholder = f"__VAULT_{clean_label}_{self._next_id:02d}__"
        else:
            placeholder = f"__VAULT_SECRET_{self._next_id:02d}__"

        # If placeholder name collides with an existing one for a DIFFERENT secret
        if placeholder in self.placeholder_to_secret:
            clean_base = placeholder.strip("_")
            placeholder = f"__{clean_base}_{self._next_id:02d}__"

        self._next_id += 1
        self.secret_to_placeholder[secret] = placeholder
        self.placeholder_to_secret[placeholder] = secret

        if self.on_mask:
            self.on_mask(placeholder, secret)

        return placeholder

    def scan_and_register_dynamic(self, text: str) -> List[Tuple[str, str]]:
        """
        Smart Scanner:
        1. Contextual assignments (e.g. token = "...", password: "...")
        2. Known signatures (OpenAI, Anthropic, Google, AWS, GitHub, etc.)
        3. Shannon Entropy analysis for high-randomness strings
        """
        found = []

        # 1. Contextual assignments in code or JSON
        for m in self.assignment_pattern.finditer(text):
            var_name = m.group(1)
            val = m.group(2)
            if val and val not in self.secret_to_placeholder and not val.startswith("__VAULT_"):
                ph = self.register_secret(val, var_name)
                found.append((val, ph))

        # 2. Environment exports
        for m in self.env_pattern.finditer(text):
            var_name = m.group(1)
            val = m.group(2)
            if val and val not in self.secret_to_placeholder and not val.startswith("__VAULT_"):
                ph = self.register_secret(val, var_name)
                found.append((val, ph))

        # 3. Signature patterns
        for pattern, label in self.signature_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) >= 8 and not match.startswith("__VAULT_"):
                    if match not in self.secret_to_placeholder:
                        ph = self.register_secret(match, label)
                        found.append((match, ph))

        # 4. Shannon Entropy analysis for arbitrary high-entropy tokens (>=20 chars)
        potential_tokens = re.findall(r"\b[A-Za-z0-9_\-\.]{20,}\b", text)
        for token in potential_tokens:
            if token in self.secret_to_placeholder or token.startswith("__VAULT_"):
                continue
            # Must contain both letters and digits
            if re.search(r"[A-Za-z]", token) and re.search(r"[0-9]", token):
                # Ignore URLs, typical paths or package names
                if not token.startswith("http") and not "/" in token:
                    h = calculate_shannon_entropy(token)
                    if h >= 4.15:
                        ph = self.register_secret(token, "ENTROPY_KEY")
                        found.append((token, ph))

        # 5. IPv4 Addresses (Local & Public)
        for m in self.ipv4_pattern.finditer(text):
            ip = m.group(1)
            if ip in self.ipv4_exempt or ip in self.secret_to_placeholder or ip.startswith("__VAULT_"):
                continue
            # Ignore if part of a version string like v1.2.3.4
            start_pos = m.start()
            if start_pos > 0 and text[start_pos - 1] in ("v", "V", "/"):
                continue

            # Classify local subnet vs public IP
            clean_ip = ip.split("/")[0]
            if clean_ip.startswith("192.168.") or clean_ip.startswith("10.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", clean_ip):
                ph = self.register_secret(ip, "LOCAL_IP")
            else:
                ph = self.register_secret(ip, "IP_ADDR")
            found.append((ip, ph))

        # 6. IPv6 Addresses
        for m in self.ipv6_pattern.finditer(text):
            ip6 = m.group(1)
            if ip6 in ("::1", "::") or ip6 in self.secret_to_placeholder or ip6.startswith("__VAULT_"):
                continue
            ph = self.register_secret(ip6, "IPV6_ADDR")
            found.append((ip6, ph))

        return found

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Replaces all known and newly detected secrets in text with placeholders."""
        if not text:
            return text, 0

        self.scan_and_register_dynamic(text)

        replacements = 0
        masked = text

        # Sort secrets by length descending to avoid partial prefix collisions
        sorted_secrets = sorted(self.secret_to_placeholder.keys(), key=len, reverse=True)
        for secret in sorted_secrets:
            if secret in masked:
                placeholder = self.secret_to_placeholder[secret]
                count = masked.count(secret)
                if count > 0:
                    masked = masked.replace(secret, placeholder)
                    replacements += count

        return masked, replacements

    def mask_payload(self, data: Any) -> Tuple[Any, int]:
        """Recursively masks string values in a JSON-serializable structure."""
        if isinstance(data, str):
            return self.mask_text(data)
        elif isinstance(data, list):
            new_list = []
            total_replacements = 0
            for item in data:
                masked_item, count = self.mask_payload(item)
                new_list.append(masked_item)
                total_replacements += count
            return new_list, total_replacements
        elif isinstance(data, dict):
            new_dict = {}
            total_replacements = 0
            for k, v in data.items():
                masked_v, count = self.mask_payload(v)
                new_dict[k] = masked_v
                total_replacements += count
            return new_dict, total_replacements
        return data, 0

    def demask_text(self, text: str) -> Tuple[str, int]:
        """Restores placeholders in text back to real secrets."""
        if not text:
            return text, 0

        restorations = 0
        result = text
        sorted_placeholders = sorted(self.placeholder_to_secret.keys(), key=len, reverse=True)
        for placeholder in sorted_placeholders:
            if placeholder in result:
                real_secret = self.placeholder_to_secret[placeholder]
                count = result.count(placeholder)
                if count > 0:
                    result = result.replace(placeholder, real_secret)
                    restorations += count
                    if self.on_demask:
                        self.on_demask(placeholder, real_secret)

        return result, restorations


class TextStreamDemasker:
    """
    Stateful buffer for continuous text stream (e.g. delta field inside SSE).
    Buffers only when an unclosed '__' placeholder prefix is detected at the tail.
    """
    def __init__(self, vault: SecretVault, max_placeholder_len: int = 40):
        self.vault = vault
        self.max_placeholder_len = max_placeholder_len
        self.buffer = ""

    def process(self, text: str) -> str:
        if not text:
            return ""

        self.buffer += text

        # Demask any complete placeholders currently in buffer
        self.buffer, _ = self.vault.demask_text(self.buffer)

        # Look for the last '__' in the buffer
        last_double_underscore = self.buffer.rfind("__")

        if last_double_underscore == -1:
            # No '__' at all: entire buffer is safe to emit immediately
            to_emit = self.buffer
            self.buffer = ""
            return to_emit

        # There is a '__'
        tail = self.buffer[last_double_underscore:]

        # If tail starts with '__' and doesn't contain a closing '__' (after the first 2 chars)
        # and tail length is less than max_placeholder_len, hold tail back
        if tail.startswith("__") and tail[2:].find("__") == -1 and len(tail) < self.max_placeholder_len:
            to_emit = self.buffer[:last_double_underscore]
            self.buffer = tail
            return to_emit

        # Otherwise, whatever is in buffer is either closed or too long to be a placeholder
        to_emit = self.buffer
        self.buffer = ""
        return to_emit

    def flush(self) -> str:
        final_text, _ = self.vault.demask_text(self.buffer)
        self.buffer = ""
        return final_text


class SSEStreamDemasker:
    """
    Universal Demasker for Server-Sent Events (SSE).
    Supports:
    1. OpenAI Realtime / Responses API (`openai-responses` format: `type: response.output_text.delta`, `delta: str`)
    2. OpenAI Chat Completions (`choices[].delta.content`)
    3. Anthropic (`type: content_block_delta`, `delta.text`)
    4. Arbitrary JSON text fields and fallback raw SSE streams
    """
    def __init__(self, vault: SecretVault):
        self.vault = vault
        self.raw_line_buffer = ""
        self.content_demasker = TextStreamDemasker(vault)
        self.last_responses_event: Optional[Dict[str, Any]] = None
        self.saw_choices: bool = False

    def process_raw_chunk(self, chunk: str) -> str:
        self.raw_line_buffer += chunk
        output = []

        while "\n" in self.raw_line_buffer:
            line, self.raw_line_buffer = self.raw_line_buffer.split("\n", 1)
            line = line.strip()

            if not line:
                output.append("\n\n")
                continue

            if line.startswith("data:"):
                data_str = line[5:].strip()

                if data_str == "[DONE]":
                    # Flush before [DONE]
                    flushed = self.content_demasker.flush()
                    if flushed:
                        if self.last_responses_event:
                            ev = dict(self.last_responses_event)
                            ev["delta"] = flushed
                            output.append(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n")
                        elif self.saw_choices:
                            synth = {"choices": [{"index": 0, "delta": {"content": flushed}}]}
                            output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")
                    output.append("data: [DONE]\n\n")
                    continue

                try:
                    event_data = json.loads(data_str)
                    modified = False

                    # 1. Format: OpenAI Responses API (e.g. response.output_text.delta)
                    # Used by ZCode when api.type == "openai-responses"!
                    if isinstance(event_data, dict) and "delta" in event_data and isinstance(event_data["delta"], str):
                        event_data["delta"] = self.content_demasker.process(event_data["delta"])
                        self.last_responses_event = dict(event_data)
                        modified = True

                    # 2. Format: OpenAI Chat Completions (choices -> delta -> content)
                    elif isinstance(event_data, dict) and "choices" in event_data and isinstance(event_data["choices"], list):
                        self.saw_choices = True
                        for choice in event_data.get("choices", []):
                            delta = choice.get("delta", {})
                            if isinstance(delta, dict):
                                if "content" in delta and isinstance(delta["content"], str):
                                    delta["content"] = self.content_demasker.process(delta["content"])
                                    modified = True
                                if "reasoning_content" in delta and isinstance(delta["reasoning_content"], str):
                                    delta["reasoning_content"] = self.content_demasker.process(delta["reasoning_content"])
                                    modified = True

                    # 3. Format: Anthropic (delta.text or content_block)
                    elif isinstance(event_data, dict) and "delta" in event_data and isinstance(event_data["delta"], dict):
                        if "text" in event_data["delta"] and isinstance(event_data["delta"]["text"], str):
                            event_data["delta"]["text"] = self.content_demasker.process(event_data["delta"]["text"])
                            modified = True

                    # 4. Universal fallback: recursive string demasking for any other JSON structure
                    if not modified and isinstance(event_data, (dict, list)):
                        def recursive_demask(item):
                            if isinstance(item, str):
                                res, _ = self.vault.demask_text(item)
                                return res
                            elif isinstance(item, list):
                                return [recursive_demask(x) for x in item]
                            elif isinstance(item, dict):
                                return {k: recursive_demask(v) for k, v in item.items()}
                            return item

                        event_data = recursive_demask(event_data)

                    output.append(f"data: {json.dumps(event_data, ensure_ascii=False)}\n")

                except Exception:
                    # Non-JSON data line: fallback direct text demask
                    demasked_line, _ = self.vault.demask_text(line)
                    output.append(demasked_line + "\n")
            else:
                # Other SSE headers (event:, id:, retry:, etc.)
                demasked_line, _ = self.vault.demask_text(line)
                output.append(demasked_line + "\n")

        return "".join(output)

    def flush(self) -> str:
        output = []
        flushed = self.content_demasker.flush()
        if flushed:
            if self.last_responses_event:
                ev = dict(self.last_responses_event)
                ev["delta"] = flushed
                output.append(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n")
            elif self.saw_choices:
                synth = {"choices": [{"index": 0, "delta": {"content": flushed}}]}
                output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

        if self.raw_line_buffer:
            demasked_rem, _ = self.vault.demask_text(self.raw_line_buffer)
            output.append(demasked_rem)
            self.raw_line_buffer = ""

        return "".join(output)
