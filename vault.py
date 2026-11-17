import re
import json
import os
import math
import ipaddress
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

# System keys in LLM JSON payloads that should NOT be masked by entropy/regex
SYSTEM_SAFE_KEYS = {
    "id", "tool_call_id", "call_id", "signature", "encrypted_content"
}

# Thinking / reasoning blocks must be neither masked on egress nor demasked on ingress.
# Symmetry keeps the block byte-for-byte identical to what the upstream produced:
# signatures stay valid and no real secret can leak back on the next turn.
# Scope is deliberately narrow: a block is recognised ONLY by its "type", and only
# its own opaque fields are skipped. Generic keys such as "data" or "summary" in
# ordinary dicts (e.g. tool_use.input) are processed like any other data.
THINKING_BLOCK_TYPES = {
    "thinking", "redacted_thinking", "reasoning"
}

THINKING_BLOCK_KEYS = {
    "thinking", "data", "signature", "encrypted_content", "summary", "content"
}


def _skip_symmetric(node: Dict[str, Any], key: str) -> bool:
    """True if `key` of dict `node` must pass through mask/demask untouched."""
    if node.get("type") in THINKING_BLOCK_TYPES and key in THINKING_BLOCK_KEYS:
        return True
    # Chat Completions assistant message carrying provider reasoning text
    if key == "reasoning_content" and "role" in node:
        return True
    return False


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

        # IPv6 candidate pattern (checked strictly via ipaddress)
        self.ipv6_candidate_pattern = re.compile(
            r"\b([0-9a-fA-F:]{3,39})\b"
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

                        if key.upper() in IGNORE_ENV_KEYS:
                            continue
                        if val.lower() in ("true", "false", "null", "undefined", "yes", "no"):
                            continue
                        if val.isdigit() and len(val) < 8:
                            continue
                        if len(val) >= 5:
                            self.register_secret(val, key)
                            loaded += 1
            print(f"[Vault] Loaded {loaded} secret(s) from .env file: {path}")
        except Exception as e:
            print(f"[Vault] Error loading .env from {path}: {e}")
        return loaded

    def load_secrets_file(self, path: str):
        """
        Loads static secrets from JSON or line-based text file.
        Strict schema: JSON key is ALWAYS the label/placeholder, and value is ALWAYS the secret.
        Only non-empty string values are registered. Booleans and numbers are ignored.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return

                if content.startswith("{"):
                    data = json.loads(content)
                    for k, v in data.items():
                        if isinstance(v, bool):
                            continue
                        if isinstance(v, str) and v.strip():
                            if v.strip().lower() in ("true", "false", "null", "undefined"):
                                continue
                            self.register_secret(v.strip(), str(k).strip())
                else:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.register_secret(line)
        except Exception as e:
            print(f"[Vault] Error loading secrets from {path}: {e}")

    def register_secret(self, secret: str, label: Optional[str] = None) -> str:
        if not secret or len(secret) < 3:
            return secret

        if secret in self.secret_to_placeholder:
            return self.secret_to_placeholder[secret]

        if label:
            if label.startswith("__") and label.endswith("__") and len(label) > 4:
                clean_tag = re.sub(r"[^A-Za-z0-9_]", "_", label[2:-2])
                placeholder = f"__{clean_tag}__"
            else:
                clean_label = re.sub(r"[^A-Za-z0-9_]", "_", label).upper()
                placeholder = f"__VAULT_{clean_label}_{self._next_id:02d}__"
        else:
            placeholder = f"__VAULT_SECRET_{self._next_id:02d}__"

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
            if any(token.startswith(pfx) for pfx in ("call_", "toolu_", "chatcmpl-", "msg_", "resp_", "ft:", "gpt-", "claude-")):
                continue
            if re.search(r"[A-Za-z]", token) and re.search(r"[0-9]", token):
                if not token.startswith("http") and "/" not in token:
                    h = calculate_shannon_entropy(token)
                    if h >= 4.15:
                        ph = self.register_secret(token, "ENTROPY_KEY")
                        found.append((token, ph))

        # 5. IPv4 Addresses (Local & Public)
        for m in self.ipv4_pattern.finditer(text):
            ip = m.group(1)
            if ip in self.ipv4_exempt or ip in self.secret_to_placeholder or ip.startswith("__VAULT_"):
                continue
            start_pos = m.start()
            if start_pos > 0 and text[start_pos - 1] in ("v", "V", "/"):
                continue

            clean_ip = ip.split("/")[0]
            if clean_ip.startswith("192.168.") or clean_ip.startswith("10.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", clean_ip):
                ph = self.register_secret(ip, "LOCAL_IP")
            else:
                ph = self.register_secret(ip, "IP_ADDR")
            found.append((ip, ph))

        # 6. IPv6 Addresses (Validated strictly with ipaddress module)
        for m in self.ipv6_candidate_pattern.finditer(text):
            cand = m.group(1)
            if cand.count(":") < 2:
                continue
            try:
                ip_obj = ipaddress.IPv6Address(cand)
                if ip_obj.is_loopback or ip_obj.is_unspecified:
                    continue
                if cand in self.secret_to_placeholder or cand.startswith("__VAULT_"):
                    continue
                ph = self.register_secret(cand, "IPV6_ADDR")
                found.append((cand, ph))
            except ValueError:
                continue

        return found

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Replaces all known and newly detected secrets in text with placeholders."""
        if not text:
            return text, 0

        self.scan_and_register_dynamic(text)

        replacements = 0
        masked = text

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
        """
        Recursively masks string values in a JSON-serializable structure.
        Thinking/reasoning blocks (matched by `type`) are passed through intact; see _skip_symmetric.
        """
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
                if k in SYSTEM_SAFE_KEYS or _skip_symmetric(data, k):
                    new_dict[k] = v
                    continue

                masked_v, count = self.mask_payload(v)
                new_dict[k] = masked_v
                total_replacements += count
            return new_dict, total_replacements
        return data, 0

    def demask_text(self, text: str, json_escaped: bool = False) -> Tuple[str, int]:
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
                    if json_escaped:
                        replacement = json.dumps(real_secret)[1:-1]
                    else:
                        replacement = real_secret
                    result = result.replace(placeholder, replacement)
                    restorations += count
                    if self.on_demask:
                        self.on_demask(placeholder, real_secret)

        return result, restorations

    def demask_payload(self, data: Any) -> Tuple[Any, int]:
        """
        Recursively demasks string values in a JSON-serializable structure.
        Maintains symmetry with mask_payload: thinking/reasoning blocks (matched by `type`) are never demasked.
        This guarantees that thinking blocks returning from LLM remain byte-for-byte identical,
        preserving cryptographic signatures and preventing secrets from leaking on the next conversation turn.
        """
        if isinstance(data, str):
            return self.demask_text(data)
        elif isinstance(data, list):
            new_list = []
            total_restorations = 0
            for item in data:
                demasked_item, count = self.demask_payload(item)
                new_list.append(demasked_item)
                total_restorations += count
            return new_list, total_restorations
        elif isinstance(data, dict):
            new_dict = {}
            total_restorations = 0
            for k, v in data.items():
                if _skip_symmetric(data, k):
                    new_dict[k] = v
                    continue

                demasked_v, count = self.demask_payload(v)
                new_dict[k] = demasked_v
                total_restorations += count
            return new_dict, total_restorations
        return data, 0

    def demask_json_str(self, text: str) -> Tuple[str, int]:
        """Safely demasks a JSON string by parsing it into structured Python objects first."""
        try:
            parsed = json.loads(text)
            demasked_obj, count = self.demask_payload(parsed)
            return json.dumps(demasked_obj, ensure_ascii=False), count
        except Exception:
            return self.demask_text(text, json_escaped=True)


class TextStreamDemasker:
    """
    Stateful buffer for continuous text stream (e.g. delta field inside SSE).
    Buffers ONLY when a genuine unclosed placeholder prefix (e.g. '__VAULT_API')
    is detected at the tail of the stream.
    Valid unclosed placeholder prefixes must strictly match ^__[A-Za-z0-9_]*$ without spaces.
    """
    def __init__(self, vault: SecretVault, max_placeholder_len: int = 40, json_escaped: bool = False):
        self.vault = vault
        self.max_placeholder_len = max_placeholder_len
        self.json_escaped = json_escaped
        self.buffer = ""

    def process(self, text: str) -> str:
        if not text:
            return ""

        self.buffer += text

        # Demask any complete placeholders currently in buffer
        self.buffer, _ = self.vault.demask_text(self.buffer, json_escaped=self.json_escaped)

        # Look for the last '__' in the buffer
        last_double_underscore = self.buffer.rfind("__")

        if last_double_underscore == -1:
            to_emit = self.buffer
            self.buffer = ""
            return to_emit

        tail = self.buffer[last_double_underscore:]

        is_candidate_prefix = (
            re.match(r"^__[A-Za-z0-9_]*$", tail) is not None
            and tail[2:].find("__") == -1
            and len(tail) < self.max_placeholder_len
        )

        if is_candidate_prefix:
            to_emit = self.buffer[:last_double_underscore]
            self.buffer = tail
            return to_emit

        to_emit = self.buffer
        self.buffer = ""
        return to_emit

    def flush(self) -> str:
        final_text, _ = self.vault.demask_text(self.buffer, json_escaped=self.json_escaped)
        self.buffer = ""
        return final_text


class SSEStreamDemasker:
    """
    Universal Demasker for Server-Sent Events (SSE).
    Supports OpenAI Chat Completions, Responses API, Anthropic, and streaming tool calls.
    Flushes buffers proactively on finish_reason, content_block_stop, response.output_text.done, and [DONE].
    NEVER demasks thinking, reasoning, or signature events in the stream.
    """
    def __init__(self, vault: SecretVault):
        self.vault = vault
        self.raw_line_buffer = ""
        self.content_demasker = TextStreamDemasker(vault, json_escaped=False)
        self.stream_demaskers: Dict[str, TextStreamDemasker] = {}
        self.last_responses_event: Optional[Dict[str, Any]] = None
        self.saw_choices: bool = False

    def _get_stream_demasker(self, key: str, json_escaped: bool = False) -> TextStreamDemasker:
        if key not in self.stream_demaskers:
            self.stream_demaskers[key] = TextStreamDemasker(self.vault, json_escaped=json_escaped)
        return self.stream_demaskers[key]

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
                    flushed = self.flush_internal()
                    if flushed:
                        output.append(flushed)
                    output.append("data: [DONE]\n\n")
                    continue

                try:
                    event_data = json.loads(data_str)
                    modified = False

                    if isinstance(event_data, dict):
                        ev_type = event_data.get("type", "")

                        # Responses API reasoning events: NEVER demask (preserve placeholders intact)
                        if ev_type in (
                            "response.reasoning_text.delta",
                            "response.reasoning_summary_text.delta",
                            "response.reasoning.delta"
                        ):
                            modified = True

                        # 1. OpenAI Responses API text output
                        elif "delta" in event_data and isinstance(event_data["delta"], str):
                            if ev_type == "response.function_call_arguments.delta":
                                call_id = event_data.get("call_id", "default")
                                demasker = self._get_stream_demasker(f"resp_fn_{call_id}", json_escaped=True)
                                event_data["delta"] = demasker.process(event_data["delta"])
                            else:
                                event_data["delta"] = self.content_demasker.process(event_data["delta"])
                            self.last_responses_event = dict(event_data)
                            modified = True

                        # Responses API: proactively flush buffers on completion events before sending them
                        elif ev_type in (
                            "response.output_text.done",
                            "response.content_part.done",
                            "response.completed",
                            "response.done",
                        ):
                            flushed_c = self.content_demasker.flush()
                            if flushed_c:
                                synth = {
                                    "type": "response.output_text.delta",
                                    "delta": flushed_c
                                }
                                if self.last_responses_event:
                                    for k in ("item_id", "output_index", "content_index"):
                                        if k in self.last_responses_event:
                                            synth[k] = self.last_responses_event[k]
                                output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

                        elif ev_type == "response.function_call_arguments.done":
                            call_id = event_data.get("call_id", "default")
                            key = f"resp_fn_{call_id}"
                            if key in self.stream_demaskers:
                                flushed_fn = self.stream_demaskers[key].flush()
                                if flushed_fn:
                                    synth = {
                                        "type": "response.function_call_arguments.delta",
                                        "call_id": call_id,
                                        "delta": flushed_fn
                                    }
                                    output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

                        # 2. OpenAI Chat Completions (choices -> delta)
                        elif "choices" in event_data and isinstance(event_data["choices"], list):
                            self.saw_choices = True
                            for choice in event_data.get("choices", []):
                                c_idx = choice.get("index", 0)
                                delta = choice.get("delta", {})
                                finish_reason = choice.get("finish_reason")

                                if isinstance(delta, dict):
                                    if "content" in delta and isinstance(delta["content"], str):
                                        delta["content"] = self.content_demasker.process(delta["content"])
                                        modified = True

                                    # DO NOT demask reasoning_content: keep placeholders intact
                                    if "reasoning_content" in delta:
                                        modified = True

                                    if "tool_calls" in delta and isinstance(delta["tool_calls"], list):
                                        for tc in delta["tool_calls"]:
                                            tc_idx = tc.get("index", 0)
                                            func = tc.get("function", {})
                                            if isinstance(func, dict) and "arguments" in func and isinstance(func["arguments"], str):
                                                key = f"openai_tc_{c_idx}_{tc_idx}"
                                                tc_demasker = self._get_stream_demasker(key, json_escaped=True)
                                                func["arguments"] = tc_demasker.process(func["arguments"])
                                                modified = True

                                # Proactively flush held buffer when finish_reason arrives
                                if finish_reason is not None:
                                    flushed_c = self.content_demasker.flush()
                                    if flushed_c:
                                        if "delta" in choice and "content" in choice["delta"]:
                                            choice["delta"]["content"] = (choice["delta"]["content"] or "") + flushed_c
                                        else:
                                            choice.setdefault("delta", {})["content"] = flushed_c
                                        modified = True

                        # 3. Anthropic format
                        elif "delta" in event_data and isinstance(event_data["delta"], dict):
                            delta_obj = event_data["delta"]
                            d_type = delta_obj.get("type", "")
                            block_idx = event_data.get("index", 0)

                            # Anthropic thinking / signature deltas: NEVER demask
                            if d_type in ("thinking_delta", "signature_delta"):
                                modified = True

                            elif "text" in delta_obj and isinstance(delta_obj["text"], str):
                                delta_obj["text"] = self.content_demasker.process(delta_obj["text"])
                                modified = True
                            elif "partial_json" in delta_obj and isinstance(delta_obj["partial_json"], str):
                                key = f"anthropic_block_{block_idx}"
                                tc_demasker = self._get_stream_demasker(key, json_escaped=True)
                                delta_obj["partial_json"] = tc_demasker.process(delta_obj["partial_json"])
                                modified = True

                        # Anthropic content_block_stop / message_stop: proactively flush held text
                        elif ev_type in ("content_block_stop", "message_stop"):
                            block_idx = event_data.get("index", 0)
                            flushed_c = self.content_demasker.flush()
                            tc_key = f"anthropic_block_{block_idx}"
                            flushed_tc = self.stream_demaskers[tc_key].flush() if tc_key in self.stream_demaskers else ""

                            if flushed_c:
                                synth = {
                                    "type": "content_block_delta",
                                    "index": block_idx,
                                    "delta": {"type": "text_delta", "text": flushed_c}
                                }
                                output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

                            if flushed_tc:
                                synth_tc = {
                                    "type": "content_block_delta",
                                    "index": block_idx,
                                    "delta": {"type": "input_json_delta", "partial_json": flushed_tc}
                                }
                                output.append(f"data: {json.dumps(synth_tc, ensure_ascii=False)}\n\n")

                    if not modified and isinstance(event_data, (dict, list)):
                        event_data, _ = self.vault.demask_payload(event_data)

                    output.append(f"data: {json.dumps(event_data, ensure_ascii=False)}\n")

                except Exception:
                    demasked_line, _ = self.vault.demask_text(line)
                    output.append(demasked_line + "\n")
            else:
                demasked_line, _ = self.vault.demask_text(line)
                output.append(demasked_line + "\n")

        return "".join(output)

    def flush_internal(self) -> str:
        output = []
        flushed_content = self.content_demasker.flush()
        if flushed_content:
            if self.last_responses_event:
                ev = dict(self.last_responses_event)
                ev["delta"] = flushed_content
                output.append(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n")
            elif self.saw_choices:
                synth = {"choices": [{"index": 0, "delta": {"content": flushed_content}}]}
                output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

        for key, demasker in list(self.stream_demaskers.items()):
            flushed_extra = demasker.flush()
            if flushed_extra:
                if key.startswith("anthropic_block_"):
                    try:
                        b_idx = int(key.split("_")[-1])
                    except Exception:
                        b_idx = 0
                    synth = {"type": "content_block_delta", "index": b_idx, "delta": {"type": "input_json_delta", "partial_json": flushed_extra}}
                    output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")
                elif key.startswith("openai_tc_"):
                    parts = key.split("_")
                    c_idx = int(parts[2]) if len(parts) > 2 else 0
                    t_idx = int(parts[3]) if len(parts) > 3 else 0
                    synth = {"choices": [{"index": c_idx, "delta": {"tool_calls": [{"index": t_idx, "function": {"arguments": flushed_extra}}]}}]}
                    output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")
                elif key.startswith("resp_fn_"):
                    call_id = key.split("resp_fn_")[-1]
                    synth = {
                        "type": "response.function_call_arguments.delta",
                        "call_id": call_id,
                        "delta": flushed_extra
                    }
                    output.append(f"data: {json.dumps(synth, ensure_ascii=False)}\n\n")

        self.stream_demaskers.clear()
        return "".join(output)

    def flush(self) -> str:
        output = [self.flush_internal()]
        if self.raw_line_buffer:
            demasked_rem, _ = self.vault.demask_text(self.raw_line_buffer)
            output.append(demasked_rem)
            self.raw_line_buffer = ""

        return "".join(output)
