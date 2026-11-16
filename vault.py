import re
import json
import os
from typing import Dict, List, Tuple, Any, Optional

class SecretVault:
    def __init__(self, secrets_file: Optional[str] = None):
        self.secrets_file = secrets_file
        self.secret_to_placeholder: Dict[str, str] = {}
        self.placeholder_to_secret: Dict[str, str] = {}
        self._next_id = 1

        # Built-in regex patterns for common high-risk secrets
        self.patterns = [
            # OpenAI / Anthropic / general API keys
            (r"\b(sk-[a-zA-Z0-9_\-]{20,})\b", "API_KEY"),
            # GitHub Personal Access Tokens (classic & fine-grained)
            (r"\b(ghp_[a-zA-Z0-9]{36})\b", "GITHUB_PAT"),
            (r"\b(github_pat_[a-zA-Z0-9_]{82})\b", "GITHUB_PAT"),
            # Telegram Bot Tokens
            (r"\b(\d{9,10}:[A-Za-z0-9_-]{35})\b", "TG_BOT_TOKEN"),
            # AWS Access Key ID
            (r"\b(AKIA[0-9A-Z]{16})\b", "AWS_KEY"),
            # Private keys
            (r"(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)", "PRIVATE_KEY"),
            # Database URIs with passwords (e.g., postgresql://user:password@host)
            (r"(?:postgres|postgresql|mongodb|mysql|redis):\/\/[^:\/\s]+:([^@\/\s]+)@", "DB_PASSWORD"),
        ]

        if secrets_file and os.path.exists(secrets_file):
            self.load_secrets_file(secrets_file)

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
                        # If format is {"sk-123": "MY_LABEL"} or {"label": "sk-123"}
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
        """Registers a secret and returns its placeholder."""
        if not secret or len(secret) < 6:
            return secret

        if secret in self.secret_to_placeholder:
            return self.secret_to_placeholder[secret]

        if label:
            # Clean label to be uppercase alphanumeric
            clean_label = re.sub(r"[^A-Za-z0-9_]", "_", label).upper()
            placeholder = f"__VAULT_{clean_label}_{self._next_id:02d}__"
        else:
            placeholder = f"__VAULT_SECRET_{self._next_id:02d}__"

        self._next_id += 1
        self.secret_to_placeholder[secret] = placeholder
        self.placeholder_to_secret[placeholder] = secret
        return placeholder

    def scan_and_register_dynamic(self, text: str) -> List[Tuple[str, str]]:
        """Scans text for common secret patterns and registers newly found secrets."""
        found = []
        for pattern, label in self.patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) >= 8:
                    if match not in self.secret_to_placeholder:
                        placeholder = self.register_secret(match, label)
                        found.append((match, placeholder))
        return found

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Replaces all known and newly detected secrets in text with placeholders."""
        if not text:
            return text, 0

        # 1. Scan for newly appearing secrets
        self.scan_and_register_dynamic(text)

        replacements = 0
        masked = text

        # Sort secrets by length descending to replace longest first (avoids sub-token collision)
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
        # Sort placeholders by length descending
        sorted_placeholders = sorted(self.placeholder_to_secret.keys(), key=len, reverse=True)
        for placeholder in sorted_placeholders:
            if placeholder in result:
                real_secret = self.placeholder_to_secret[placeholder]
                count = result.count(placeholder)
                if count > 0:
                    result = result.replace(placeholder, real_secret)
                    restorations += count

        return result, restorations


class TextStreamDemasker:
    """
    Stateful buffer for continuous text stream (e.g. content field inside SSE).
    Buffers partial placeholders across token boundaries.
    """
    def __init__(self, vault: SecretVault, buffer_size: int = 40):
        self.vault = vault
        self.buffer_size = buffer_size
        self.buffer = ""

    def process(self, text: str) -> str:
        if not text:
            return ""

        self.buffer += text
        # Demask any completed placeholders
        self.buffer, _ = self.vault.demask_text(self.buffer)

        # Check if the buffer ends with an unclosed placeholder start
        last_double_underscore = self.buffer.rfind("__")
        if last_double_underscore != -1:
            tail = self.buffer[last_double_underscore:]
            # If tail starts with '__' and doesn't contain a closing '__' (after the first 2 chars)
            if tail.startswith("__") and tail[2:].find("__") == -1 and len(tail) < self.buffer_size:
                to_emit = self.buffer[:last_double_underscore]
                self.buffer = tail
                return to_emit

        # If buffer is getting too long and doesn't match an unclosed placeholder
        if len(self.buffer) > self.buffer_size:
            cut = len(self.buffer) - self.buffer_size
            to_emit = self.buffer[:cut]
            self.buffer = self.buffer[cut:]
            return to_emit

        return ""

    def flush(self) -> str:
        final_text, _ = self.vault.demask_text(self.buffer)
        self.buffer = ""
        return final_text


class SSEStreamDemasker:
    """
    Demasker specifically for Server-Sent Events (SSE).
    Parses 'data: {...}' lines, demasks content inside delta/choices,
    and handles placeholders split across multiple SSE events.
    """
    def __init__(self, vault: SecretVault):
        self.vault = vault
        self.raw_line_buffer = ""
        self.content_demasker = TextStreamDemasker(vault)
        self.reasoning_demasker = TextStreamDemasker(vault)

    def process_raw_chunk(self, chunk: str) -> str:
        self.raw_line_buffer += chunk
        output = []

        # Split into complete SSE events separated by \n\n or \n
        while "\n" in self.raw_line_buffer:
            line, self.raw_line_buffer = self.raw_line_buffer.split("\n", 1)
            line = line.strip()

            if not line:
                output.append("\n\n")
                continue

            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    # Flush any buffered text before emitting [DONE]
                    flushed_content = self.content_demasker.flush()
                    flushed_reasoning = self.reasoning_demasker.flush()
                    if flushed_content or flushed_reasoning:
                        synthetic_chunk = {
                            "choices": [{
                                "index": 0,
                                "delta": {}
                            }]
                        }
                        if flushed_content:
                            synthetic_chunk["choices"][0]["delta"]["content"] = flushed_content
                        if flushed_reasoning:
                            synthetic_chunk["choices"][0]["delta"]["reasoning_content"] = flushed_reasoning
                        output.append(f"data: {json.dumps(synthetic_chunk)}\n\n")
                    output.append("data: [DONE]\n\n")
                    continue

                try:
                    event_data = json.loads(data_str)
                    modified = False

                    # Check choices -> delta (OpenAI format)
                    if isinstance(event_data, dict) and "choices" in event_data:
                        for choice in event_data.get("choices", []):
                            delta = choice.get("delta", {})
                            if isinstance(delta, dict):
                                if "content" in delta and isinstance(delta["content"], str):
                                    delta["content"] = self.content_demasker.process(delta["content"])
                                    modified = True
                                if "reasoning_content" in delta and isinstance(delta["reasoning_content"], str):
                                    delta["reasoning_content"] = self.reasoning_demasker.process(delta["reasoning_content"])
                                    modified = True

                    # Fallback for other formats (e.g. text/responses)
                    if not modified and isinstance(event_data, dict):
                        for key in ("text", "response", "content"):
                            if key in event_data and isinstance(event_data[key], str):
                                event_data[key] = self.content_demasker.process(event_data[key])
                                modified = True

                    output.append(f"data: {json.dumps(event_data)}\n")

                except Exception:
                    # Non-JSON data payload, fallback to direct text demasking
                    demasked_line, _ = self.vault.demask_text(line)
                    output.append(demasked_line + "\n")
            else:
                # Other SSE headers (event:, id:, retry:, etc.)
                demasked_line, _ = self.vault.demask_text(line)
                output.append(demasked_line + "\n")

        return "".join(output)

    def flush(self) -> str:
        output = []
        flushed_content = self.content_demasker.flush()
        flushed_reasoning = self.reasoning_demasker.flush()

        if flushed_content or flushed_reasoning:
            synthetic_chunk = {
                "choices": [{
                    "index": 0,
                    "delta": {}
                }]
            }
            if flushed_content:
                synthetic_chunk["choices"][0]["delta"]["content"] = flushed_content
            if flushed_reasoning:
                synthetic_chunk["choices"][0]["delta"]["reasoning_content"] = flushed_reasoning
            output.append(f"data: {json.dumps(synthetic_chunk)}\n\n")

        if self.raw_line_buffer:
            demasked_rem, _ = self.vault.demask_text(self.raw_line_buffer)
            output.append(demasked_rem)
            self.raw_line_buffer = ""

        return "".join(output)

