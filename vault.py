import re
import json
import os
import sys
import time
import math
import secrets
import threading
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

# Generic / non-sensitive environment values that should never be registered as secrets
IGNORE_ENV_VALUES = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "true", "false", "null", "undefined",
    "production", "development", "test", "staging", "default", "none", "local",
    "debug", "info", "warn", "error", "trace", "fatal", "yes", "no", "on", "off"
}

# Dummy placeholder secrets and non-secrets commonly found in source code / docs / databases
DUMMY_VALUES = {
    "changeme", "dummy", "example", "your_api_key_here", "your_key", "your_secret",
    "todo", "secret", "password", "tokenizer", "gpt2-tokenizer", "test", "demo",
    "sample", "placeholder", "xxx", "xxxx", "null", "none", "undefined",
    "admin", "root", "user", "guest", "postgres", "mysql", "redis", "mongodb", "localhost"
}

# Programming language types and keywords to ignore in bare/YAML assignments
NON_SECRET_TYPES = {
    "string", "str", "number", "int", "integer", "float", "double", "bool", "boolean",
    "char", "byte", "bytes", "any", "unknown", "never", "void", "null", "undefined",
    "true", "false", "object", "array", "list", "dict", "tuple", "set", "map", "record",
    "optional", "union", "literal", "text", "varchar", "bigint", "date", "datetime", "timestamp"
}

# Variable name suffixes and prefixes to ignore in contextual assignment scanning
# Prevents false-positives for parameter names, types, field names, selectors, and URLs
NON_SECRET_VAR_SUFFIXES = (
    "name", "type", "field", "url", "path", "header",
    "class", "selector", "tag", "param", "schema",
    "user", "username", "email", "host", "port", "database", "db", "service",
    "_name", "_type", "_field", "_url", "_path", "_header",
    "_class", "_selector", "_tag", "_param", "_schema", "_key_name",
    "_user", "_username", "_email", "_host", "_port", "_database", "_db", "_service"
)
NON_SECRET_VAR_PREFIXES = (
    "public_", "next_public_", "default_type"
)

# JSON-inside-string keys in LLM tool calling payloads
JSON_STRING_KEYS = {
    "arguments", "partial_json", "input_json_delta", "input_json"
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
    # Vision & Audio payloads: preserve base64 and data-URIs intact without entropy corruption
    val = node.get(key)
    if isinstance(val, str) and val.startswith("data:"):
        return True
    if key == "source" and isinstance(val, dict):
        if "data" in val or val.get("type") == "base64":
            return True
    if key == "data" and isinstance(val, str):
        if node.get("type") in ("base64", "image", "input_audio") or "media_type" in node or "format" in node:
            return True
        if len(val) > 200 and re.match(r"^[A-Za-z0-9+/=\s]+$", val):
            return True
    if key == "url" and isinstance(val, str) and val.startswith("data:"):
        return True
    if key == "image_url" and isinstance(val, dict):
        u = val.get("url", "")
        if isinstance(u, str) and u.startswith("data:"):
            return True
    return False


class SecretVault:
    def __init__(self, secrets_file: Optional[str] = None, env_files: Optional[List[str]] = None,
                 state_file: Optional[str] = None, state_ttl: int = 86400,
                 session_nonce: Optional[str] = None):
        self.secrets_file = secrets_file
        self.state_file = state_file
        self.state_ttl = state_ttl
        self.session_nonce = session_nonce or secrets.token_hex(3)
        self._lock = threading.RLock()
        self._state_lock = threading.Lock()
        self.secret_to_placeholder: Dict[str, str] = {}
        self.placeholder_to_secret: Dict[str, str] = {}
        self.dynamic_secrets: Dict[str, Dict[str, Any]] = {}
        self._next_id = 1
        self._mask_regex: Optional[re.Pattern] = None
        self._demask_regex: Optional[re.Pattern] = None
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
        # Lookarounds prevent matching substrings of OIDs (e.g. 1.3.6.1.4.1) or multi-part versions
        # while permitting punctuation like trailing sentence periods
        self.ipv4_pattern = re.compile(
            r"(?<![0-9])(?<![0-9]\.)((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\/\d{1,2})?)(?![0-9])(?!\.[0-9])"
        )
        self.ipv4_exempt = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}

        # IPv6 candidate pattern (isolated from code identifier characters like Rust/C++ :: namespace)
        self.ipv6_candidate_pattern = re.compile(
            r"(?<![a-zA-Z0-9_])([0-9a-fA-F:]{3,39})(?![a-zA-Z0-9_])"
        )

        # Contextual assignment patterns (code with quoted values or JSON with quoted keys & values)
        # Bounded identifier length {0,40} prevents quadratic backtracking (ReDoS) on large minified code/hex dumps
        self.assignment_pattern = re.compile(
            r"""(?i)(?:["']\b|\b)([a-zA-Z0-9_]{0,40}(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)[a-zA-Z0-9_]{0,40})(?:\b["']|\b)\s*[:=]\s*["']([^"'\r\n]{6,})["']"""
        )

        # YAML / Config bare assignment on its own line (e.g. DB_PASSWORD: hunter2hunter2)
        # Excludes code line endings like semicolons, commas, or braces
        self.yaml_assignment_pattern = re.compile(
            r"""(?im)^\s*["']?([a-zA-Z0-9_]{0,40}(?:api[_-]?key|secret|token|password|passwd)[a-zA-Z0-9_]{0,40})["']?\s*[:=]\s*["']?([^"'\s\r\n;,{}]{6,})["']?\s*$"""
        )

        # Bearer token pattern (HTTP Authorization headers or curl commands)
        self.bearer_pattern = re.compile(
            r"""(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9_\-\.]{15,})"""
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

        if self.state_file and os.path.exists(self.state_file):
            self.load_state()

    def _invalidate_regex_cache(self):
        """Invalidates compiled regex caches when secrets or placeholders change."""
        self._mask_regex = None
        self._demask_regex = None

    def load_env_file(self, path: str) -> int:
        """Loads secrets from a .env file, ignoring non-sensitive config keys and stripping comments."""
        loaded = 0
        try:
            items = {}
            try:
                from dotenv import dotenv_values
                parsed = dotenv_values(path)
                if parsed:
                    items = {k: v for k, v in parsed.items() if k and v}
            except Exception:
                items = {}

            if not items and os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            # Handle quotes and strip inline comments
                            if (val.startswith('"') and '"' in val[1:]) or (val.startswith("'") and "'" in val[1:]):
                                quote_char = val[0]
                                end_idx = val.find(quote_char, 1)
                                val = val[1:end_idx]
                            else:
                                if "#" in val:
                                    val = val.split("#", 1)[0].strip()
                                val = val.strip("\"'").strip()
                            items[key] = val

            for key, val in items.items():
                if not key or not val:
                    continue
                key_lower = key.lower()
                if key.upper() in IGNORE_ENV_KEYS:
                    continue
                if any(key_lower.endswith(sfx) for sfx in NON_SECRET_VAR_SUFFIXES):
                    continue
                if any(key_lower.startswith(pfx) for pfx in NON_SECRET_VAR_PREFIXES):
                    continue

                val_clean = val.strip().lower()
                if val_clean in IGNORE_ENV_VALUES or val_clean in DUMMY_VALUES or val_clean in NON_SECRET_TYPES:
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
                            val_clean = v.strip().lower()
                            if val_clean in ("true", "false", "null", "undefined") or val_clean in DUMMY_VALUES or val_clean in IGNORE_ENV_VALUES:
                                continue
                            self.register_secret(v.strip(), str(k).strip())
                else:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if line.lower() not in DUMMY_VALUES and line.lower() not in IGNORE_ENV_VALUES:
                                self.register_secret(line)
        except Exception as e:
            print(f"[Vault] Error loading secrets from {path}: {e}")

    def cleanup_expired(self) -> int:
        """Purges dynamic secrets older than state_ttl from memory and caches."""
        if self.state_ttl <= 0 or not self.dynamic_secrets:
            return 0
        now = time.time()
        with self._lock:
            expired = [
                ph for ph, info in self.dynamic_secrets.items()
                if (now - float(info.get("ts", 0))) > self.state_ttl
            ]
            for ph in expired:
                secret = self.placeholder_to_secret.pop(ph, None)
                if secret and secret in self.secret_to_placeholder:
                    del self.secret_to_placeholder[secret]
                del self.dynamic_secrets[ph]

            if expired:
                self._invalidate_regex_cache()
                if self.state_file:
                    self.save_state()
            return len(expired)

    def load_state(self):
        """Loads dynamically registered secrets from state_file, discarding expired entries and preventing collisions."""
        if not self.state_file or not os.path.exists(self.state_file):
            return
        with self._lock:
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        return
                    data = json.loads(content)
                    now = time.time()
                    loaded_count = 0

                    if isinstance(data, dict) and "secrets" in data:
                        items_dict = data.get("secrets", {})
                    else:
                        items_dict = data

                    for ph, info in items_dict.items():
                        if isinstance(info, dict):
                            secret = info.get("secret")
                            ts = float(info.get("ts", 0))
                            label = info.get("label")
                        else:
                            secret = str(info)
                            ts = now
                            label = None

                        if not secret:
                            continue

                        if self.state_ttl > 0 and (now - ts) > self.state_ttl:
                            continue

                        # Static secrets already loaded take absolute precedence
                        if secret in self.secret_to_placeholder:
                            continue

                        # Avoid placeholder collision with static secrets and normalize any inner double underscores
                        clean_base = re.sub(r"_+", "_", ph.strip("_"))
                        final_ph = f"__{clean_base}__"
                        if final_ph in self.placeholder_to_secret and self.placeholder_to_secret[final_ph] != secret:
                            clean_lbl = re.sub(r"[^A-Za-z0-9_]", "_", label).upper() if label else "SECRET"
                            clean_lbl = re.sub(r"_+", "_", clean_lbl).strip("_")
                            while True:
                                final_ph = f"__VAULT_{clean_lbl}_{secrets.token_hex(4)}__"
                                if final_ph not in self.placeholder_to_secret:
                                    break

                        self.secret_to_placeholder[secret] = final_ph
                        self.placeholder_to_secret[final_ph] = secret
                        self.dynamic_secrets[final_ph] = {"secret": secret, "ts": ts, "label": label}
                        loaded_count += 1

                    self._invalidate_regex_cache()
                    if loaded_count > 0:
                        print(f"[Vault] Restored {loaded_count} dynamic secret mapping(s) from state file.")
            except Exception as e:
                print(f"[Vault] Error loading state file: {e}")

    def save_state(self):
        """Persists dynamic secret mappings to state_file atomically with 0o600 permissions."""
        if not self.state_file or not self.dynamic_secrets:
            return
        with self._state_lock:
            try:
                tmp_path = f"{self.state_file}.tmp_{os.getpid()}_{time.time_ns()}"
                payload = {
                    "secrets": self.dynamic_secrets
                }
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)

                if hasattr(os, "chmod") and sys.platform != "win32":
                    try:
                        os.chmod(tmp_path, 0o600)
                    except Exception:
                        pass

                os.replace(tmp_path, self.state_file)
            except Exception as e:
                print(f"[Vault] Error saving state file: {e}")

    def register_secret(self, secret: str, label: Optional[str] = None, is_dynamic: bool = False) -> str:
        if not secret or len(secret) < 3:
            return secret

        with self._lock:
            if secret in self.secret_to_placeholder:
                return self.secret_to_placeholder[secret]

            if label:
                if label.startswith("__") and label.endswith("__") and len(label) > 4:
                    clean_tag = re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9_]", "_", label[2:-2])).strip("_")
                    placeholder = f"__{clean_tag}__"
                else:
                    clean_label = re.sub(r"[^A-Za-z0-9_]", "_", label).upper()
                    clean_label = re.sub(r"_+", "_", clean_label).strip("_")
                    while True:
                        placeholder = f"__VAULT_{clean_label}_{secrets.token_hex(4)}__"
                        if placeholder not in self.placeholder_to_secret:
                            break
            else:
                while True:
                    placeholder = f"__VAULT_SECRET_{secrets.token_hex(4)}__"
                    if placeholder not in self.placeholder_to_secret:
                        break

            if placeholder in self.placeholder_to_secret:
                clean_base = re.sub(r"_+", "_", placeholder.strip("_"))
                while True:
                    placeholder = f"__{clean_base}_{secrets.token_hex(4)}__"
                    if placeholder not in self.placeholder_to_secret:
                        break

            self.secret_to_placeholder[secret] = placeholder
            self.placeholder_to_secret[placeholder] = secret
            self._invalidate_regex_cache()

        if is_dynamic:
            self.dynamic_secrets[placeholder] = {
                "secret": secret,
                "ts": time.time(),
                "label": label or ""
            }

        if self.on_mask:
            self.on_mask(placeholder, label or "SECRET")

        return placeholder

    def scan_and_register_dynamic(self, text: str) -> List[Tuple[str, str]]:
        found = []
        with self._lock:
            initial_count = len(self.dynamic_secrets)

            # 1. Contextual assignments in code and JSON with quoted keys & values
            for m in self.assignment_pattern.finditer(text):
                var_name = m.group(1)
                val = m.group(2)
                var_lower = var_name.lower()
                if any(var_lower.endswith(sfx) for sfx in NON_SECRET_VAR_SUFFIXES):
                    continue
                if any(var_lower.startswith(pfx) for pfx in NON_SECRET_VAR_PREFIXES):
                    continue
                if val and val.strip().lower() in DUMMY_VALUES:
                    continue
                if val and val not in self.secret_to_placeholder and not val.startswith("__VAULT_"):
                    ph = self.register_secret(val, var_name, is_dynamic=True)
                    found.append((val, ph))

            # 1.1 YAML / bare config assignments on individual lines
            for m in self.yaml_assignment_pattern.finditer(text):
                var_name = m.group(1)
                val = m.group(2).strip().rstrip(";,")
                var_lower = var_name.lower()
                if any(var_lower.endswith(sfx) for sfx in NON_SECRET_VAR_SUFFIXES):
                    continue
                if any(var_lower.startswith(pfx) for pfx in NON_SECRET_VAR_PREFIXES):
                    continue

                val_lower = val.lower()
                if val_lower in DUMMY_VALUES or val_lower in IGNORE_ENV_VALUES or val_lower in NON_SECRET_TYPES:
                    continue

                # Skip type annotations like Optional[str], List[string], Array<string>, etc.
                if any(val_lower.startswith(t_pfx) for t_pfx in ("optional[", "list[", "dict[", "set[", "tuple[", "array<", "map<", "record<")):
                    continue

                # Skip template expressions and environment substitutions (${VAR}, $VAR, {{VAR}})
                if "${" in val or "}}" in val or val.startswith("$") or (val.startswith("<") and val.endswith(">")):
                    continue

                # Filter out identifiers/words without digits, without symbols, and without mixed case:
                # A genuine bare config secret has digits, symbols, or mixed case.
                # Pure letters in single case (e.g. 'string', 'password', 'custom') are code words/types.
                has_digits = any(c.isdigit() for c in val)
                has_symbols = any(c in "-_./@=+!#$%&*?" for c in val)
                is_mixed_case = any(c.islower() for c in val) and any(c.isupper() for c in val)
                if not (has_digits or has_symbols or is_mixed_case):
                    continue

                if val and val not in self.secret_to_placeholder and not val.startswith("__VAULT_"):
                    ph = self.register_secret(val, var_name, is_dynamic=True)
                    found.append((val, ph))

            # 1.1 Bearer tokens in Authorization headers / curl
            for m in self.bearer_pattern.finditer(text):
                tok = m.group(1).strip()
                if tok and tok.lower() not in DUMMY_VALUES and tok not in self.secret_to_placeholder and not tok.startswith("__VAULT_"):
                    ph = self.register_secret(tok, "BEARER_TOKEN", is_dynamic=True)
                    found.append((tok, ph))

            # 2. Environment exports
            for m in self.env_pattern.finditer(text):
                var_name = m.group(1)
                val = m.group(2)
                var_lower = var_name.lower()
                if any(var_lower.endswith(sfx) for sfx in NON_SECRET_VAR_SUFFIXES):
                    continue
                if val and (val.strip().lower() in DUMMY_VALUES or val.strip().lower() in IGNORE_ENV_VALUES):
                    continue
                if val and val not in self.secret_to_placeholder and not val.startswith("__VAULT_"):
                    ph = self.register_secret(val, var_name, is_dynamic=True)
                    found.append((val, ph))

            # 3. Signature patterns
            for pattern, label in self.signature_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match and len(match) >= 8 and not match.startswith("__VAULT_"):
                        if match not in self.secret_to_placeholder:
                            ph = self.register_secret(match, label, is_dynamic=True)
                            found.append((match, ph))

            # 4. Shannon Entropy analysis for arbitrary high-entropy tokens (>=20 chars)
            # Strip data URIs and long base64 blocks so image/audio blobs are not chopped into false-positive secrets
            text_for_entropy = re.sub(r"data:[a-zA-Z0-9/+.\-]+;base64,[A-Za-z0-9+/=]+", " ", text)
            text_for_entropy = re.sub(r"[A-Za-z0-9+/]{64,}={0,2}", " ", text_for_entropy)

            potential_tokens = re.findall(r"\b[A-Za-z0-9_\-\.]{20,}\b", text_for_entropy)
            for token in potential_tokens:
                if token in self.secret_to_placeholder or token.startswith("__VAULT_"):
                    continue
                if any(token.startswith(pfx) for pfx in ("call_", "toolu_", "chatcmpl-", "msg_", "resp_", "ft:", "gpt-", "claude-")):
                    continue
                # Ignore pure hex strings of length 32, 40, 64 (MD5, Git SHA-1, SHA-256 / Webpack hashes)
                if re.fullmatch(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", token):
                    continue
                # Ignore PascalCase / camelCase code identifiers composed of natural dictionary words
                if any(c.isupper() for c in token):
                    word_chunks = re.findall(r"[A-Z][a-z]{2,}", token)
                    if len(word_chunks) >= 2 and sum(len(w) for w in word_chunks) / len(token) > 0.60:
                        continue
                # Ignore file names with common extensions
                if re.search(r"\.(?:js|ts|py|json|html|css|jsx|tsx|go|rs|cpp|h|java|png|jpg|svg|lock|md)$", token, re.IGNORECASE):
                    continue
                # Ignore variable names / file stems with words joined by underscore
                if "_" in token:
                    subwords = [w.lower() for w in token.split("_") if w]
                    if any(sw in DUMMY_VALUES or sw in IGNORE_ENV_VALUES or sw in ("password", "passwd", "secret", "token", "key", "backup", "temp", "file") for sw in subwords):
                        continue
                # Ignore path separators or URLs
                if "/" in token or "\\" in token or token.startswith("http"):
                    continue

                if re.search(r"[A-Za-z]", token) and re.search(r"[0-9]", token):
                    h = calculate_shannon_entropy(token)
                    if h >= 3.70:
                        ph = self.register_secret(token, "ENTROPY_KEY", is_dynamic=True)
                        found.append((token, ph))

            # 5. IPv4 Addresses (Local & Public)
            for m in self.ipv4_pattern.finditer(text):
                ip = m.group(1)
                if ip in self.ipv4_exempt or ip in self.secret_to_placeholder or ip.startswith("__VAULT_"):
                    continue
                start_pos = m.start()
                if start_pos > 0 and text[start_pos - 1] in ("v", "V", "/"):
                    continue
                preceding = text[max(0, start_pos - 20):start_pos]
                if re.search(r"\b(?:version|ver|release|rel)\b", preceding, re.IGNORECASE):
                    continue

                clean_ip = ip.split("/")[0]
                if clean_ip.startswith("192.168.") or clean_ip.startswith("10.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", clean_ip):
                    ph = self.register_secret(ip, "LOCAL_IP", is_dynamic=True)
                else:
                    ph = self.register_secret(ip, "IP_ADDR", is_dynamic=True)
                found.append((ip, ph))

            # 6. IPv6 Addresses (Validated strictly with ipaddress module)
            for m in self.ipv6_candidate_pattern.finditer(text):
                cand = m.group(1)
                if cand.count(":") < 2:
                    continue
                try:
                    ip_obj = ipaddress.IPv6Address(cand)
                    # Ignore loopback, unspecified, multicast, and IANA reserved ranges (prevents masking code identifiers like a::b or face::cafe)
                    if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved:
                        continue
                    # Reject code identifiers or trivial 2-hextet values without colons/digits (e.g. a::b, face::cafe)
                    parts = [p for p in cand.split(":") if p]
                    if len(parts) < 3 and cand.count(":") < 3:
                        continue
                    if cand in self.secret_to_placeholder or cand.startswith("__VAULT_"):
                        continue
                    ph = self.register_secret(cand, "IPV6_ADDR", is_dynamic=True)
                    found.append((cand, ph))
                except ValueError:
                    continue

            if self.state_file and len(self.dynamic_secrets) > initial_count:
                self.save_state()

        return found

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Replaces all known and newly detected secrets in text with placeholders in a single pass."""
        if not text:
            return text, 0

        with self._lock:
            self.scan_and_register_dynamic(text)

            if not self.secret_to_placeholder:
                return text, 0

            if self._mask_regex is None:
                sorted_secrets = sorted(self.secret_to_placeholder.keys(), key=len, reverse=True)
                patterns = []
                for s in sorted_secrets:
                    esc = re.escape(s)
                    # Word boundaries ONLY for short alphanumeric secrets (< 8 chars) to prevent substring collisions (e.g. abc in abcdef)
                    # Longer secrets (>= 8 chars, like hunter2hunter2) are masked as normal substrings
                    if len(s) < 8 and re.fullmatch(r"^\w+$", s):
                        patterns.append(rf"\b{esc}\b")
                    else:
                        patterns.append(esc)
                self._mask_regex = re.compile("|".join(patterns))

            replacements = 0
            def _replace_secret(match: re.Match) -> str:
                nonlocal replacements
                replacements += 1
                return self.secret_to_placeholder[match.group(0)]

            masked = self._mask_regex.sub(_replace_secret, text)
            return masked, replacements

    def mask_payload(self, data: Any) -> Tuple[Any, int]:
        """
        Recursively masks string values in a JSON-serializable structure.
        Thinking/reasoning blocks (matched by `type`) are passed through intact; see _skip_symmetric.
        Keys in JSON_STRING_KEYS (like tool_calls function arguments) are parsed as inner JSON
        so that escaped characters (\n, \", \\) are matched against secrets without leaking.
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

                if k in JSON_STRING_KEYS and isinstance(v, str):
                    try:
                        inner_obj = json.loads(v)
                        masked_inner, count = self.mask_payload(inner_obj)
                        new_dict[k] = json.dumps(masked_inner, ensure_ascii=False)
                        total_replacements += count
                        continue
                    except Exception:
                        pass

                masked_v, count = self.mask_payload(v)
                new_dict[k] = masked_v
                total_replacements += count
            return new_dict, total_replacements
        return data, 0

    def demask_text(self, text: str, json_escaped: bool = False) -> Tuple[str, int]:
        """Restores placeholders in text back to real secrets in a single pass."""
        if not text or not self.placeholder_to_secret:
            return text, 0

        with self._lock:
            if self._demask_regex is None:
                sorted_placeholders = sorted(self.placeholder_to_secret.keys(), key=len, reverse=True)
                self._demask_regex = re.compile("|".join(re.escape(ph) for ph in sorted_placeholders))

            restorations = 0
            def _replace_placeholder(match: re.Match) -> str:
                nonlocal restorations
                placeholder = match.group(0)
                real_secret = self.placeholder_to_secret[placeholder]
                restorations += 1
                if self.on_demask:
                    self.on_demask(placeholder, real_secret)
                if json_escaped:
                    return json.dumps(real_secret)[1:-1]
                return real_secret

            result = self._demask_regex.sub(_replace_placeholder, text)
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

                if k in JSON_STRING_KEYS and isinstance(v, str):
                    try:
                        inner_obj = json.loads(v)
                        demasked_inner, count = self.demask_payload(inner_obj)
                        new_dict[k] = json.dumps(demasked_inner, ensure_ascii=False)
                        total_restorations += count
                        continue
                    except Exception:
                        demasked_v, count = self.demask_text(v, json_escaped=True)
                        new_dict[k] = demasked_v
                        total_restorations += count
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
    Buffers ONLY when a genuine unclosed placeholder prefix (e.g. '__VAULT_API' or trailing '_')
    is detected at the tail of the stream.
    Valid unclosed placeholder prefixes must strictly match ^__[A-Za-z0-9_]*$ without spaces.
    """
    def __init__(self, vault: SecretVault, max_placeholder_len: int = 100, json_escaped: bool = False):
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
            # Check if buffer ends with a single '_' (might be start of '__')
            if self.buffer.endswith("_"):
                to_emit = self.buffer[:-1]
                self.buffer = "_"
                return to_emit
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
    Strictly preserves SSE event headers (e.g. event: content_block_stop) and formats synthetic deltas.
    """
    def __init__(self, vault: SecretVault):
        self.vault = vault
        self.raw_line_buffer = ""
        self.content_demasker = TextStreamDemasker(vault, json_escaped=False)
        self.stream_demaskers: Dict[str, TextStreamDemasker] = {}
        self.last_responses_event: Optional[Dict[str, Any]] = None
        self.saw_choices: bool = False
        self.pending_event_lines: List[str] = []

    def _get_stream_demasker(self, key: str, json_escaped: bool = False) -> TextStreamDemasker:
        if key not in self.stream_demaskers:
            self.stream_demaskers[key] = TextStreamDemasker(self.vault, json_escaped=json_escaped)
        return self.stream_demaskers[key]

    def _emit_pending_events(self, output: List[str]):
        if self.pending_event_lines:
            for pel in self.pending_event_lines:
                demasked_line, _ = self.vault.demask_text(pel)
                output.append(demasked_line + "\n")
            self.pending_event_lines.clear()

    def process_raw_chunk(self, chunk: str) -> str:
        self.raw_line_buffer += chunk
        output = []

        while "\n" in self.raw_line_buffer:
            line, self.raw_line_buffer = self.raw_line_buffer.split("\n", 1)
            line = line.rstrip("\r")

            if not line:
                self._emit_pending_events(output)
                output.append("\n")
                continue

            if line.startswith(("event:", "id:", "retry:")):
                self.pending_event_lines.append(line)
                continue

            if line.startswith("data:"):
                data_str = line[5:].strip()

                if data_str == "[DONE]":
                    flushed = self.flush_internal()
                    if flushed:
                        output.append(flushed)
                    self._emit_pending_events(output)
                    output.append("data: [DONE]\n")
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
                                call_id = event_data.get("call_id") or event_data.get("item_id", "default")
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
                            call_id = event_data.get("call_id") or event_data.get("item_id", "default")
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
                            if "arguments" in event_data and isinstance(event_data["arguments"], str):
                                event_data["arguments"] = self.vault.demask_text(event_data["arguments"], json_escaped=True)[0]
                                modified = True

                        elif ev_type == "response.output_item.done":
                            if "item" in event_data and isinstance(event_data["item"], dict):
                                item = event_data["item"]
                                if "arguments" in item and isinstance(item["arguments"], str):
                                    item["arguments"] = self.vault.demask_text(item["arguments"], json_escaped=True)[0]
                                    modified = True

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

                                    prefix = f"openai_tc_{c_idx}_"
                                    for key in list(self.stream_demaskers.keys()):
                                        if key.startswith(prefix):
                                            flushed_tc = self.stream_demaskers[key].flush()
                                            if flushed_tc:
                                                try:
                                                    t_idx = int(key[len(prefix):])
                                                except ValueError:
                                                    t_idx = 0
                                                tc_list = choice.setdefault("delta", {}).setdefault("tool_calls", [])
                                                matched = False
                                                for existing_tc in tc_list:
                                                    if existing_tc.get("index") == t_idx:
                                                        func = existing_tc.setdefault("function", {})
                                                        func["arguments"] = (func.get("arguments") or "") + flushed_tc
                                                        matched = True
                                                        break
                                                if not matched:
                                                    tc_list.append({
                                                        "index": t_idx,
                                                        "function": {"arguments": flushed_tc}
                                                    })
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
                                output.append(f"event: content_block_delta\ndata: {json.dumps(synth, ensure_ascii=False)}\n\n")

                            if flushed_tc:
                                synth_tc = {
                                    "type": "content_block_delta",
                                    "index": block_idx,
                                    "delta": {"type": "input_json_delta", "partial_json": flushed_tc}
                                }
                                output.append(f"event: content_block_delta\ndata: {json.dumps(synth_tc, ensure_ascii=False)}\n\n")

                    if not modified and isinstance(event_data, (dict, list)):
                        event_data, _ = self.vault.demask_payload(event_data)

                    self._emit_pending_events(output)
                    output.append(f"data: {json.dumps(event_data, ensure_ascii=False)}\n")

                except Exception:
                    self._emit_pending_events(output)
                    demasked_line, _ = self.vault.demask_text(line)
                    output.append(demasked_line + "\n")
            else:
                self._emit_pending_events(output)
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
                    output.append(f"event: content_block_delta\ndata: {json.dumps(synth, ensure_ascii=False)}\n\n")
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
        self._emit_pending_events(output)
        if self.raw_line_buffer:
            demasked_rem, _ = self.vault.demask_text(self.raw_line_buffer)
            output.append(demasked_rem)
            self.raw_line_buffer = ""

        return "".join(output)
