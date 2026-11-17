import re
import base64
import unicodedata
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field

# Zero-width / invisible unicode characters commonly used to split keywords
INVISIBLE_CHARS = [
    "\u200B",  # zero-width space
    "\u200C",  # zero-width non-joiner
    "\u200D",  # zero-width joiner
    "\uFEFF",  # zero-width no-break space (BOM)
    "\u2060",  # word joiner
    "\u200E",  # left-to-right mark
    "\u200F",  # right-to-left mark
    "\u00AD",  # soft hyphen
]
INVISIBLE_REGEX = re.compile("[" + "".join(INVISIBLE_CHARS) + "]")

# Homoglyph translation table (Cyrillic lookalikes -> Latin equivalents)
CYRILLIC_TO_LATIN = str.maketrans({
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X'
})

@dataclass
class InjectionResult:
    is_malicious: bool = False
    risk_score: float = 0.0
    category: Optional[str] = None
    matched_patterns: List[str] = field(default_factory=list)
    has_obfuscation: bool = False
    details: str = ""


class PromptInjectionGuard:
    def __init__(self, sensitivity: float = 0.65):
        self.sensitivity = sensitivity

        # 1. Direct instruction overrides & memory wipes (English)
        self.override_patterns = [
            (r"(?i)\b(?:ignore|disregard|forget|override|bypass|cancel)\b[\s\S]{0,40}\b(?:previous|all|prior|system|initial|core)\b[\s\S]{0,40}\b(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)\b", "INSTRUCTION_OVERRIDE"),
            (r"(?i)\b(?:disregard|ignore)\s+everything\s+(?:above|before|previously\s+said)\b", "INSTRUCTION_OVERRIDE"),
            (r"(?i)\b(?:new|updated)\s+(?:system\s+)?instructions?\s*:\s*(?:from\s+now\s+on|you\s+must|always)\b", "INSTRUCTION_OVERRIDE"),
        ]

        # 2. Instruction overrides & memory wipes (Russian)
        self.override_patterns_ru = [
            (r"(?i)\b(?:игнорируй|забудь|отмени|пропусти|сбрось)\b[\s\S]{0,40}\b(?:все|предыдущие|прошлые|системные|исходные|начальные)\b[\s\S]{0,40}\b(?:инструкции|правила|указания|директивы|промпты|ограничения)\b", "INSTRUCTION_OVERRIDE_RU"),
            (r"(?i)\b(?:забудь|игнорируй)\s+вс[её](?:,\s*что)?\s+(?:было\s+)?(?:выше|до\s+этого|сказанное|ранее)\b", "INSTRUCTION_OVERRIDE_RU"),
            (r"(?i)\b(?:новые|обновленн(?:ые|ая))\s+(?:системн(?:ые|ая)\s+)?инструкци(?:и|я)\s*:\s*(?:отныне|ты\s+должен|всегда|делай\s+вс[её])\b", "INSTRUCTION_OVERRIDE_RU"),
        ]

        # 3. Jailbreak personas & developer mode hacks (EN & RU)
        self.jailbreak_patterns = [
            (r"(?i)\b(?:dan\s*mode|developer\s*mode|jailbreak|unrestricted\s*mode|do\s*anything\s*now)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\byou\s+are\s+now\s+(?:unfiltered|unrestricted|free\s+of\s+rules|an\s+evil\s+ai)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\bpretend\s+(?:you\s+have\s+no\s+rules|you\s+are\s+in\s+developer\s+mode|to\s+be\s+an\s+unfiltered)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\b(?:grandma\s+exploit|hypothetical\s+scenarios?\s+without\s+ethics)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\b(?:ты\s+теперь|действуй\s+как|представь,\s+что\s+ты)\s+(?:без\s+ограничений|злой\s+ии|взломанный|jailbreak|дан\s+мод)\b", "JAILBREAK_PERSONA_RU"),
        ]

        # 4. System prompt & secret exfiltration leaks (EN & RU)
        self.prompt_leak_patterns = [
            (r"(?i)\b(?:repeat|reveal|print|output|display|show|dump)\b[\s\S]{0,30}\b(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|instructions?\s+above|hidden\s+prompt)\b", "PROMPT_LEAK"),
            (r"(?i)\bwhat\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+(?:instructions?|prompts?)\b", "PROMPT_LEAK"),
            (r"(?i)\boutput\s+everything\s+starting\s+with\s+[\"']?(?:you\s+are|<\|im_start\|>)\b", "PROMPT_LEAK"),
            (r"(?i)\b(?:выведи|покажи|распечатай|повтори)\s+(?:свой\s+)?(?:системный\s+промпт|исходные\s+инструкции|инструкции\s+выше)\b", "PROMPT_LEAK_RU"),
        ]

        # 5. Role spoofing & delimiter injections
        self.role_spoofing_patterns = [
            (r"(?i)<\|im_start\|>\s*(?:system|assistant|user)", "ROLE_SPOOFING"),
            (r"(?i)\[\s*SYSTEM\s*\]\s*:", "ROLE_SPOOFING"),
            (r"(?i)\n\s*System\s*:\s*(?:You\s+are|Override|Forget)", "ROLE_SPOOFING"),
            (r"(?i)\[\s*ASSISTANT\s*\]\s*:\s*I\s+will\s+now\s+follow", "ROLE_SPOOFING"),
        ]

        # 6. Destructive commands (strictly root filesystem / drive formatting, NOT normal build cleanup)
        self.destructive_shell_patterns = [
            (r"(?i)(?:\brm\s+-(?:r[fF]|f[rR]|r|f)\s+(?:\/(?:\*|\s|$|\;|\&))|rmdir\s+\/s\s+\/q\s+[c-zC-Z]:\\|format\s+[c-zC-Z]:)", "DESTRUCTIVE_COMMAND"),
            (r"(?i)\bpowershell(?:\.exe)?\s+-[eE]nc(?:odedcommand)?\b", "ENCODED_POWERSHELL"),
        ]

        # 7. Download & exec patterns (weight 0.55 so documentation examples in README don't trigger alone)
        self.download_exec_patterns = [
            (r"(?i)\b(?:invoke-webrequest|iwr|curl|wget)\b[\s\S]{0,60}\|\s*(?:iex|sh|bash)\b", "MALICIOUS_DOWNLOAD_EXEC"),
        ]

    def normalize(self, text: str) -> Tuple[str, str, bool]:
        """
        Strips invisible characters and normalizes Unicode.
        Returns: (nfkd_normalized_text, latin_homoglyph_normalized_text, has_invisible)
        """
        has_invisible = bool(INVISIBLE_REGEX.search(text))
        cleaned = INVISIBLE_REGEX.sub("", text)
        normalized = unicodedata.normalize("NFKD", cleaned)
        latin_normalized = normalized.translate(CYRILLIC_TO_LATIN)
        return normalized, latin_normalized, has_invisible

    def scan_base64_payloads(self, text: str) -> List[Tuple[str, str]]:
        findings = []
        b64_candidates = re.findall(r"(?:^|\s|[\"'])((?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)(?:$|\s|[\"'])", text)

        all_patterns = self.override_patterns + self.override_patterns_ru + self.jailbreak_patterns
        for b64_str in b64_candidates:
            try:
                decoded_bytes = base64.b64decode(b64_str, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text) >= 10:
                    norm, lat_norm, _ = self.normalize(decoded_text)
                    for pattern, label in all_patterns:
                        if re.search(pattern, norm) or re.search(pattern, lat_norm):
                            findings.append((b64_str, f"BASE64_OBFUSCATED_{label}"))
                            break
            except Exception:
                pass
        return findings

    def scan_text(self, text: str) -> InjectionResult:
        """Analyzes text for prompt injections, jailbreaks, and evasions."""
        if not text or len(text.strip()) < 5:
            return InjectionResult(is_malicious=False, risk_score=0.0)

        normalized_text, latin_text, has_invisible = self.normalize(text)
        matched = []
        highest_category = None
        base_score = 0.0

        if has_invisible:
            base_score += 0.35

        # 1. Base64 obfuscated payloads
        b64_findings = self.scan_base64_payloads(text)
        if b64_findings:
            base_score += 0.6
            for _, tag in b64_findings:
                matched.append(tag)
                highest_category = tag

        # 2. Scan text against pattern groups with balanced weights
        pattern_groups = [
            (self.destructive_shell_patterns, 0.85),
            (self.override_patterns, 0.75),
            (self.override_patterns_ru, 0.75),
            (self.jailbreak_patterns, 0.70),
            (self.role_spoofing_patterns, 0.65),
            (self.prompt_leak_patterns, 0.50),
        ]

        for patterns, weight in pattern_groups:
            for pattern, label in patterns:
                if (re.search(pattern, text) or
                    re.search(pattern, normalized_text) or
                    re.search(pattern, latin_text)):
                    matched.append(label)
                    base_score = max(base_score, weight)
                    if not highest_category:
                        highest_category = label

        # Download & execute: distinguish direct execution vs markdown code block / documentation example
        for pattern, label in self.download_exec_patterns:
            if (re.search(pattern, text) or
                re.search(pattern, normalized_text) or
                re.search(pattern, latin_text)):
                matched.append(label)
                is_doc_example = bool(re.search(r"```|(?:install|setup|usage|readme|example|docker|guide)[\s\S]{0,40}(?:curl|wget)", text, re.IGNORECASE))
                weight = 0.50 if is_doc_example else 0.70
                base_score = max(base_score, weight)
                if not highest_category:
                    highest_category = label

        # Additional risk if multiple patterns match
        if len(matched) > 1:
            base_score = min(1.0, base_score + 0.15)

        is_malicious = base_score >= self.sensitivity

        return InjectionResult(
            is_malicious=is_malicious,
            risk_score=round(base_score, 2),
            category=highest_category or ("OBFUSCATION" if has_invisible else "CLEAN"),
            matched_patterns=list(set(matched)),
            has_obfuscation=has_invisible or bool(b64_findings),
            details=f"Risk: {round(base_score, 2)}, Category: {highest_category}, Matches: {', '.join(set(matched))}" if is_malicious else "Safe"
        )

    def scan_payload(self, body_json: Any) -> InjectionResult:
        """
        Deep-scans an entire LLM request payload:
        - Chat completions (messages)
        - Anthropic top-level 'system' prompt
        - OpenAI / Anthropic 'tools' definitions
        - Responses API top-level 'input' and 'function_call_output'
        """
        combined_text = []

        if isinstance(body_json, dict):
            # 1. Top-level system prompt (Anthropic)
            sys_prompt = body_json.get("system")
            if isinstance(sys_prompt, str):
                combined_text.append(sys_prompt)
            elif isinstance(sys_prompt, list):
                for item in sys_prompt:
                    if isinstance(item, dict) and "text" in item:
                        combined_text.append(str(item["text"]))

            # 2. Top-level tools definitions
            tools = body_json.get("tools")
            if isinstance(tools, list):
                for t in tools:
                    if isinstance(t, dict):
                        func = t.get("function", t)
                        if "description" in func:
                            combined_text.append(str(func["description"]))

            # 3. Responses API top-level input array (containing function_call_output)
            input_data = body_json.get("input")
            if isinstance(input_data, list):
                for item in input_data:
                    if isinstance(item, dict):
                        # function_call_output items
                        if "output" in item:
                            combined_text.append(str(item["output"]))
                        if "content" in item:
                            c = item["content"]
                            if isinstance(c, str):
                                combined_text.append(c)
                            elif isinstance(c, list):
                                for part in c:
                                    if isinstance(part, dict) and "text" in part:
                                        combined_text.append(str(part["text"]))
                    elif isinstance(item, str):
                        combined_text.append(item)
            elif isinstance(input_data, str):
                combined_text.append(input_data)

            # 4. Messages list (Chat completions)
            messages = body_json.get("messages")
            if isinstance(messages, list):
                last_assistant_idx = -1
                for idx, msg in enumerate(messages):
                    if isinstance(msg, dict) and msg.get("role") == "assistant":
                        last_assistant_idx = idx

                untrusted_messages = messages[last_assistant_idx + 1:] if last_assistant_idx != -1 else messages

                for msg in untrusted_messages:
                    if isinstance(msg, dict):
                        content = msg.get("content", "")
                        if isinstance(content, str):
                            combined_text.append(content)
                        elif isinstance(content, list):
                            for part in content:
                                if isinstance(part, str):
                                    combined_text.append(part)
                                elif isinstance(part, dict):
                                    if "text" in part:
                                        combined_text.append(str(part["text"]))
                                    if part.get("type") == "tool_result":
                                        tr_content = part.get("content", "")
                                        if isinstance(tr_content, str):
                                            combined_text.append(tr_content)
                                        elif isinstance(tr_content, list):
                                            for sub in tr_content:
                                                if isinstance(sub, dict) and "text" in sub:
                                                    combined_text.append(str(sub["text"]))
                                    if "output" in part:
                                        combined_text.append(str(part["output"]))

        elif isinstance(body_json, list):
            for item in body_json:
                res = self.scan_payload(item)
                if res.is_malicious:
                    return res
        elif isinstance(body_json, str):
            combined_text.append(body_json)

        full_content = "\n".join(combined_text)
        return self.scan_text(full_content)

    def scan_messages(self, messages: Any) -> InjectionResult:
        """Backward-compatible wrapper for scan_payload."""
        if isinstance(messages, dict):
            return self.scan_payload(messages)
        return self.scan_payload({"messages": messages})
