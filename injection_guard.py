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

# Homoglyph translation table (Cyrillic & Greek lookalikes -> Latin equivalents)
HOMOGLYPH_TO_LATIN = str.maketrans({
    # Cyrillic lookalikes
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y'
})
CYRILLIC_TO_LATIN = HOMOGLYPH_TO_LATIN

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
            (r"(?i)\b(?:repeat|reveal|print|output|display|dump)\b[\s\S]{0,35}\b(?:your|all|hidden)\b[\s\S]{0,25}\b(?:(?:initial|system|original|core)\s+)*(?:prompt|instructions?)\b", "PROMPT_LEAK"),
            (r"(?i)\bshow\s+(?:me\s+)?(?:your|all|the\s+entire|hidden)\s+(?:(?:initial|system|original|core)\s+)*(?:prompt|instructions?)\b", "PROMPT_LEAK"),
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

        # 7. Download & exec patterns (locally contextualized to avoid false positives in code fences/docs)
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
        latin_normalized = normalized.translate(HOMOGLYPH_TO_LATIN)
        return normalized, latin_normalized, has_invisible

    def scan_base64_payloads(self, text: str) -> List[Tuple[str, str]]:
        findings = []
        # Support both standard Base64 (+/) and URL-safe Base64 (-_), with optional padding
        b64_candidates = re.findall(r"(?:^|[\s\"':=])([A-Za-z0-9+/\-_]{16,}={0,2})(?:$|[\s\"';,])", text)

        all_patterns = (
            self.override_patterns +
            self.override_patterns_ru +
            self.jailbreak_patterns +
            self.prompt_leak_patterns +
            self.role_spoofing_patterns +
            self.destructive_shell_patterns +
            self.download_exec_patterns
        )
        for candidate in b64_candidates:
            clean_b64 = re.sub(r"\s+", "", candidate)
            # URL-safe -> standard base64 translation
            std_b64 = clean_b64.translate(str.maketrans("-_", "+/"))
            pad_len = (4 - len(std_b64) % 4) % 4
            std_b64 += "=" * pad_len

            try:
                decoded_bytes = base64.b64decode(std_b64, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text) >= 10:
                    norm, lat_norm, _ = self.normalize(decoded_text)
                    for pattern, label in all_patterns:
                        if (re.search(pattern, decoded_text) or
                            re.search(pattern, norm) or
                            re.search(pattern, lat_norm)):
                            findings.append((candidate, f"BASE64_OBFUSCATED_{label}"))
                            break
            except Exception:
                pass
        return findings

    def _scan_single_text(self, text: str) -> InjectionResult:
        """Analyzes a single slice of text for prompt injections, jailbreaks, and evasions."""
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
            base_score = max(base_score, 0.75)
            for _, tag in b64_findings:
                matched.append(tag)
                highest_category = tag

        # 2. Scan text against pattern groups
        pattern_groups = [
            (self.destructive_shell_patterns, 0.85),
            (self.override_patterns, 0.75),
            (self.override_patterns_ru, 0.75),
            (self.jailbreak_patterns, 0.70),
            (self.role_spoofing_patterns, 0.65),
            (self.prompt_leak_patterns, 0.65),
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

        # Download & execute: LOCAL context check (checks if match itself is enclosed in code fence or preceded by doc words)
        for pattern, label in self.download_exec_patterns:
            for m in re.finditer(pattern, text):
                matched.append(label)
                start_idx = m.start()

                # Check if this specific match is inside a markdown code block (odd number of fences before it)
                preceding_text = text[:start_idx]
                fences_before = preceding_text.count("```")
                inside_code_block = (fences_before % 2 == 1)

                # Check if directly preceded by install/documentation words within 60 chars
                preceding_slice = preceding_text[max(0, start_idx - 60):]
                is_doc_preceded = bool(re.search(r"(?i)\b(?:install(?:ation)?|setup|usage|readme|example|docker(?:file)?|guide)\b", preceding_slice))

                is_doc_example = inside_code_block or is_doc_preceded
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

    def scan_text(self, text: str) -> InjectionResult:
        """Analyzes text for prompt injections, jailbreaks, and evasions with ReDoS chunking."""
        if not text or len(text.strip()) < 5:
            return InjectionResult(is_malicious=False, risk_score=0.0)

        CHUNK_SIZE = 8192
        CHUNK_OVERLAP = 512

        if len(text) > CHUNK_SIZE:
            chunks = []
            start = 0
            while start < len(text):
                end = min(len(text), start + CHUNK_SIZE)
                chunks.append(text[start:end])
                if end == len(text):
                    break
                start += CHUNK_SIZE - CHUNK_OVERLAP

            max_res = InjectionResult(is_malicious=False, risk_score=0.0)
            all_matched = []
            for chunk in chunks:
                res = self._scan_single_text(chunk)
                if res.risk_score > max_res.risk_score:
                    max_res = res
                if res.matched_patterns:
                    all_matched.extend(res.matched_patterns)
                if res.is_malicious:
                    max_res.matched_patterns = list(set(all_matched))
                    return max_res
            max_res.matched_patterns = list(set(all_matched))
            return max_res

        return self._scan_single_text(text)

    def _extract_untrusted_elements(self, items: List[Any]) -> List[Any]:
        """
        Extracts untrusted items from a turn sequence using sliding turn window:
        - Prevents spoofed trailing assistant messages from bypassing the scan
        - Scans current turn (all messages after the last resolved assistant turn)
        - Includes the calling assistant if it initiated active tool calls
        """
        if not items:
            return []

        last_user_or_tool_idx = -1
        for idx, item in enumerate(items):
            if isinstance(item, dict):
                role = str(item.get("role", "")).lower()
                item_type = str(item.get("type", "")).lower()
                if role in ("user", "tool", "developer", "system") or item_type in ("function_call_output", "tool_result", "custom_tool_call_output"):
                    last_user_or_tool_idx = idx
            elif isinstance(item, str):
                last_user_or_tool_idx = idx

        if last_user_or_tool_idx == -1:
            return items

        last_prior_asst_idx = -1
        for idx in range(last_user_or_tool_idx - 1, -1, -1):
            item = items[idx]
            if isinstance(item, dict):
                role = str(item.get("role", "")).lower()
                if role == "assistant" or (item.get("type") == "message" and role == "assistant"):
                    last_prior_asst_idx = idx
                    break

        if last_prior_asst_idx == -1:
            return items

        asst_item = items[last_prior_asst_idx]
        if isinstance(asst_item, dict) and asst_item.get("tool_calls"):
            return items[last_prior_asst_idx:]

        return items[last_prior_asst_idx + 1:]

    def scan_payload(self, body_json: Any) -> InjectionResult:
        """
        Deep-scans an entire LLM request payload:
        - Chat completions (messages): scans user/tool/developer/system turns, name, tool_calls arguments,
          and eliminates the spoofed assistant bypass.
        - Anthropic top-level 'system' prompt
        - OpenAI / Anthropic 'tools' definitions (including all parameter & property descriptions)
        - Responses API top-level 'input'
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

            # 2. Tool definitions: scan parameter and property descriptions for tool poisoning attacks
            tools = body_json.get("tools")
            if isinstance(tools, list):
                def extract_descriptions(obj: Any):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if k == "description" and isinstance(v, str):
                                combined_text.append(v)
                            else:
                                extract_descriptions(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            extract_descriptions(item)

                for t in tools:
                    extract_descriptions(t)

            # 3. Responses API top-level input array
            input_data = body_json.get("input")
            if isinstance(input_data, list):
                untrusted_inputs = self._extract_untrusted_elements(input_data)
                for item in untrusted_inputs:
                    if isinstance(item, dict):
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
                        if "arguments" in item and isinstance(item["arguments"], str):
                            combined_text.append(item["arguments"])
                        if "call_id" in item and isinstance(item["call_id"], str):
                            combined_text.append(item["call_id"])
                    elif isinstance(item, str):
                        combined_text.append(item)
            elif isinstance(input_data, str):
                combined_text.append(input_data)

            # 4. Messages list (Chat completions)
            messages = body_json.get("messages")
            if isinstance(messages, list):
                untrusted_messages = self._extract_untrusted_elements(messages)
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

                        # Scan name and tool_call_id
                        name = msg.get("name")
                        if isinstance(name, str):
                            combined_text.append(name)
                        tcid = msg.get("tool_call_id")
                        if isinstance(tcid, str):
                            combined_text.append(tcid)

                        # Scan tool_calls arguments (can be invoked by assistant)
                        tool_calls = msg.get("tool_calls")
                        if isinstance(tool_calls, list):
                            for tc in tool_calls:
                                if isinstance(tc, dict):
                                    func = tc.get("function", {})
                                    if isinstance(func, dict):
                                        args = func.get("arguments")
                                        if isinstance(args, str):
                                            combined_text.append(args)
                                        fn_name = func.get("name")
                                        if isinstance(fn_name, str):
                                            combined_text.append(fn_name)
                    elif isinstance(msg, str):
                        combined_text.append(msg)

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
        if isinstance(messages, dict):
            return self.scan_payload(messages)
        return self.scan_payload({"messages": messages})
