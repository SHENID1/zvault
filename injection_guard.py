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

@dataclass
class InjectionResult:
    is_malicious: bool = False
    risk_score: float = 0.0
    category: Optional[str] = None
    matched_patterns: List[str] = field(default_factory=list)
    has_obfuscation: bool = False
    details: str = ""


class PromptInjectionGuard:
    def __init__(self, sensitivity: float = 0.6):
        self.sensitivity = sensitivity

        # 1. Direct instruction overrides & memory wipes
        self.override_patterns = [
            (r"(?i)\b(?:ignore|disregard|forget|override|bypass|cancel)\b[\s\S]{0,40}\b(?:previous|all|prior|system|initial|core)\b[\s\S]{0,40}\b(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)\b", "INSTRUCTION_OVERRIDE"),
            (r"(?i)\b(?:disregard|ignore)\s+everything\s+(?:above|before|previously\s+said)\b", "INSTRUCTION_OVERRIDE"),
            (r"(?i)\b(?:new|updated)\s+(?:system\s+)?instructions?\s*:\s*(?:from\s+now\s+on|you\s+must|always)\b", "INSTRUCTION_OVERRIDE"),
        ]

        # 2. Jailbreak personas & developer mode hacks
        self.jailbreak_patterns = [
            (r"(?i)\b(?:dan\s*mode|developer\s*mode|jailbreak|unrestricted\s*mode|do\s*anything\s*now)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\byou\s+are\s+now\s+(?:unfiltered|unrestricted|free\s+of\s+rules|an\s+evil\s+ai)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\bpretend\s+(?:you\s+have\s+no\s+rules|you\s+are\s+in\s+developer\s+mode|to\s+be\s+an\s+unfiltered)\b", "JAILBREAK_PERSONA"),
            (r"(?i)\b(?:grandma\s+exploit|hypothetical\s+scenarios?\s+without\s+ethics)\b", "JAILBREAK_PERSONA"),
        ]

        # 3. System prompt & secret exfiltration leaks
        self.prompt_leak_patterns = [
            (r"(?i)\b(?:repeat|reveal|print|output|display|show|dump)\b[\s\S]{0,30}\b(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|instructions?\s+above|hidden\s+prompt)\b", "PROMPT_LEAK"),
            (r"(?i)\bwhat\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+(?:instructions?|prompts?)\b", "PROMPT_LEAK"),
            (r"(?i)\boutput\s+everything\s+starting\s+with\s+[\"']?(?:you\s+are|<\|im_start\|>)\b", "PROMPT_LEAK"),
        ]

        # 4. Role spoofing & delimiter injections
        self.role_spoofing_patterns = [
            (r"(?i)<\|im_start\|>\s*(?:system|assistant|user)", "ROLE_SPOOFING"),
            (r"(?i)\[\s*SYSTEM\s*\]\s*:", "ROLE_SPOOFING"),
            (r"(?i)\n\s*System\s*:\s*(?:You\s+are|Override|Forget)", "ROLE_SPOOFING"),
            (r"(?i)\[\s*ASSISTANT\s*\]\s*:\s*I\s+will\s+now\s+follow", "ROLE_SPOOFING"),
        ]

        # 5. Remote payload execution & destructive shell payloads
        self.destructive_shell_patterns = [
            (r"(?i)\b(?:invoke-webrequest|iwr|curl|wget)\b[\s\S]{0,60}\|\s*(?:iex|sh|bash)\b", "MALICIOUS_DOWNLOAD_EXEC"),
            (r"(?i)\bpowershell(?:\.exe)?\s+-[eE]nc(?:odedcommand)?\b", "ENCODED_POWERSHELL"),
            (r"(?i)\b(?:rm\s+-rf\s+\/|rmdir\s+\/s\s+\/q\s+[c-zC-Z]:\\|format\s+[c-zC-Z]:)\b", "DESTRUCTIVE_COMMAND"),
        ]

    def normalize(self, text: str) -> Tuple[str, bool]:
        """Strips invisible characters and normalizes Unicode."""
        has_invisible = bool(INVISIBLE_REGEX.search(text))
        cleaned = INVISIBLE_REGEX.sub("", text)
        # Unicode normalization (handles homoglyphs / accents / math fonts)
        normalized = unicodedata.normalize("NFKD", cleaned)
        return normalized, has_invisible

    def scan_base64_payloads(self, text: str) -> List[Tuple[str, str]]:
        """Finds base64 encoded strings and checks if decoded content contains overrides."""
        findings = []
        # Match base64 tokens with optional padding = or ==
        b64_candidates = re.findall(r"(?:^|\s|[\"'])((?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)(?:$|\s|[\"'])", text)

        for b64_str in b64_candidates:
            try:
                decoded_bytes = base64.b64decode(b64_str, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text) >= 10:
                    # Check decoded text for overrides
                    for pattern, label in self.override_patterns + self.jailbreak_patterns:
                        if re.search(pattern, decoded_text):
                            findings.append((b64_str, f"BASE64_OBFUSCATED_{label}"))
                            break
            except Exception:
                pass
        return findings

    def scan_text(self, text: str) -> InjectionResult:
        """Analyzes text for prompt injections, jailbreaks, and evasions."""
        if not text or len(text) < 10:
            return InjectionResult(is_malicious=False, risk_score=0.0)

        normalized_text, has_invisible = self.normalize(text)
        matched = []
        highest_category = None
        base_score = 0.0

        # Check invisible characters (obfuscation attempt)
        if has_invisible:
            base_score += 0.35

        # 1. Base64 obfuscated payloads
        b64_findings = self.scan_base64_payloads(text)
        if b64_findings:
            base_score += 0.6
            for _, tag in b64_findings:
                matched.append(tag)
                highest_category = tag

        # 2. Scan normalized text against pattern sets
        pattern_groups = [
            (self.destructive_shell_patterns, 0.85),
            (self.override_patterns, 0.75),
            (self.jailbreak_patterns, 0.70),
            (self.role_spoofing_patterns, 0.65),
            (self.prompt_leak_patterns, 0.50),
        ]

        for patterns, weight in pattern_groups:
            for pattern, label in patterns:
                # Test on both original and normalized text
                if re.search(pattern, normalized_text) or re.search(pattern, text):
                    matched.append(label)
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

    def scan_messages(self, messages: Any) -> InjectionResult:
        """Scans all message contents in a chat completions payload."""
        combined_text = []

        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict):
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        combined_text.append(content)
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and "text" in part:
                                combined_text.append(str(part["text"]))
        elif isinstance(messages, str):
            combined_text.append(messages)

        full_content = "\n".join(combined_text)
        return self.scan_text(full_content)
