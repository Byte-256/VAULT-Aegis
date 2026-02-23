"""
VAULT Aegis - Prompt Injection Detector
Enhanced keyword/pattern-based detection with comprehensive coverage.
Uses semantic analysis to catch variations like "forgot", "ignore", etc.
"""

import re


def detect_injection(text: str) -> dict:
    """
    Enhanced detection for prompt injection attacks.
    Catches variations like: forgot, ignore, disregard, override, etc.
    Uses comprehensive regex patterns + semantic analysis.
    """
    text_lower = text.lower()

    # Action verbs that attempt to override instructions
    override_verbs = [
        "forget",
        "forgot",
        "forgetting",
        "forgets",
        "ignore",
        "ignored",
        "ignoring",
        "ignores",
        "disregard",
        "disregarding",
        "override",
        "overriding",
        "overridden",
        "overwrite",
        "overwriting",
        "overwrites",
        "discard",
        "discarding",
        "drop",
        "dismiss",
        "unset",
        "clear",
        "reset",
        "erase",
        "wipe",
        "bypass",
        "circumvent",
        "break",
        "breakout",
        "disable",
        "deactivate",
        "turn off",
    ]

    # Targets of override attempts
    override_targets = [
        "previous",
        "prior",
        "above",
        "earlier",
        "initial",
        "original",
        "old",
        "instructions",
        "commands",
        "directives",
        "orders",
        "rules",
        "guidelines",
        "policy",
        "policies",
        "system",
        "system instructions",
        "system prompt",
        "system message",
        "system role",
        "restrictions",
        "limitations",
        "constraints",
        "boundaries",
        "safety",
        "safety guidelines",
        "your rules",
        "my rules",
        "your guidelines",
        "my guidelines",
    ]

    # Comprehensive injection patterns
    patterns = [
        # Forgot/ignore + previous/prior/above + instructions
        r"(?i)\b(forget|forgot|forgetting|ignore|ignored|disregard|discard|clear|reset)\s+(all\s+)?(your|my|their|the|these|those|previous|prior|above|earlier|initial|original|old)\s+(instructions|commands|rules|guidelines|restrictions|limitations|system|directives|settings)\b",
        # Override/bypass patterns
        r"(?i)\b(override|overwrite|bypass|disable|deactivate)\s+(all\s+)?(system|security|restriction|rule|guideline|safety|filter|control)\b",
        # "As an AI" patterns
        r"(?i)\bas an?\s+(ai|chatbot|assistant|model|you are allowed|you have no|unrestricted)\b",
        # "You are now" (excluding benign uses)
        r"(?i)\byou are now\b(?!\s+(a?\s*helpful|\s*here|\s*ready|\s*able|to help))",
        # Simulate/pretend/act as
        r"(?i)\b(simulate|pretend|act as|roleplay)\s+(a?|\w+\s+)?(system|adult|jailbroken|unrestricted|different|evil|unethical)\b",
        # No restrictions
        r"(?i)\b(no|without)\s+(restriction|limit|filter|boundary|rule|guardrails)\b",
        r"(?i)\bunfiltered\b|\bunlocked\b|\bunbanned\b|\bno ethics\b|\bno moral\b",
        # Reveal system prompt
        r"(?i)\b(reveal|show|tell|expose|leak|share|print)\s+(me\s+)?(your|the|all\s+)?(system|hidden|secret|actual|real|original|internal)\s+(instruction|prompt|command|rule|system|guideline)\b",
        # Repeat after me
        r"(?i)\brepeat\s+(after\s+)?me\s*[:;,]?\s*",
        # System role override
        r"(?i)(?:^|\n)\s*system\s*[:\-]\s*",
        r"(?i)\[system\]|\[/system\]",
        r"(?i)###\s*system\s*###",
        # Code/markdown injection
        r'(?i)""".*?"""',
        r"(?i)```system.*?```",
        # Jailbreak terms
        r"(?i)\bdo\s+anything\b|\bdan\s+mode\b|\bstan\b|\bjailbroken\b|\bjailbreak\b",
        r"(?i)\bdeveloper\s+mode\b|\bdev\s+mode\b",
        r"(?i)\bhello\s+claude\b|\bhi\s+claude\b",
        # Multi-language (Chinese, Russian, etc)
        r"(?i)角色扮演|忽略|忘记|系统指令|忽略所有|忘记之前的",
        # Instruction modification
        r"(?i)instead\s+of\s+(your|previous|original)\s+instructions",
        r"(?i)new\s+instructions|new\s+rules|new\s+system",
        r"(?i)change\s+your\s+(instructions|rules|behavior)",
        # Credential harvesting
        r"(?i)show\s+(me\s+)?(your|all\s+)?(api|secret|password|token|key)",
        r"(?i)what\s+is\s+your\s+(system\s+)?(prompt|instruction)",
    ]

    # Check patterns first (highest confidence)
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return {
                "is_injection": True,
                "confidence": 0.95,
                "reason": f"Matched: {match.group()[:60]}",
                "method": "regex",
            }

    # Check verb + target combinations
    for verb in override_verbs:
        for target in override_targets:
            if verb in text_lower and target in text_lower:
                return {
                    "is_injection": True,
                    "confidence": 0.85,
                    "reason": f"Found '{verb}' + '{target}'",
                    "method": "semantic",
                }

    # Strong indicators
    strong_indicators = [
        "jailbreak",
        "jailbroken",
        "jail-breaking",
        "developer mode",
        "dev mode",
        "do anything now",
        "dan mode",
        "stan mode",
        "ignore all previous instructions",
        "forget all prior instructions",
        "forget all previous",
        "disregard all previous",
        "disregard prior",
        "reveal system prompt",
        "show system prompt",
        "show your instructions",
        "reveal your instructions",
        "override system",
        "bypass safety",
        "bypass restrictions",
    ]

    for indicator in strong_indicators:
        if indicator in text_lower:
            return {
                "is_injection": True,
                "confidence": 0.9,
                "reason": f"Strong: {indicator}",
                "method": "indicator",
            }

    return {
        "is_injection": False,
        "confidence": 0.0,
        "reason": "No injection detected",
        "method": "pattern",
    }


def detect_injection_with_bert(text: str) -> dict:
    """
    BERT-based detection (optional - requires transformers).
    This is a placeholder for when the user has proper GPU support.
    """
    return None  # Not implemented - requires torch/transformers
