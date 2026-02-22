"""
VAULT Aegis — PII Sanitizer: Sanitization Engine
===================================================
Transforms detected PII using configurable modes:
  - DETECT_ONLY: Logs detections without modifying content
  - MASK:        Partial masking (e.g. j***@email.com)
  - REDACT:      Full replacement (e.g. [REDACTED_EMAIL])
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .config import SanitizeMode, PII_TYPES, RiskLevel
from .detector import PIIDetection, PIIDetector
from .risk_engine import PIIRiskEngine, PIIRiskScore


# ──────────────────────────────────────────────────────────────────────────────
# Sanitization Result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SanitizeResult:
    """Result of a sanitization operation."""
    original_text: str
    sanitized_text: str
    detections: List[PIIDetection]
    risk_score: PIIRiskScore
    mode: SanitizeMode
    detections_count: int = 0

    def __post_init__(self):
        self.detections_count = len(self.detections)

    def as_dict(self) -> dict:
        return {
            "sanitized_text": self.sanitized_text,
            "detections": [d.as_dict() for d in self.detections],
            "risk_score": self.risk_score.as_dict(),
            "mode": self.mode.value,
            "detections_count": self.detections_count,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Masking Strategies
# ──────────────────────────────────────────────────────────────────────────────

def _mask_email(value: str) -> str:
    """john.doe@email.com → j***@email.com"""
    parts = value.split("@")
    if len(parts) != 2:
        return "***@***"
    local = parts[0]
    domain = parts[1]
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"


def _mask_credit_card(value: str) -> str:
    """4111 1111 1111 1111 → **** **** **** 1111"""
    digits = re.sub(r"[\s\-]", "", value)
    if len(digits) < 4:
        return "****"
    return f"**** **** **** {digits[-4:]}"


def _mask_phone(value: str) -> str:
    """+1-555-123-4567 → +1-***-***-4567"""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***"
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _mask_ssn(value: str) -> str:
    """123-45-6789 → ***-**-6789"""
    digits = re.sub(r"[\s\-]", "", value)
    if len(digits) < 4:
        return "***"
    return f"***-**-{digits[-4:]}"


def _mask_aadhaar(value: str) -> str:
    """1234 5678 9012 → **** **** 9012"""
    digits = re.sub(r"[\s\-]", "", value)
    if len(digits) < 4:
        return "****"
    return f"**** **** {digits[-4:]}"


def _mask_generic(value: str) -> str:
    """Generic masking — show first and last character, mask the rest."""
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def _mask_ip(value: str) -> str:
    """192.168.1.100 → 192.168.*.*"""
    parts = value.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "***"


def _mask_token(value: str) -> str:
    """Long tokens — show first 4 and last 4 characters."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


# Map PII types to their masking functions
_MASK_FN = {
    "EMAIL": _mask_email,
    "CREDIT_CARD": _mask_credit_card,
    "PHONE": _mask_phone,
    "SSN": _mask_ssn,
    "AADHAAR": _mask_aadhaar,
    "IP_ADDRESS": _mask_ip,
    "JWT_TOKEN": _mask_token,
    "API_KEY": _mask_token,
    "ACCESS_TOKEN": _mask_token,
    "PRIVATE_KEY": lambda v: "[MASKED_PRIVATE_KEY]",
    "DB_URL": lambda v: v.split("://")[0] + "://***" if "://" in v else "***",
}


# ──────────────────────────────────────────────────────────────────────────────
# PII Sanitizer
# ──────────────────────────────────────────────────────────────────────────────

class PIISanitizer:
    """
    PII detection and sanitization engine.

    Supports three operating modes:
      - DETECT_ONLY: Detects PII but returns original text unchanged.
      - MASK:        Partially masks detected PII.
      - REDACT:      Fully replaces detected PII with type-specific tags.

    Usage:
        sanitizer = PIISanitizer(mode=SanitizeMode.MASK)
        result = sanitizer.sanitize("Email me at john@example.com")
        print(result.sanitized_text)  # "Email me at j***@example.com"
    """

    def __init__(
        self,
        mode: SanitizeMode = SanitizeMode.REDACT,
        ner_enabled: bool = True,
    ):
        self.mode = mode
        self.detector = PIIDetector(ner_enabled=ner_enabled)
        self.risk_engine = PIIRiskEngine()

    def sanitize(self, text: str, source: str = "unknown") -> SanitizeResult:
        """
        Detect and sanitize PII in the given text.

        Args:
            text: The input text to scan and sanitize.
            source: Source identifier (e.g. "api_gateway", "ai_pipeline").

        Returns:
            SanitizeResult with sanitized text, detections, and risk score.
        """
        if not text or not text.strip():
            return SanitizeResult(
                original_text=text,
                sanitized_text=text,
                detections=[],
                risk_score=PIIRiskScore(
                    level=RiskLevel.LOW, score=0,
                    summary="No content to scan",
                    detections_count=0, dominant_type=None,
                ),
                mode=self.mode,
            )

        # 1. Detect PII
        detections = self.detector.detect(text)

        # 2. Score risk
        risk_score = self.risk_engine.score(detections, source=source)

        # 3. Sanitize based on mode
        if self.mode == SanitizeMode.DETECT_ONLY or not detections:
            sanitized = text
        elif self.mode == SanitizeMode.MASK:
            sanitized = self._apply_mask(text, detections)
        else:  # REDACT
            sanitized = self._apply_redact(text, detections)

        return SanitizeResult(
            original_text=text,
            sanitized_text=sanitized,
            detections=detections,
            risk_score=risk_score,
            mode=self.mode,
        )

    def _apply_mask(self, text: str, detections: List[PIIDetection]) -> str:
        """Apply partial masking to all detected PII."""
        # Process from end to start to preserve indices
        sorted_dets = sorted(detections, key=lambda d: d.start, reverse=True)
        result = text
        for det in sorted_dets:
            mask_fn = _MASK_FN.get(det.pii_type, _mask_generic)
            masked = mask_fn(det.value)
            result = result[:det.start] + masked + result[det.end:]
        return result

    def _apply_redact(self, text: str, detections: List[PIIDetection]) -> str:
        """Replace all detected PII with redaction tags."""
        sorted_dets = sorted(detections, key=lambda d: d.start, reverse=True)
        result = text
        for det in sorted_dets:
            info = PII_TYPES.get(det.pii_type, {})
            tag = info.get("redact_tag", f"[REDACTED_{det.pii_type}]")
            result = result[:det.start] + tag + result[det.end:]
        return result

    def should_block(self) -> bool:
        """Check if the risk engine recommends blocking (for external callers)."""
        return False  # Called on result, not instance — see risk_engine

    def update_mode(self, mode: SanitizeMode):
        """Update the sanitization mode at runtime."""
        self.mode = mode
