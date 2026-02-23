"""
VAULT Aegis — PII Sanitizer: Detection Engine
================================================
Hybrid PII detection using regex patterns + optional spaCy NER.
Each detection is validated through type-specific validators
to minimize false positives.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .config import (
    PATTERNS,
    DETECTION_ORDER,
    PII_TYPES,
    RiskLevel,
    PIICategory,
    NER_ENABLED,
    NER_MODEL,
    NER_ENTITY_MAP,
)
from .validators import (
    luhn_check,
    verhoeff_check,
    validate_ssn,
    validate_ip_address,
    validate_email_structure,
    validate_ifsc,
    validate_card_prefix,
)


# ──────────────────────────────────────────────────────────────────────────────
# Detection Result
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class PIIDetection:
    """A single PII detection result."""

    pii_type: str  # Key from PII_TYPES (e.g. "EMAIL", "CREDIT_CARD")
    value: str  # The matched text
    start: int  # Start index in source text
    end: int  # End index in source text
    confidence: float  # 0.0 – 1.0
    risk_level: RiskLevel  # LOW / MEDIUM / HIGH / CRITICAL
    category: PIICategory  # personal / financial / auth_secret / confidential
    label: str = ""  # Human-readable label

    def __post_init__(self):
        info = PII_TYPES.get(self.pii_type, {})
        self.label = info.get("label", self.pii_type)

    def as_dict(self) -> dict:
        return {
            "type": self.pii_type,
            "label": self.label,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "risk_level": self.risk_level.value,
            "category": self.category.value,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Validator dispatch — maps PII type to its validation function
# ──────────────────────────────────────────────────────────────────────────────


def _validate_detection(pii_type: str, value: str) -> bool:
    """
    Run the appropriate validator for the given PII type.
    Returns True if the detection is valid (or no validator exists).
    """
    clean = re.sub(r"[\s\-]", "", value)

    if pii_type == "CREDIT_CARD":
        return validate_card_prefix(value) and luhn_check(value)

    if pii_type == "AADHAAR":
        return verhoeff_check(value)

    if pii_type == "SSN":
        return validate_ssn(value)

    if pii_type == "EMAIL":
        return validate_email_structure(value)

    if pii_type == "IFSC":
        return validate_ifsc(value)

    if pii_type == "IP_ADDRESS":
        return validate_ip_address(value)

    # No special validator — accept the regex match
    return True


# ──────────────────────────────────────────────────────────────────────────────
# NER Module Loader (lazy) - using Microsoft Presidio
# ──────────────────────────────────────────────────────────────────────────────

_presidio_analyzer = None


def _get_presidio_analyzer():
    """Lazy-load the Presidio analyzer."""
    global _presidio_analyzer
    if _presidio_analyzer is not None:
        return _presidio_analyzer
    try:
        from presidio_analyzer import AnalyzerEngine

        _presidio_analyzer = AnalyzerEngine()
        return _presidio_analyzer
    except ImportError as e:
        print(f"[VAULT PII] Presidio not available: {e}")
        return None


PRESIDIO_TO_PII = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "US_SSN": "SSN",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "IP_ADDRESS": "IP_ADDRESS",
    "CREDIT_CARD": "CREDIT_CARD",
    "DATE_TIME": "DATE",
    "PERSON": "PERSON_NAME",
    "ORGANIZATION": "ORG_NAME",
    "LOCATION": "LOCATION",
    "IBAN_CODE": "IBAN",
    "SWIFT_CODE": "SWIFT",
}


# ──────────────────────────────────────────────────────────────────────────────
# PIIDetector
# ──────────────────────────────────────────────────────────────────────────────


class PIIDetector:
    """
    Hybrid PII detection engine.
    Combines regex pattern matching with optional spaCy NER
    for comprehensive PII identification.
    """

    def __init__(self, ner_enabled: bool = NER_ENABLED):
        self.ner_enabled = ner_enabled
        self._compiled_patterns = {}
        for pii_type in DETECTION_ORDER:
            if pii_type in PATTERNS:
                self._compiled_patterns[pii_type] = re.compile(
                    PATTERNS[pii_type], re.IGNORECASE | re.MULTILINE
                )

    def detect(self, text: str) -> List[PIIDetection]:
        """
        Detect all PII in the given text using regex only.
        NER is disabled due to spaCy/pydantic compatibility issues.

        Args:
            text: The input text to scan.

        Returns:
            List of PIIDetection objects, sorted by position.
        """
        if not text or not text.strip():
            return []

        detections = self._detect_regex(text)

        detections = self._deduplicate(detections)
        detections.sort(key=lambda d: d.start)
        return detections

    def _detect_regex(self, text: str) -> List[PIIDetection]:
        """Run all regex patterns against the text."""
        results = []
        covered_spans = set()

        for pii_type in DETECTION_ORDER:
            pattern = self._compiled_patterns.get(pii_type)
            if pattern is None:
                continue

            info = PII_TYPES.get(pii_type, {})

            for match in pattern.finditer(text):
                # Use group(1) if it exists (for patterns with capture groups), else group(0)
                if match.lastindex and match.lastindex >= 1:
                    value = match.group(1)
                    start = match.start(1)
                    end = match.end(1)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                # Skip if this span is already covered by a higher-priority detection
                span = (start, end)
                if any(s <= start and e >= end for s, e in covered_spans):
                    continue

                # Validate the detection
                if not _validate_detection(pii_type, value):
                    continue

                detection = PIIDetection(
                    pii_type=pii_type,
                    value=value,
                    start=start,
                    end=end,
                    confidence=info.get("confidence", 0.5),
                    risk_level=info.get("risk", RiskLevel.MEDIUM),
                    category=info.get("category", PIICategory.CONFIDENTIAL),
                )
                results.append(detection)
                covered_spans.add(span)

        return results

    def _detect_ner(self, text: str) -> List[PIIDetection]:
        """Run Microsoft Presidio NER to detect entities."""
        analyzer = _get_presidio_analyzer()
        if analyzer is None:
            return []

        results = []
        try:
            analysis = analyzer.analyze(
                text=text, language="en", entities=list(PRESIDIO_TO_PII.keys())
            )
        except Exception as e:
            print(f"[VAULT PII] Presidio analysis failed: {e}")
            return []

        for ent in analysis:
            pii_type = PRESIDIO_TO_PII.get(ent.entity_type)
            if pii_type is None:
                continue

            info = PII_TYPES.get(pii_type, {})
            confidence = ent.score * info.get("confidence", 0.5)

            detection = PIIDetection(
                pii_type=pii_type,
                value=ent.text,
                start=ent.start,
                end=ent.end,
                confidence=round(confidence, 2),
                risk_level=info.get("risk", RiskLevel.MEDIUM),
                category=info.get("category", PIICategory.PERSONAL),
            )
            results.append(detection)

        return results

    def _deduplicate(self, detections: List[PIIDetection]) -> List[PIIDetection]:
        """
        Remove overlapping detections, keeping the one with highest confidence.
        Also removes exact duplicate values of the same type.
        """
        if not detections:
            return []

        # Sort by confidence descending
        sorted_dets = sorted(detections, key=lambda d: d.confidence, reverse=True)
        kept = []
        used_spans = []

        for det in sorted_dets:
            # Check for overlap with already-kept detections
            overlaps = False
            for k_start, k_end in used_spans:
                if det.start < k_end and det.end > k_start:
                    overlaps = True
                    break
            if not overlaps:
                kept.append(det)
                used_spans.append((det.start, det.end))

        return kept
