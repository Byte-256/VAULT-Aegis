"""
VAULT Aegis — PII & Confidential Data Sanitizer
=================================================
Production-grade PII detection, sanitization, and risk-scoring engine.

Features:
  - Hybrid detection: regex patterns + spaCy NER
  - 22 PII types across 4 categories (Personal, Financial, Auth, Confidential)
  - 3 operating modes: Detect Only, Mask, Redact
  - Luhn & Verhoeff checksum validation for financial identifiers
  - Real-time risk scoring with configurable block thresholds
  - Compliant with GDPR, HIPAA, PCI-DSS

Usage:
    from pii_sanitizer import PIISanitizer, SanitizeMode

    sanitizer = PIISanitizer(mode=SanitizeMode.MASK)
    result = sanitizer.sanitize("Email me at john@example.com")
    print(result.sanitized_text)   # "Email me at j***@example.com"
    print(result.risk_score.level) # "High"
"""

from .config import SanitizeMode, RiskLevel, PIICategory, PII_TYPES
from .detector import PIIDetector, PIIDetection
from .sanitizer import PIISanitizer, SanitizeResult
from .risk_engine import PIIRiskEngine, PIIRiskScore
from .validators import luhn_check, verhoeff_check

__all__ = [
    "PIISanitizer",
    "PIIDetector",
    "PIIDetection",
    "PIIRiskEngine",
    "PIIRiskScore",
    "SanitizeResult",
    "SanitizeMode",
    "RiskLevel",
    "PIICategory",
    "PII_TYPES",
    "luhn_check",
    "verhoeff_check",
]

__version__ = "1.0.0"
