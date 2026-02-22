"""
VAULT Aegis — PII & Confidential Data Sanitizer: Configuration
================================================================
Central configuration for PII detection patterns, sanitization modes,
risk thresholds, and category definitions.

Compliant with: GDPR, HIPAA, PCI-DSS
"""

from enum import Enum
from typing import Dict, List

# ──────────────────────────────────────────────────────────────────────────────
# Sanitization Modes
# ──────────────────────────────────────────────────────────────────────────────

class SanitizeMode(str, Enum):
    """Operating mode for the PII sanitizer."""
    DETECT_ONLY = "detect_only"   # Log PII but do not modify content
    MASK = "mask"                 # Partial masking (j***@email.com)
    REDACT = "redact"             # Full replacement ([REDACTED_EMAIL])


# ──────────────────────────────────────────────────────────────────────────────
# Risk Levels
# ──────────────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ──────────────────────────────────────────────────────────────────────────────
# PII Categories
# ──────────────────────────────────────────────────────────────────────────────

class PIICategory(str, Enum):
    PERSONAL = "personal"
    FINANCIAL = "financial"
    AUTH_SECRET = "auth_secret"
    CONFIDENTIAL = "confidential"


# ──────────────────────────────────────────────────────────────────────────────
# PII Type Registry
# Each type: human label, category, default risk, default confidence, regex key
# ──────────────────────────────────────────────────────────────────────────────

PII_TYPES: Dict[str, dict] = {
    # ── Personal Identifiers ─────────────────────────────────────────────
    "EMAIL": {
        "label": "Email Address",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.95,
        "redact_tag": "[REDACTED_EMAIL]",
    },
    "PHONE": {
        "label": "Phone Number",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.85,
        "redact_tag": "[REDACTED_PHONE]",
    },
    "SSN": {
        "label": "Social Security Number",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.92,
        "redact_tag": "[REDACTED_SSN]",
    },
    "AADHAAR": {
        "label": "Aadhaar Number",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.90,
        "redact_tag": "[REDACTED_AADHAAR]",
    },
    "PASSPORT": {
        "label": "Passport Number",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.80,
        "redact_tag": "[REDACTED_PASSPORT]",
    },
    "DRIVERS_LICENSE": {
        "label": "Driver's License Number",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.75,
        "redact_tag": "[REDACTED_DL]",
    },
    "DOB": {
        "label": "Date of Birth",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.MEDIUM,
        "confidence": 0.70,
        "redact_tag": "[REDACTED_DOB]",
    },
    "PERSON_NAME": {
        "label": "Person Name",
        "category": PIICategory.PERSONAL,
        "risk": RiskLevel.MEDIUM,
        "confidence": 0.65,
        "redact_tag": "[REDACTED_NAME]",
    },

    # ── Financial Information ─────────────────────────────────────────────
    "CREDIT_CARD": {
        "label": "Credit Card Number",
        "category": PIICategory.FINANCIAL,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.98,
        "redact_tag": "[REDACTED_CREDIT_CARD]",
    },
    "CVV": {
        "label": "CVV Code",
        "category": PIICategory.FINANCIAL,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.70,
        "redact_tag": "[REDACTED_CVV]",
    },
    "BANK_ACCOUNT": {
        "label": "Bank Account Number",
        "category": PIICategory.FINANCIAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.75,
        "redact_tag": "[REDACTED_BANK_ACCT]",
    },
    "IFSC": {
        "label": "IFSC Code",
        "category": PIICategory.FINANCIAL,
        "risk": RiskLevel.MEDIUM,
        "confidence": 0.90,
        "redact_tag": "[REDACTED_IFSC]",
    },
    "IBAN": {
        "label": "IBAN",
        "category": PIICategory.FINANCIAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.88,
        "redact_tag": "[REDACTED_IBAN]",
    },

    # ── Authentication Secrets ────────────────────────────────────────────
    "API_KEY": {
        "label": "API Key",
        "category": PIICategory.AUTH_SECRET,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.90,
        "redact_tag": "[REDACTED_API_KEY]",
    },
    "JWT_TOKEN": {
        "label": "JWT Token",
        "category": PIICategory.AUTH_SECRET,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.95,
        "redact_tag": "[REDACTED_JWT]",
    },
    "PRIVATE_KEY": {
        "label": "Private Key",
        "category": PIICategory.AUTH_SECRET,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.97,
        "redact_tag": "[REDACTED_PRIVATE_KEY]",
    },
    "PASSWORD": {
        "label": "Password",
        "category": PIICategory.AUTH_SECRET,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.80,
        "redact_tag": "[REDACTED_PASSWORD]",
    },
    "ACCESS_TOKEN": {
        "label": "Access Token",
        "category": PIICategory.AUTH_SECRET,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.88,
        "redact_tag": "[REDACTED_TOKEN]",
    },

    # ── Other Confidential Data ───────────────────────────────────────────
    "IP_ADDRESS": {
        "label": "IP Address",
        "category": PIICategory.CONFIDENTIAL,
        "risk": RiskLevel.MEDIUM,
        "confidence": 0.85,
        "redact_tag": "[REDACTED_IP]",
    },
    "PHYSICAL_ADDRESS": {
        "label": "Physical Address",
        "category": PIICategory.CONFIDENTIAL,
        "risk": RiskLevel.HIGH,
        "confidence": 0.60,
        "redact_tag": "[REDACTED_ADDRESS]",
    },
    "EMPLOYEE_ID": {
        "label": "Employee ID",
        "category": PIICategory.CONFIDENTIAL,
        "risk": RiskLevel.MEDIUM,
        "confidence": 0.70,
        "redact_tag": "[REDACTED_EMP_ID]",
    },
    "DB_URL": {
        "label": "Database URL",
        "category": PIICategory.CONFIDENTIAL,
        "risk": RiskLevel.CRITICAL,
        "confidence": 0.92,
        "redact_tag": "[REDACTED_DB_URL]",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Regex Patterns — ordered by specificity (most specific first)
# ──────────────────────────────────────────────────────────────────────────────

PATTERNS: Dict[str, str] = {
    # ── Auth Secrets (highest priority) ───────────────────────────────────
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT_TOKEN": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "API_KEY": (
        r"(?i)(?:api[_\- ]?key|secret[_\- ]?key|access[_\- ]?key)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
    ),
    "ACCESS_TOKEN": (
        r"(?i)(?:bearer|token|access_token|auth_token)"
        r"\s*[:=]?\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?"
    ),
    "PASSWORD": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?\S{4,}['\"]?",

    # ── Database URLs ─────────────────────────────────────────────────────
    "DB_URL": r"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|sqlite|mssql)://\S+",

    # ── Financial ─────────────────────────────────────────────────────────
    "CREDIT_CARD": r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]|6(?:011|5[0-9]{2}))[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{1,4}\b",
    "IBAN": r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b",
    "IFSC": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "CVV": r"(?i)\bcvv\s*[:=]?\s*\d{3,4}\b",
    "BANK_ACCOUNT": r"(?i)(?:account|acct)\s*(?:no|number|#)?\s*[:=]?\s*\d{9,18}",

    # ── Personal Identifiers ─────────────────────────────────────────────
    "EMAIL": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b",
    "SSN": r"\b\d{3}[\-\s]?\d{2}[\-\s]?\d{4}\b",
    "AADHAAR": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    "PHONE": (
        r"(?:\+?\d{1,3}[\s\-]?)?"
        r"(?:\(?\d{2,4}\)?[\s\-]?)?"
        r"\d{3,4}[\s\-]?\d{3,4}\b"
    ),
    "PASSPORT": r"\b[A-Z]{1}[0-9]{7}\b",
    "DRIVERS_LICENSE": r"(?i)\b(?:DL|D\.L\.)[\s\-]?[A-Z0-9]{5,15}\b",
    "DOB": r"\b(?:\d{2}[/\-]\d{2}[/\-]\d{4}|\d{4}[/\-]\d{2}[/\-]\d{2})\b",

    # ── Confidential ──────────────────────────────────────────────────────
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "EMPLOYEE_ID": r"(?i)\b(?:emp|employee)\s*(?:id|#|no)?\s*[:=]?\s*[A-Z0-9]{4,12}\b",
}


# ──────────────────────────────────────────────────────────────────────────────
# Detection order — scan in this sequence for priority
# ──────────────────────────────────────────────────────────────────────────────

DETECTION_ORDER: List[str] = [
    "PRIVATE_KEY", "JWT_TOKEN", "API_KEY", "ACCESS_TOKEN", "PASSWORD",
    "DB_URL",
    "CREDIT_CARD", "IBAN", "IFSC", "CVV", "BANK_ACCOUNT",
    "EMAIL", "SSN", "AADHAAR", "PHONE", "PASSPORT",
    "DRIVERS_LICENSE", "DOB",
    "IP_ADDRESS", "EMPLOYEE_ID",
]


# ──────────────────────────────────────────────────────────────────────────────
# Risk score thresholds
# ──────────────────────────────────────────────────────────────────────────────

RISK_SCORE_MAP = {
    RiskLevel.LOW: 25,
    RiskLevel.MEDIUM: 50,
    RiskLevel.HIGH: 75,
    RiskLevel.CRITICAL: 95,
}

# Score at which the request should be blocked
BLOCK_THRESHOLD: int = 80

# ──────────────────────────────────────────────────────────────────────────────
# NER configuration
# ──────────────────────────────────────────────────────────────────────────────

NER_ENABLED: bool = True
NER_MODEL: str = "en_core_web_sm"  # spaCy model to use

# spaCy entity labels to treat as PII
NER_ENTITY_MAP = {
    "PERSON": "PERSON_NAME",
    "GPE": "PHYSICAL_ADDRESS",
    "ORG": "PERSON_NAME",  # Organizations can contain names
}
