"""
VAULT Aegis — PII Sanitizer: Validators
=========================================
Checksum-based validators to reduce false positives in PII detection.
Includes Luhn (credit cards), Verhoeff (Aadhaar), and structural validators.
"""

import re
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Luhn Algorithm — Credit/Debit Card Validation
# ──────────────────────────────────────────────────────────────────────────────

def luhn_check(number: str) -> bool:
    """
    Validate a number using the Luhn (mod-10) algorithm.
    Used for credit/debit card number validation.

    Args:
        number: String of digits (spaces/dashes stripped automatically).

    Returns:
        True if the number passes Luhn validation.
    """
    digits = re.sub(r"[\s\-]", "", number)
    if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ──────────────────────────────────────────────────────────────────────────────
# Verhoeff Algorithm — Aadhaar Number Validation (India)
# ──────────────────────────────────────────────────────────────────────────────

# Verhoeff tables
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check(number: str) -> bool:
    """
    Validate a number using the Verhoeff checksum algorithm.
    Used for Aadhaar (India) 12-digit UID validation.

    Args:
        number: String of digits (spaces/dashes stripped automatically).

    Returns:
        True if the number passes Verhoeff validation.
    """
    digits = re.sub(r"[\s\-]", "", number)
    if not digits.isdigit() or len(digits) != 12:
        return False

    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


# ──────────────────────────────────────────────────────────────────────────────
# Email domain validator
# ──────────────────────────────────────────────────────────────────────────────

def validate_email_structure(email: str) -> bool:
    """
    Validate that an email has a plausible structure.
    Does NOT check MX records (that requires network I/O).

    Returns:
        True if the email has a valid local + domain structure.
    """
    pattern = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
    return bool(re.match(pattern, email))


# ──────────────────────────────────────────────────────────────────────────────
# IFSC Code Validator (India)
# ──────────────────────────────────────────────────────────────────────────────

def validate_ifsc(code: str) -> bool:
    """
    Validate an Indian IFSC code format: 4 letters + 0 + 6 alphanumeric.

    Returns:
        True if the code matches IFSC structure.
    """
    return bool(re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", code))


# ──────────────────────────────────────────────────────────────────────────────
# SSN structure validator
# ──────────────────────────────────────────────────────────────────────────────

def validate_ssn(ssn: str) -> bool:
    """
    Validate US SSN structure (not just format, also known invalid ranges).
    SSN cannot start with 000, 666, or 9xx; middle digits can't be 00;
    last digits can't be 0000.

    Returns:
        True if SSN passes structural validation.
    """
    digits = re.sub(r"[\s\-]", "", ssn)
    if not digits.isdigit() or len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if serial == 0:
        return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# IP Address validator
# ──────────────────────────────────────────────────────────────────────────────

def validate_ip_address(ip: str) -> bool:
    """
    Validate that each octet in an IPv4 address is 0-255.

    Returns:
        True if the IP address has valid octets.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            val = int(part)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Credit card prefix validator (quick IIN check)
# ──────────────────────────────────────────────────────────────────────────────

def validate_card_prefix(number: str) -> bool:
    """
    Check that the card number starts with a known IIN/BIN prefix.
    Visa (4), Mastercard (51-55, 2221-2720), Amex (34, 37),
    Discover (6011, 65), Diners (300-305, 36, 38).

    Returns:
        True if the prefix matches a known card network.
    """
    digits = re.sub(r"[\s\-]", "", number)
    if len(digits) < 13:
        return False
    d = digits
    if d[0] == "4":
        return True  # Visa
    if d[:2] in ("34", "37"):
        return True  # Amex
    if 51 <= int(d[:2]) <= 55:
        return True  # Mastercard
    if 2221 <= int(d[:4]) <= 2720:
        return True  # Mastercard (new range)
    if d[:4] == "6011" or d[:2] == "65":
        return True  # Discover
    if d[:2] == "36" or d[:2] == "38":
        return True  # Diners
    if 300 <= int(d[:3]) <= 305:
        return True  # Diners
    return False
