"""
Deterministic mathematical & structural validators for Indian PII.

Zero external network dependencies. All validators are pure functions
implemented from first principles:

- Verhoeff dihedral-group D5 validation for 12-digit Aadhaar.
- PAN structural validation (entity status code, masked formats).
- ICAO Doc 9303 passport MRZ line validation (7-3-1 check digits).
- GSTIN Mod-36 checksum validation (Luhn Mod-36 algorithm).
- DOB calendar plausibility (rejects invalid dates, future dates).
- Indian state/union-territory code validation (28 States + 8 UTs + Bharat Series 'BH').
"""

import re
from datetime import datetime, date
from typing import Dict, Any, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Verhoeff algorithm tables (D5 dihedral group)
# ---------------------------------------------------------------------------

# Multiplication table for the dihedral group D5
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

# Standard Verhoeff permutation table (order 8 permutation)
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

# Inverse table
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number_str: str) -> bool:
    """
    Validate a 12-digit Aadhaar number using the Verhoeff dihedral group D5 algorithm.

    Aadhaar uses the last digit as a Verhoeff check digit computed over the
    preceding 11 digits. Returns True if the check digit is valid.

    Args:
        number_str: A string of 12 digits (may contain spaces/dots/dashes which
                    are stripped before validation).

    Returns:
        bool: True if the number passes Verhoeff checksum validation.
    """
    digits_str = re.sub(r"[\s.\-]", "", number_str)

    if not digits_str.isdigit() or len(digits_str) != 12:
        return False

    # Aadhaar must start with 2-9 (first digit cannot be 0 or 1)
    if digits_str[0] in ("0", "1"):
        return False

    digits = [int(d) for d in digits_str]

    # Apply Verhoeff validation (process all digits including check digit)
    # Iterate from right to left; i is position from right (0-indexed, mod 8)
    c = 0
    for i, digit in enumerate(reversed(digits)):
        p_value = _VERHOEFF_P[i % 8][digit]
        c = _VERHOEFF_D[c][p_value]

    return c == 0


# ---------------------------------------------------------------------------
# PAN structural validation
# ---------------------------------------------------------------------------

# Valid 4th-character entity status codes in PAN
_PAN_STATUS_CODES = {
    "P", "C", "H", "F", "A", "T", "B", "L", "J", "G", "K"
}

# Masked PAN pattern: first 5 chars masked, then 4 digits, then 1 letter
_MASKED_PAN_PATTERN = re.compile(
    r"^[X*][X*.]{4}[0-9]{4}[A-Z]$"
)

# Full PAN pattern
_FULL_PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def validate_pan_structure(pan_str: str) -> bool:
    """
    Validate a 10-character PAN number structure.

    Checks:
    - Full PAN: 5 uppercase letters, 4 digits, 1 uppercase letter (e.g., ABCPE1234F)
    - 4th character must be a valid entity status code (P, C, H, F, A, T, B, L, J, G, K)
    - Masked PAN: patterns like XXXXX1234F, *****1234F, ....1234F

    Args:
        pan_str: PAN string (10 chars for full, or masked format).

    Returns:
        bool: True if the PAN structure is valid.
    """
    pan_clean = pan_str.strip().upper()

    # Check masked formats FIRST (before full format, since X is [A-Z])
    if len(pan_clean) == 10:
        # Masked PAN: first 5 chars can be X, *, or .
        if _MASKED_PAN_PATTERN.match(pan_clean):
            digits_part = pan_clean[5:9]
            final_char = pan_clean[9]
            if digits_part.isdigit() and final_char.isalpha():
                return True

        # Full PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
        if _FULL_PAN_PATTERN.match(pan_clean):
            status_char = pan_clean[3]
            return status_char in _PAN_STATUS_CODES

    return False


# ---------------------------------------------------------------------------
# ICAO 9303 Passport MRZ validation (TD3 - 2 lines x 44 chars)
# ---------------------------------------------------------------------------

_MRZ_LINE_LENGTH = 44


def _mrz_check_digit(chars_str: str) -> str:
    """
    Compute ICAO 9303 check digit for an MRZ field string.

    Weights cycle: 7, 3, 1 for each character position.
    Characters:
      0-9 -> 0-9
      A-Z -> 10-35 (ord(c) - 55)
      '<' filler -> 0
    """
    total = 0
    weights = [7, 3, 1]

    for i, ch in enumerate(chars_str):
        if ch.isdigit():
            val = int(ch)
        elif ch.isalpha():
            val = ord(ch.upper()) - 55
        else:
            val = 0  # '<' filler counts as 0

        total += val * weights[i % 3]

    return str(total % 10)


def validate_passport_mrz(mrz_line1: str, mrz_line2: str) -> Dict[str, Any]:
    """
    Validate ICAO Doc 9303 passport MRZ (Machine Readable Zone) two lines (TD3 format).

    Each line must be exactly 44 characters.
    Per ICAO Doc 9303 Part 4:
    Line 1:
      - 0: 'P' (Passport)
      - 1: type / '<'
      - 2-4: Issuing country ('IND')
      - 5-43: Name (Surname<<Given Names)
    Line 2:
      - 0-8: Document / Passport number (9 chars)
      - 9: Check digit over document number (1 char)
      - 10-12: Nationality ('IND')
      - 13-18: Date of birth (YYMMDD, 6 digits)
      - 19: Check digit over date of birth (1 char)
      - 20: Sex ('M', 'F', '<')
      - 21-26: Expiry date (YYMMDD, 6 digits)
      - 27: Check digit over expiry date (1 char)
      - 28-41: Optional data (14 chars)
      - 42: Check digit over optional data (1 char) or '<'
      - 43: Composite check digit (1 char)
    """
    result = {
        "valid": False,
        "passport_number": None,
        "date_of_birth": None,
        "expiry_date": None,
        "check_digit_passed": False,
        "passport_number_valid": False,
        "dob_valid": False,
        "expiry_valid": False,
    }

    # Clean and normalize
    line1 = mrz_line1.strip().replace(" ", "").upper()
    line2 = mrz_line2.strip().replace(" ", "").upper()

    if len(line1) != _MRZ_LINE_LENGTH or len(line2) != _MRZ_LINE_LENGTH:
        return result

    # Validate line 1 starts with P< (passport)
    if not line1.startswith("P<"):
        return result

    # Indian passport should have IND in line 1
    if "IND" not in line1[1:6]:
        return result

    all_checks_passed = True

    # Document number: line 2, positions 0-8 (9 chars), check digit at position 9
    doc_number_raw = line2[0:9]
    doc_number_check = line2[9]
    doc_number_str = doc_number_raw.replace("<", "")

    if doc_number_str:
        computed = _mrz_check_digit(doc_number_raw)
        if computed == doc_number_check:
            result["passport_number_valid"] = True
            result["passport_number"] = doc_number_str
        else:
            all_checks_passed = False
    else:
        all_checks_passed = False

    # Date of birth: line 2, positions 13-18 (6 digits), check digit at position 19
    dob_raw = line2[13:19]
    dob_check = line2[19]
    computed_dob_check = _mrz_check_digit(dob_raw)

    if computed_dob_check == dob_check:
        result["dob_valid"] = True
        result["date_of_birth"] = dob_raw
    else:
        all_checks_passed = False

    # Expiry date: line 2, positions 21-26 (6 digits), check digit at position 27
    expiry_raw = line2[21:27]
    expiry_check = line2[27]
    computed_expiry_check = _mrz_check_digit(expiry_raw)

    if computed_expiry_check == expiry_check:
        result["expiry_valid"] = True
        result["expiry_date"] = expiry_raw
    else:
        all_checks_passed = False

    result["check_digit_passed"] = all_checks_passed
    result["valid"] = (
        result["passport_number_valid"]
        and result["dob_valid"]
        and result["expiry_valid"]
        and all_checks_passed
    )

    return result


# ---------------------------------------------------------------------------
# GSTIN Mod-36 checksum validation (Luhn Mod-36)
# ---------------------------------------------------------------------------

_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def validate_gstin_checksum(gstin_str: str) -> bool:
    """
    Validate a 15-character GSTIN number using the standard Luhn Mod-36 algorithm.

    GSTIN structure:
    - Positions 0-1: 2-digit state code (01-38)
    - Positions 2-11: 10-char PAN
    - Position 12: Entity code (1-9, A-Z)
    - Position 13: 'Z' by default (or 'N')
    - Position 14: Luhn Mod-36 check digit

    Args:
        gstin_str: 15-character GSTIN string.

    Returns:
        bool: True if the GSTIN checksum is valid.
    """
    gstin = gstin_str.strip().upper().replace(" ", "")

    if len(gstin) != 15:
        return False

    # Validate standard format: 2 digits + 10-char PAN + 1 alphanumeric entity + Z/N + check digit
    if not re.match(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z][ZN][0-9A-Z]$", gstin):
        return False

    # Validate state code is 01-38
    state_code = int(gstin[0:2])
    if state_code < 1 or state_code > 38:
        return False

    # Standard Luhn Mod-36 checksum
    n = len(_GSTIN_ALPHABET)
    try:
        values = tuple(_GSTIN_ALPHABET.index(c) for c in reversed(gstin))
        chk = (sum(values[::2]) + sum(sum(divmod(i * 2, n)) for i in values[1::2])) % n
        return chk == 0
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# DOB calendar plausibility validation
# ---------------------------------------------------------------------------

def validate_dob_date(date_str: str) -> bool:
    """
    Validate a date string for calendar plausibility.

    Checks:
    - Valid calendar date (rejects 31/02, 29/02/2023, etc.)
    - Year in range [1900, current_year]
    - Date is not in the future

    Supports formats:
    - DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY
    - DD MMM YYYY (e.g., "15 Aug 1990")

    Args:
        date_str: Date string to validate.

    Returns:
        bool: True if the date is a plausible birth date.
    """
    date_str = date_str.strip()

    # Try DD/MM/YYYY with various separators
    date_pattern = re.match(
        r"^(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})$",
        date_str
    )

    if date_pattern:
        day = int(date_pattern.group(1))
        month = int(date_pattern.group(2))
        year = int(date_pattern.group(3))
    else:
        # Try DD MMM YYYY format
        month_map = {
            "jan": 1, "feb": 2, "mar": 3, "apr": 4,
            "may": 5, "jun": 6, "jul": 7, "aug": 8,
            "sep": 9, "oct": 10, "nov": 11, "dec": 12,
            "january": 1, "february": 2, "march": 3, "april": 4,
            "may": 5, "june": 6, "july": 7, "august": 8,
            "september": 9, "october": 10, "november": 11, "december": 12,
        }

        month_year_pattern = re.match(
            r"^(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})$",
            date_str
        )

        if month_year_pattern:
            day = int(month_year_pattern.group(1))
            month_name = month_year_pattern.group(2).lower()
            year = int(month_year_pattern.group(3))

            if month_name not in month_map:
                return False
            month = month_map[month_name]
        else:
            return False

    # Validate calendar date
    try:
        parsed_date = date(year, month, day)
    except ValueError:
        return False

    # Year range check
    current_year = datetime.now().year
    if year < 1900 or year > current_year:
        return False

    # Not in the future
    today = date.today()
    if parsed_date > today:
        return False

    return True


# ---------------------------------------------------------------------------
# Indian State/UT code validation
# ---------------------------------------------------------------------------

# All 28 States and 8 Union Territories of India
_INDIAN_STATE_CODES = {
    # 28 States
    "AP", "AR", "AS", "BR", "CG", "GA", "GJ", "HR", "HP",
    "JH", "KA", "KL", "MP", "MH", "MN", "ML", "MZ", "NL",
    "OD", "OR", "PB", "RJ", "SK", "TN", "TS", "TR", "UP", "UK",
    "WB",
    # 8 Union Territories
    "AN", "CH", "DH", "DL", "JK", "LA", "LD", "PY",
}

# Bharat Series (new vehicle registration series)
_STATE_CODES_WITH_BH = _INDIAN_STATE_CODES | {"BH"}

# Mapping for full state names to 2-letter codes (for future expansion)
STATE_NAME_TO_CODE = {
    "Andaman and Nicobar Islands": "AN",
    "Andhra Pradesh": "AP",
    "Arunachal Pradesh": "AR",
    "Assam": "AS",
    "Bihar": "BR",
    "Chandigarh": "CH",
    "Chhattisgarh": "CG",
    "Dadra and Nagar Haveli and Daman and Diu": "DH",
    "Delhi": "DL",
    "Goa": "GA",
    "Gujarat": "GJ",
    "Haryana": "HR",
    "Himachal Pradesh": "HP",
    "Jammu and Kashmir": "JK",
    "Jharkhand": "JH",
    "Karnataka": "KA",
    "Kerala": "KL",
    "Ladakh": "LA",
    "Lakshadweep": "LD",
    "Madhya Pradesh": "MP",
    "Maharashtra": "MH",
    "Manipur": "MN",
    "Meghalaya": "ML",
    "Mizoram": "MZ",
    "Nagaland": "NL",
    "Odisha": "OD",
    "Puducherry": "PY",
    "Punjab": "PB",
    "Rajasthan": "RJ",
    "Sikkim": "SK",
    "Tamil Nadu": "TN",
    "Telangana": "TS",
    "Tripura": "TR",
    "Uttar Pradesh": "UP",
    "Uttarakhand": "UK",
    "West Bengal": "WB",
}


def validate_state_code(code: str) -> bool:
    """
    Validate a 2-letter Indian state/UT code.

    Supports all 28 states, 8 union territories, and 'BH' (Bharat Series).

    Args:
        code: 2-character uppercase state code.

    Returns:
        bool: True if the state code is valid.
    """
    code = code.strip().upper()

    if len(code) != 2:
        return False

    return code in _STATE_CODES_WITH_BH


# ---------------------------------------------------------------------------
# Convenience: batch validators
# ---------------------------------------------------------------------------

def validate_aadhaar_full(number_str: str) -> bool:
    """
    Full Aadhaar validation: 12 digits, starts with 2-9, Verhoeff checksum.
    """
    return validate_verhoeff(number_str)


def validate_pan_full(pan_str: str) -> bool:
    """
    Full PAN validation: structure + status code.
    """
    return validate_pan_structure(pan_str)


def validate_mrz_full(mrz_line1: str, mrz_line2: str) -> bool:
    """
    Full MRZ validation, returns just the boolean validity.
    """
    result = validate_passport_mrz(mrz_line1, mrz_line2)
    return result["valid"]


__all__ = [
    "validate_verhoeff",
    "validate_pan_structure",
    "validate_passport_mrz",
    "validate_gstin_checksum",
    "validate_dob_date",
    "validate_state_code",
    "validate_aadhaar_full",
    "validate_pan_full",
    "validate_mrz_full",
    "_INDIAN_STATE_CODES",
    "STATE_NAME_TO_CODE",
]
