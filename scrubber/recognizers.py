"""
Custom Presidio PatternRecognizers for Indian PII Entities.

Includes PAN, Aadhaar, Passport (standard + MRZ), Voter ID, Date of Birth (DOB),
Indian Phone/Landline, Email, Person Names, Addresses, Bank Account, IFSC,
Pincode, Driving License, GSTIN, Vehicle RC, ITR Acknowledgement, Policy/Customer ID.

Enhanced with:
- Mathematical checksum validators (Verhoeff for Aadhaar, Mod-36 for GSTIN)
- Embedded PAN extraction (masked formats, ITR tokens)
- ICAO 9303 Passport MRZ detection
- MoRTH Sarathi + legacy Driving License formats
- Modern EPIC + legacy slash-delimited Voter ID
- Multi-format DOB parsing
- Bharat Series vehicle registration
"""

import re
from typing import List, Optional
from presidio_analyzer import PatternRecognizer, Pattern, RecognizerResult

from scrubber.validators import (
    validate_verhoeff,
    validate_pan_structure,
    validate_gstin_checksum,
    validate_dob_date,
    validate_state_code,
)


def validate_entity_result(text: str, start: int, end: int, entity_type: str) -> bool:
    """
    Run mathematical validators on a matched entity.
    Returns True if the match passes validation (or has no mathematical validator).
    """
    matched = text[start:end]

    if entity_type == "INDIAN_AADHAAR":
        return validate_aadhaar_full(matched)
    elif entity_type == "INDIAN_PAN":
        return validate_pan_full(matched)
    elif entity_type == "INDIAN_GSTIN":
        return validate_gstin_checksum(matched)
    elif entity_type == "DATE_OF_BIRTH":
        return validate_dob_date(matched)
    elif entity_type == "INDIAN_PASSPORT_MRZ":
        # MRZ validation requires both lines; handled separately
        return True

    # No mathematical validator — trust regex + context gate
    return True


# Re-export for convenience
def validate_aadhaar_full(number_str: str) -> bool:
    """
    Full Aadhaar validation: 12 digits, starts with 2-9, Verhoeff checksum.
    """
    # Quick regex pre-check before running Verhoeff
    cleaned = re.sub(r"[\s.\-]", "", number_str)
    if not cleaned.isdigit() or len(cleaned) != 12:
        return False
    if cleaned[0] in ("0", "1"):
        return False
    return validate_verhoeff(cleaned)


def validate_pan_full(pan_str: str) -> bool:
    """
    Full PAN validation: structure + status code.
    """
    return validate_pan_structure(pan_str)


def get_indian_recognizers() -> List[PatternRecognizer]:
    """Return a list of initialized Presidio PatternRecognizer objects for Indian PII."""

    # 1. PAN Card Recognizer (Strict 10-char format: 5 letters, 4 numbers, 1 letter)
    # 4th-char entity status code constraint: [P, C, H, F, A, T, B, L, J, G, K]
    pan_pattern = Pattern(
        name="pan_pattern",
        regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        score=0.90,
    )
    pan_masked_pattern = Pattern(
        name="pan_masked_pattern",
        regex=r"\b(?:XXXXX|\*{5}|\.{5})[0-9]{4}[A-Z]\b|\b[A-Z]{5}XXXX[A-Z]\b",
        score=0.85,
    )
    pan_embedded_pattern = Pattern(
        name="pan_embedded_pattern",
        regex=r"(?<=ITRV-)[A-Z]{5}[0-9]{4}[A-Z]|(?<=Ack: )[0-9]{15}/[A-Z]{5}[0-9]{4}[A-Z]|(?<=ACK:)[A-Z]{5}[0-9]{4}[A-Z]",
        score=0.75,
    )
    pan_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PAN",
        patterns=[pan_pattern, pan_masked_pattern, pan_embedded_pattern],
        context=[
            "pan", "permanent account number", "income tax", "govt of india",
            "taxpayer", "income-tax", "pan card", "pan no", "pan number",
            "itrv", "itr-v", "efiling", "income tax department", "assessment",
        ],
    )

    # 2. Aadhaar Number Recognizer (12 digits, starts with 2-9)
    # Supports: 1234 5678 9012, 1234-5678-9012, 123456789012, 9876.5432.1012
    # Also masked: XXXX-XXXX-1234, •••• •••• 1234
    aadhaar_pattern_standard = Pattern(
        name="aadhaar_pattern_standard",
        regex=r"\b[2-9]\d{3}[\s.-]?\d{4}[\s.-]?\d{4}\b",
        score=0.85,
    )
    aadhaar_pattern_masked = Pattern(
        name="aadhaar_masked_pattern",
        regex=r"\b(?:XXXX|xxxx|\u2022{4}|\*{4}|[.]{4})(?:[\s.-](?:XXXX|xxxx|\u2022{4}|\*{4}|[.]{4})){1,2}[\s.-]?\d{4}\b",
        score=0.70,
    )
    aadhaar_recognizer = PatternRecognizer(
        supported_entity="INDIAN_AADHAAR",
        patterns=[aadhaar_pattern_standard, aadhaar_pattern_masked],
        context=[
            "aadhaar", "aadhar", "uid", "uidai", "unique identification",
            "aadhaar card", "aadhaar no", "aadhar no", "proof of identity",
            "enrollment", "a-number", "virtual id", "vid",
        ],
    )

    # 3. Passport Number Recognizer
    # Supports regular ([A-PR-WYZ][0-9]{7}), diplomatic (D[0-9]{7}), official (S[0-9]{7})
    passport_regular_pattern = Pattern(
        name="passport_regular_pattern",
        regex=r"\b[A-HJ-NP-RT-WY][0-9]{7}\b",
        score=0.80,
    )
    passport_diplomatic_pattern = Pattern(
        name="passport_diplomatic_pattern",
        regex=r"\bD[0-9]{7,8}\b",
        score=0.75,
    )
    passport_official_pattern = Pattern(
        name="passport_official_pattern",
        regex=r"\bS[0-9]{7,8}\b",
        score=0.75,
    )
    passport_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PASSPORT",
        patterns=[passport_regular_pattern, passport_diplomatic_pattern, passport_official_pattern],
        context=[
            "passport", "passport no", "passport number", "republic of india",
            "indian passport", "travel document", "passport no:", "pp no",
        ],
    )

    # 3b. Passport MRZ Recognizer (ICAO 9303)
    # Detects 44-char Line 1 (P<IND...) and Line 2 ([A-Z0-9<]{44})
    mrz_line1_pattern = Pattern(
        name="mrz_line1_pattern",
        regex=r"P<IND[A-Z0-9<]{38}",
        score=0.70,
    )
    mrz_line2_pattern = Pattern(
        name="mrz_line2_pattern",
        regex=r"[A-Z0-9]{37}[A-Z0-9<]{7}",
        score=0.70,
    )
    mrz_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PASSPORT_MRZ",
        patterns=[mrz_line1_pattern, mrz_line2_pattern],
        context=[
            "machine readable", "mrz", "machine readable zone", "passport",
            "p<ind", "travel document",
        ],
    )

    # 4. Voter ID (EPIC) Recognizer
    # Modern EPIC: [A-Z]{3}[0-9]{7}
    # Legacy slash-delimited: ABC/12/345/678901
    voter_modern_pattern = Pattern(
        name="voter_modern_pattern",
        regex=r"\b[A-Z]{3}[0-9]{7}\b",
        score=0.80,
    )
    voter_legacy_pattern = Pattern(
        name="voter_legacy_pattern",
        regex=r"\b[A-Z]{2,3}/\d{2}/\d{3}/\d{6,7}\b",
        score=0.75,
    )
    voter_recognizer = PatternRecognizer(
        supported_entity="INDIAN_VOTER_ID",
        patterns=[voter_modern_pattern, voter_legacy_pattern],
        context=[
            "voter id", "epic", "election commission", "elector", "voter card",
            "epic no", "elector photo identity card", "voter id no", "polling",
        ],
    )

    # 5. Date of Birth (DOB) Recognizer (Multi-format)
    # DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY, DD MMM YYYY
    dob_slash_pattern = Pattern(
        name="dob_slash_pattern",
        regex=r"\b(?:0?[1-9]|[12][0-9]|3[01])/(?:0?[1-9]|1[012])/(?:19|20)\d\d\b",
        score=0.70,
    )
    dob_dash_pattern = Pattern(
        name="dob_dash_pattern",
        regex=r"\b(?:0?[1-9]|[12][0-9]|3[01])-(?:0?[1-9]|1[012])-(?:19|20)\d\d\b",
        score=0.70,
    )
    dob_dot_pattern = Pattern(
        name="dob_dot_pattern",
        regex=r"\b(?:0?[1-9]|[12][0-9]|3[01])\.(?:0?[1-9]|1[012])\.(?:19|20)\d\d\b",
        score=0.70,
    )
    dob_month_pattern = Pattern(
        name="dob_month_pattern",
        regex=r"\b(?:0?[1-9]|[12][0-9]|3[01])\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(?:19|20)\d\d\b",
        score=0.75,
    )
    dob_recognizer = PatternRecognizer(
        supported_entity="DATE_OF_BIRTH",
        patterns=[dob_slash_pattern, dob_dash_pattern, dob_dot_pattern, dob_month_pattern],
        context=[
            "dob", "date of birth", "birth date", "born on", "birth", "d.o.b",
            "yob", "year of birth", "age",
        ],
    )

    # 6. Indian Phone Number Recognizer
    # Mobile: +91, 0, 6-9 start
    # Landline: STD codes with formats (022) 1234-5679, 022-1234-5679
    # Extensions: ext 102
    phone_mobile_pattern = Pattern(
        name="phone_mobile_pattern",
        regex=r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
        score=0.75,
    )
    phone_landline_pattern = Pattern(
        name="phone_landline_pattern",
        regex=r"\b(?:\(\d{2,3}\)\s*|\d{2,3}[\s-]?)[\d\s-]{5,10}\d\b",
        score=0.75,
    )
    phone_ext_pattern = Pattern(
        name="phone_ext_pattern",
        regex=r"\b(?:ext\.?|extension|x)\s*\d{2,5}\b",
        score=0.60,
    )
    phone_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PHONE_NUMBER",
        patterns=[phone_mobile_pattern, phone_landline_pattern, phone_ext_pattern],
        context=[
            "mobile", "phone", "contact", "tel", "call", "whatsapp", "mo.",
            "ph.", "cell", "mobile no", "contact no", "phone number",
            "residence", "office", "std code",
        ],
    )

    # 7. IFSC Code Recognizer
    ifsc_pattern = Pattern(
        name="ifsc_pattern",
        regex=r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        score=0.85,
    )
    ifsc_recognizer = PatternRecognizer(
        supported_entity="INDIAN_IFSC",
        patterns=[ifsc_pattern],
        context=[
            "ifsc", "ifsc code", "bank code", "rtgs", "neft", "branch code",
            "bank branch", "branch ifsc",
        ],
    )

    # 8. Indian Pincode Recognizer
    pincode_pattern = Pattern(
        name="pincode_pattern",
        regex=r"\b[1-9][0-9]{5}\b",
        score=0.55,
    )
    pincode_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PINCODE",
        patterns=[pincode_pattern],
        context=[
            "pincode", "pin", "postal code", "pin code", "zip code",
            "location", "postal", "shipping", "pin-",
        ],
    )

    # 9. Title-Prefixed Indian Name Recognizer (Enhanced)
    # Expanded honorifics: Late, Master, Prof, Capt, Col, Major, Justice, Swami
    title_name_pattern = Pattern(
        name="title_name_pattern",
        regex=r"\b(?:Shri|Smt|Kumari|Dr|Mr|Mrs|Ms|Adv|CA|Late|Master|Prof|Capt|Col|Major|Justice|Swami)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b",
        score=0.80,
    )
    title_name_uppercase_pattern = Pattern(
        name="title_name_uppercase_pattern",
        regex=r"\b(?:Shri|Smt|Kumari|Dr|Mr|Mrs|Ms|Adv|CA|Late|Master|Prof|Capt|Col|Major|Justice|Swami)\.?\s+[A-Z]{2,}(?:\s+[A-Z]{2,}){1,2}\b",
        score=0.80,
    )
    name_label_pattern = Pattern(
        name="name_label_pattern",
        regex=r"\b(?:Name|Taxpayer|Policyholder|Insured|Customer)\s*[:/]\s+[A-Z][A-Za-z.'\-]{1,40}(?:\s+[A-Z][A-Za-z.'\-]{1,40}){1,2}\b",
        score=0.80,
    )
    name_relationship_pattern = Pattern(
        name="name_relationship_pattern",
        regex=r"\b(?:S/d|Son|D/d|Daughter|W/d|Wife|C/o|W/o|D/o|S/o)\.?\s+[A-Z][a-zA-Z.'\-]+(?:\s+[A-Z][a-zA-Z.'\-]+){1,2}\b",
        score=0.80,
    )
    title_name_recognizer = PatternRecognizer(
        supported_entity="TITLE_PERSON_NAME",
        patterns=[title_name_pattern, title_name_uppercase_pattern, name_label_pattern, name_relationship_pattern],
        context=[
            "name", "taxpayer", "policyholder", "insured", "s/o", "d/o", "w/o",
            "c/o", "applicant", "customer name", "holder",
            "son/daughter", "spouse",
        ],
    )

    # 10. Indian Address Recognizer (Hardened against false matches)
    address_pattern = Pattern(
        name="indian_address_pattern",
        regex=r"\b(?:FLAT|HOUSE|PLOT|STREET|ROAD|MARG|NAGAR|SECTOR|COLONY|ENCLAVE|VILLAGE|APARTMENT|SOCIETY|BUILDING|WARD|ZONE|DISTRICT|POST)[^\n]{5,60}\b",
        score=0.60,
    )
    address_recognizer = PatternRecognizer(
        supported_entity="INDIAN_ADDRESS",
        patterns=[address_pattern],
        context=[
            "address", "residence", "communication address", "permanent address",
            "correspondence address", "insured address", "customer address",
            "locality", "street", "home address", "registered address",
        ],
    )

    # 11. Policy Number & Customer ID Recognizer
    policy_pattern = Pattern(
        name="policy_no_pattern",
        regex=r"\b\d{8,16}\b",
        score=0.60,
    )
    policy_recognizer = PatternRecognizer(
        supported_entity="POLICY_OR_CUSTOMER_ID",
        patterns=[policy_pattern],
        context=[
            "policy number", "policy no", "customer id", "customer no",
            "account number", "account no", "member id", "proposal no",
            "policy no", "customer id no", "client no", "member no",
        ],
    )

    # 12. ITR Acknowledgement Number Recognizer (NEW)
    # 15-digit e-Filing acknowledgement numbers
    # Composite: ITRV-ABCDE1234F-2023, Ack: 123456789012345/ABCDE1234F
    itr_ack_pattern = Pattern(
        name="itr_ack_pattern",
        regex=r"\b\d{15}\b",
        score=0.65,
    )
    itr_composite_pattern = Pattern(
        name="itr_composite_pattern",
        regex=r"\b(?:ITR|ITRV|ACK)[-:]?\s*[A-Z]{5}[0-9]{4}[A-Z]\b|\b\d{15}/[A-Z]{5}[0-9]{4}[A-Z]\b",
        score=0.80,
    )
    itr_recognizer = PatternRecognizer(
        supported_entity="ITR_ACKNOWLEDGEMENT_NUMBER",
        patterns=[itr_ack_pattern, itr_composite_pattern],
        context=[
            "itr", "itrv", "acknowledgement", "ack no", "ack no:", "reference no",
            "efiling", "e-filing", "income tax", "filing status", "ack",
            "assessment year", "verification",
        ],
    )

    # 13. Driving License Recognizer (NEW)
    # MoRTH Sarathi format: SS-RR-YYYYNNNNNNN
    # Legacy state-wise formats across all 28 states and 8 UTs
    dl_sarathi_pattern = Pattern(
        name="dl_sarathi_pattern",
        regex=r"\b(?:0[1-9]|[1-2][0-9]|3[0-8])(?:-[A-Z]{1,2})?-?\d{2}-\d{4}\d{7}\b",
        score=0.80,
    )
    dl_state_pattern = Pattern(
        name="dl_state_pattern",
        regex=r"\b(?:DL|MH|KA|TN|KL|GJ|RJ|UP|BR|WB|MP|AP|TS|TG|CH|OD|JK|HR|PB|UK|HP|CG|JH|MN|ML|MZ|NL|SK|TR|LA|AN|PY)[\-\s]?\d{2,3}[\-\s]?\d{4,11}\b",
        score=0.70,
    )
    dl_recognizer = PatternRecognizer(
        supported_entity="INDIAN_DRIVING_LICENSE",
        patterns=[dl_sarathi_pattern, dl_state_pattern],
        context=[
            "driving license", "dl no", "dl number", "license no",
            "driver license", "driving licence", "rto", "sarathi",
            "license number", "vehicle license",
        ],
    )

    # 14. GSTIN Recognizer (NEW)
    # 15-character GSTIN: 2-digit state + 11-char PAN-based + Z/N + 1 check char
    gstin_pattern = Pattern(
        name="gstin_pattern",
        regex=r"\b[0-9]{2}[A-Z0-9]{11}[ZN][A-Z0-9]\b",
        score=0.85,
    )
    gstin_recognizer = PatternRecognizer(
        supported_entity="INDIAN_GSTIN",
        patterns=[gstin_pattern],
        context=[
            "gstin", "gst no", "gst number", "gst registration", "tax identification",
            "business registration", "supplier gstin", "vendor gst",
            "urn", "u-gstin",
        ],
    )

    # 15. Vehicle Registration Recognizer (NEW)
    # State RTO format: SS 01 AB 1234
    # Bharat Series: 22 BH 1234 AA, 01 BH 1234 AA
    vehicle_rto_pattern = Pattern(
        name="vehicle_rto_pattern",
        regex=r"\b[A-Z]{2}\s?\d{1,2}\s?[A-Z]{1,4}\s?\d{1,4}[A-Z]?\b",
        score=0.75,
    )
    vehicle_bharat_pattern = Pattern(
        name="vehicle_bharat_pattern",
        regex=r"\b\d{2}\s?BH\s?\d{1,4}\s?[A-Z]{2}\b",
        score=0.80,
    )
    vehicle_recognizer = PatternRecognizer(
        supported_entity="INDIAN_VEHICLE_REGISTRATION",
        patterns=[vehicle_rto_pattern, vehicle_bharat_pattern],
        context=[
            "vehicle", "registration", "reg no", "rc no", "rc book",
            "number plate", "vehicle no", "car no", "bike no",
            "registration number", "vehicle rc",
        ],
    )

    # 16. Bank Account Number Recognizer (NEW)
    # 9-18 digit account numbers with banking context
    bank_account_pattern = Pattern(
        name="bank_account_pattern",
        regex=r"\b\d{9,18}\b",
        score=0.60,
    )
    bank_account_recognizer = PatternRecognizer(
        supported_entity="INDIAN_BANK_ACCOUNT",
        patterns=[bank_account_pattern],
        context=[
            "account number", "account no", "ac no", "ac no.", "a/c no",
            "a/c number", "bank account", "savings account", "sb a/c",
            "current a/c", "cashtag", "neft account", "account",
        ],
    )

    return [
        pan_recognizer,
        aadhaar_recognizer,
        passport_recognizer,
        mrz_recognizer,
        voter_recognizer,
        dob_recognizer,
        phone_recognizer,
        ifsc_recognizer,
        pincode_recognizer,
        title_name_recognizer,
        address_recognizer,
        policy_recognizer,
        itr_recognizer,
        dl_recognizer,
        gstin_recognizer,
        vehicle_recognizer,
        bank_account_recognizer,
    ]


__all__ = [
    "get_indian_recognizers",
    "validate_entity_result",
    "validate_aadhaar_full",
    "validate_pan_full",
]
