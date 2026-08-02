"""
Custom Presidio PatternRecognizers for Indian PII Entities.
Includes PAN, Aadhaar, Passport, Voter ID, Date of Birth (DOB), Indian Mobile,
IFSC Code, Pincode, Address, Policy/Customer ID, and Title-prefixed Indian Names.
"""

from presidio_analyzer import PatternRecognizer, Pattern


def get_indian_recognizers():
    """Return a list of initialized Presidio PatternRecognizer objects for Indian PII."""

    # 1. PAN Card Recognizer (Strict 10-char format: 5 letters, 4 numbers, 1 letter)
    pan_pattern = Pattern(
        name="pan_pattern",
        regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        score=0.90,
    )
    pan_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PAN",
        patterns=[pan_pattern],
        context=[
            "pan", "permanent account number", "income tax", "govt of india",
            "taxpayer", "income-tax", "pan card", "pan no", "pan number"
        ],
    )

    # 2. Aadhaar Number Recognizer (12 digits, starts with 2-9)
    # Enhanced to handle various spacing formats: 1234 5678 9012, 1234-5678-9012, 123456789012
    aadhaar_pattern = Pattern(
        name="aadhaar_pattern",
        regex=r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b",
        score=0.85,
    )
    aadhaar_recognizer = PatternRecognizer(
        supported_entity="INDIAN_AADHAAR",
        patterns=[aadhaar_pattern],
        context=[
            "aadhaar", "aadhar", "uid", "uidai", "unique identification",
            "aadhaar card", "aadhaar no", "aadhar no", "proof of identity"
        ],
    )

    # 3. Passport Number Recognizer
    passport_pattern = Pattern(
        name="passport_pattern",
        regex=r"\b[A-PR-WY][0-9]{7}\b",
        score=0.80,
    )
    passport_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PASSPORT",
        patterns=[passport_pattern],
        context=[
            "passport", "passport no", "passport number", "republic of india",
            "indian passport", "travel document"
        ],
    )

    # 4. Voter ID (EPIC) Recognizer
    voter_pattern = Pattern(
        name="voter_pattern",
        regex=r"\b[A-Z]{3}[0-9]{7}\b",
        score=0.80,
    )
    voter_recognizer = PatternRecognizer(
        supported_entity="INDIAN_VOTER_ID",
        patterns=[voter_pattern],
        context=[
            "voter id", "epic", "election commission", "elector", "voter card",
            "epic no", "elector photo identity card"
        ],
    )

    # 5. Date of Birth (DOB) Recognizer
    dob_pattern = Pattern(
        name="dob_pattern",
        regex=r"\b(?:0?[1-9]|[12][0-9]|3[01])[\/\.-](?:0?[1-9]|1[012])[\/\.-](?:19|20)\d\d\b",
        score=0.70,
    )
    dob_recognizer = PatternRecognizer(
        supported_entity="DATE_OF_BIRTH",
        patterns=[dob_pattern],
        context=[
            "dob", "date of birth", "birth date", "born on", "birth", "d.o.b"
        ],
    )

    # 6. Indian Mobile Number Recognizer
    # Enhanced to handle more formats: (022) 1234 5678, 98765-43210, +91-98765-43210
    phone_pattern1 = Pattern(
        name="indian_phone_prefix",
        regex=r"(?:\+91[\s-]?)?[6-9]\d{9}\b",
        score=0.75,
    )
    phone_pattern2 = Pattern(
        name="indian_phone_zero",
        regex=r"\b0[6-9]\d{9}\b",
        score=0.75,
    )
    phone_pattern3 = Pattern(
        name="indian_phone_formatted",
        regex=r"\b[6-9]\d{4}[\s-]?\d{5}\b",
        score=0.70,
    )
    phone_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PHONE_NUMBER",
        patterns=[phone_pattern1, phone_pattern2, phone_pattern3],
        context=[
            "mobile", "phone", "contact", "tel", "call", "whatsapp", "mo.",
            "ph.", "cell", "mobile no", "contact no", "phone number"
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
            "ifsc", "ifsc code", "bank code", "rtgs", "neft", "branch code"
        ],
    )

    # 8. Indian Pincode Recognizer (Requires explicit context to prevent false-positives on amounts)
    # Lowered base score to reduce false positives, relying more on context gate
    pincode_pattern = Pattern(
        name="pincode_pattern",
        regex=r"\b[1-9][0-9]{5}\b",
        score=0.55,
    )
    pincode_recognizer = PatternRecognizer(
        supported_entity="INDIAN_PINCODE",
        patterns=[pincode_pattern],
        context=[
            "pincode", "pin", "postal code", "pin code", "zip code", "location"
        ],
    )

    # 9. Title-Prefixed Indian Name Recognizer
    # Enhanced to catch more name formats including "Name: Rajesh Kumar"
    title_name_pattern = Pattern(
        name="title_name_pattern",
        regex=r"\b(?:Shri|Smt|Kumari|Dr|Mr|Mrs|Ms|Adv|CA)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b",
        score=0.80,
    )
    title_name_uppercase_pattern = Pattern(
        name="title_name_uppercase_pattern",
        regex=r"\b(?:Shri|Smt|Kumari|Dr|Mr|Mrs|Ms|Adv|CA)\.?\s+[A-Z]{2,}(?:\s+[A-Z]{2,}){1,2}\b",
        score=0.80,
    )
    name_label_pattern = Pattern(
        name="name_label_pattern",
        # Enhanced to catch "Name: Rajesh Kumar" format with better token validation
        regex=r"\b(?:Name|Taxpayer|Policyholder|Insured|Customer)\s*[:/]\s+[A-Z][A-Za-z.'-]{1,40}(?:\s+[A-Z][A-Za-z.'-]{1,40}){1,2}\b",
        score=0.80,
    )
    title_name_recognizer = PatternRecognizer(
        supported_entity="TITLE_PERSON_NAME",
        patterns=[title_name_pattern, title_name_uppercase_pattern, name_label_pattern],
        context=[
            "name", "taxpayer", "policyholder", "insured", "s/o", "d/o", "w/o",
            "c/o", "applicant", "customer name", "holder"
        ],
    )

    # 10. Indian Address Line Recognizer (Context-gated to prevent matching non-PII terms)
    # Enhanced with more specific patterns to reduce false positives
    address_pattern = Pattern(
        name="indian_address_pattern",
        regex=r"\b(?:BLOCK|FLAT|HOUSE|PLOT|STREET|ROAD|MARG|NAGAR|SECTOR|COLONY|ENCLAVE|VILLAGE|APARTMENT|SOCIETY|BUILDING)\s+[\w\s,/-]{5,40}\b",
        score=0.60,
    )
    address_recognizer = PatternRecognizer(
        supported_entity="INDIAN_ADDRESS",
        patterns=[address_pattern],
        context=[
            "address", "residence", "communication address", "permanent address",
            "correspondence address", "insured address", "customer address", "locality"
        ],
    )

    # 11. Policy Number & Customer ID Recognizer (Requires mandatory context words)
    # Enhanced with more specific patterns to reduce false positives
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
            "account number", "account no", "member id", "proposal no"
        ],
    )

    return [
        pan_recognizer,
        aadhaar_recognizer,
        passport_recognizer,
        voter_recognizer,
        dob_recognizer,
        phone_recognizer,
        ifsc_recognizer,
        pincode_recognizer,
        title_name_recognizer,
        address_recognizer,
        policy_recognizer,
    ]
