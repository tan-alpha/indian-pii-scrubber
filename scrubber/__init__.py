"""
Indian PII Scrubber Package

100% Offline Python engine for detecting and permanently redacting Indian-specific
Personally Identifiable Information (PII) from PDF documents.
"""

from scrubber.analyzer import (
    build_indian_analyzer,
    ensure_spacy_model,
    GATED_TYPES,
    TRUSTED_TYPES,
    CHECKSUM_TYPES,
    HybridAnalyzerEngine,
)
from scrubber.redactor import redact_pdf, process_page_pii, DEFAULT_ENTITIES
from scrubber.ocr import is_ocr_available
from scrubber.recognizers import get_indian_recognizers
from scrubber.slm import GlinerPiiEngine, load_gliner_model
from scrubber.validators import (
    validate_verhoeff,
    validate_pan_structure,
    validate_passport_mrz,
    validate_gstin_checksum,
    validate_dob_date,
    validate_state_code,
)

__version__ = "0.3.0"
__all__ = [
    "build_indian_analyzer",
    "ensure_spacy_model",
    "GATED_TYPES",
    "TRUSTED_TYPES",
    "CHECKSUM_TYPES",
    "HybridAnalyzerEngine",
    "redact_pdf",
    "process_page_pii",
    "is_ocr_available",
    "get_indian_recognizers",
    "GlinerPiiEngine",
    "load_gliner_model",
    "DEFAULT_ENTITIES",
    "validate_verhoeff",
    "validate_pan_structure",
    "validate_passport_mrz",
    "validate_gstin_checksum",
    "validate_dob_date",
    "validate_state_code",
]
