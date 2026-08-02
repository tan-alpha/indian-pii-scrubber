"""
Automated unit tests for Indian PII Scrubber recognizers, the context gate,
and the hybrid analyzer engine.

The first two tests exercise individual recognizers (fast, no model load).
The remaining tests cover the over-redaction / under-redaction regressions the
context gate and the extended name regexes were built to fix.
"""

import time

import pytest
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from scrubber import build_indian_analyzer, get_indian_recognizers
from scrubber.analyzer import (
    GATED_TYPES,
    TRUSTED_TYPES,
    HybridAnalyzerEngine,
    build_context_map,
)
from scrubber.slm import GlinerPiiEngine


def test_indian_recognizers_registration():
    recognizers = get_indian_recognizers()
    assert len(recognizers) >= 9

    entity_types = [r.supported_entities[0] for r in recognizers]
    assert "INDIAN_PAN" in entity_types
    assert "INDIAN_AADHAAR" in entity_types
    assert "INDIAN_PASSPORT" in entity_types
    assert "INDIAN_VOTER_ID" in entity_types
    assert "DATE_OF_BIRTH" in entity_types
    assert "INDIAN_PHONE_NUMBER" in entity_types
    assert "INDIAN_IFSC" in entity_types
    assert "INDIAN_PINCODE" in entity_types


def test_pan_recognizer_matching():
    recognizers = get_indian_recognizers()
    pan_rec = [r for r in recognizers if "INDIAN_PAN" in r.supported_entities][0]

    text = "The PAN number of the taxpayer is ABCDE1234F."
    results = pan_rec.analyze(text, entities=["INDIAN_PAN"])
    assert len(results) >= 1
    assert results[0].entity_type == "INDIAN_PAN"
    assert text[results[0].start:results[0].end] == "ABCDE1234F"


def test_aadhaar_recognizer_matching():
    recognizers = get_indian_recognizers()
    aadhaar_rec = [r for r in recognizers if "INDIAN_AADHAAR" in r.supported_entities][0]

    text = "Aadhaar Card No: 9876 5432 1012 for identification."
    results = aadhaar_rec.analyze(text, entities=["INDIAN_AADHAAR"])
    assert len(results) >= 1
    assert results[0].entity_type == "INDIAN_AADHAAR"
    assert text[results[0].start:results[0].end] == "9876 5432 1012"


def _stub_presidio(results):
    """Minimal stand-in for Presidio's AnalyzerEngine returning preset results."""

    class _Stub:
        def analyze(self, text, entities=None, language="en", score_threshold=0.5, **kw):
            if entities:
                return [r for r in results if r.entity_type in entities]
            return list(results)

    return _Stub()


def _res(entity_type, text, value):
    s = text.index(value)
    return RecognizerResult(
        entity_type=entity_type, start=s, end=s + len(value), score=0.75
    )


# ---------------------------------------------------------------------------
# Context gate: deterministic, no model loads required
# ---------------------------------------------------------------------------

def test_gate_drops_contextless_pincode_but_keeps_labeled():
    """Over-redaction regression: a bare amount must NOT be redacted as a pincode
    when no PIN/Pincode context sits on its line; a real labeled pincode is kept."""
    recs = get_indian_recognizers()
    eng = HybridAnalyzerEngine(
        presidio_analyzer=_stub_presidio([]), context_map=build_context_map(recs)
    )
    text = "INR 150000 credited to your account.\nPincode: 560001"
    results = [_res("INDIAN_PINCODE", text, "150000"), _res("INDIAN_PINCODE", text, "560001")]
    kept, dropped = eng._apply_context_gate(results, text, [], None)
    dropped_texts = {text[d.start:d.end] for d in dropped}
    kept_texts = {text[k.start:k.end] for k in kept}
    assert "150000" in dropped_texts
    assert "560001" in kept_texts


def test_gate_drops_contextless_policy_but_keeps_labeled():
    """Over-redaction regression: a sum-assured amount must NOT be redacted as a
    policy/customer id without an explicit label; 'Policy No:' keeps it."""
    recs = get_indian_recognizers()
    eng = HybridAnalyzerEngine(
        presidio_analyzer=_stub_presidio([]), context_map=build_context_map(recs)
    )
    text = "Sum Assured is 10000000 for this policy.\nPolicy No: 1000000012345678"
    results = [
        _res("POLICY_OR_CUSTOMER_ID", text, "10000000"),
        _res("POLICY_OR_CUSTOMER_ID", text, "1000000012345678"),
    ]
    kept, dropped = eng._apply_context_gate(results, text, [], None)
    dropped_texts = {text[d.start:d.end] for d in dropped}
    kept_texts = {text[k.start:k.end] for k in kept}
    assert "10000000" in dropped_texts
    assert "1000000012345678" in kept_texts


def test_gate_drops_unlabeled_address_keyword():
    """Over-redaction regression: 'BUILDING CODE compliance' must NOT be redacted as
    an address when no address-context word is on its line."""
    recs = get_indian_recognizers()
    eng = HybridAnalyzerEngine(
        presidio_analyzer=_stub_presidio([]), context_map=build_context_map(recs)
    )
    text = "STATE OF BHARAT and BUILDING CODE compliance clause."
    results = [_res("INDIAN_ADDRESS", text, "BUILDING CODE compliance clause")]
    kept, dropped = eng._apply_context_gate(results, text, [], None)
    assert kept == []
    assert len(dropped) == 1
    assert dropped[0].entity_type == "INDIAN_ADDRESS"


def test_gate_keeps_address_with_slm_corroboration():
    """Under-redaction safeguard: an unlabeled street line is still kept when the
    SLM corroborates it as a residential address/street locality."""
    recs = get_indian_recognizers()
    eng = HybridAnalyzerEngine(
        presidio_analyzer=_stub_presidio([]), context_map=build_context_map(recs)
    )
    text = "12 MG Road, ABC Nagar, Sector 5"
    hit = _res("INDIAN_ADDRESS", text, "12 MG Road, ABC Nagar")
    # GLiLER says the same span is a street locality -> should be corroborated
    slm = [
        RecognizerResult(
            entity_type="INDIAN_ADDRESS",
            start=hit.start,
            end=hit.end,
            score=0.9,
        )
    ]
    kept, dropped = eng._apply_context_gate([hit], text, slm, None)
    assert len(kept) == 1
    assert kept[0].start == hit.start
    assert dropped == []


def test_gate_never_vetoes_trusted_structural_ids():
    """Trusted IDs (PAN/Aadhaar/etc.) are kept unconditionally — the gate must
    never suppress them, even with no context keyword present."""
    recs = get_indian_recognizers()
    eng = HybridAnalyzerEngine(
        presidio_analyzer=_stub_presidio([]), context_map=build_context_map(recs)
    )
    assert TRUSTED_TYPES.isdisjoint(GATED_TYPES)
    text = "ABCDE1234F"  # standalone PAN, no context label on the line
    results = [_res("INDIAN_PAN", text, "ABCDE1234F")]
    kept, dropped = eng._apply_context_gate(results, text, [], None)
    assert len(kept) == 1 and dropped == []


# ---------------------------------------------------------------------------
# Name regex robustness (recognizer-level, no models required)
# ---------------------------------------------------------------------------

def test_title_name_regex_catches_allcaps_and_labelled_and_internals():
    recognizers = get_indian_recognizers()
    title_rec = [r for r in recognizers if "TITLE_PERSON_NAME" in r.supported_entities][0]

    should_hit = [
        "Shri RAJESH KUMAR",        # all-caps title name
        "Shri Rajesh Kumar",        # title-case title name
        "Policyholder: Amitab Bachchan",  # label + name (no honorific)
        "Name: M. Srinivasan",      # label + initial-surname
        "Smt SUNITA DEVI",          # all-caps title name
        "Dr. Sneha Patel",          # title + title-case
    ]
    no_match = [
        "Name: Address",            # single token after label
        "Policy Number 10000000",   # label has no colon separator
        "BUILDING CODE compliance", # not a name
    ]

    for s in should_hit:
        res = title_rec.analyze(s, entities=["TITLE_PERSON_NAME"])
        assert res, f"expected TITLE_PERSON_NAME hit for: {s!r}"

    for s in no_match:
        res = title_rec.analyze(s, entities=["TITLE_PERSON_NAME"])
        assert res == [], f"expected no match for: {s!r}"


# ---------------------------------------------------------------------------
# Integration tests (build the real analyzer; skip if models are unavailable)
# ---------------------------------------------------------------------------

def _models_available():
    import spacy
    gliner_ok = GlinerPiiEngine().is_available()
    spacy_ok = spacy.util.is_package("en_core_web_lg")
    return spacy_ok and gliner_ok


@pytest.fixture(scope="module")
def hybrid_analyzer():
    if not _models_available():
        pytest.skip("en_core_web_lg and/or GLiNER not available in this env")
    return build_indian_analyzer(spacy_model="en_core_web_lg", enable_slm=True)


def test_no_slm_gate_still_drops_overredactions(hybrid_analyzer):
    """Even with the SLM disabled, the deterministic context gate must drop the
    three canonical over-redaction cases (amount, sum assured, building-code)."""
    samples = [
        ("INR 150000 credited to your account.", "INDIAN_PINCODE"),
        ("Sum Assured is 10000000 for this policy.", "POLICY_OR_CUSTOMER_ID"),
        ("STATE OF BHARAT and BUILDING CODE compliance clause.", "INDIAN_ADDRESS"),
    ]
    for text, etype in samples:
        kept, dropped = hybrid_analyzer.analyze(
            text, entities=[etype], score_threshold=0.50, use_slm=False
        )
        kept_types = {r.entity_type for r in kept}
        assert etype not in kept_types, f"over-redaction not suppressed for {etype!r}"
        assert any(d.entity_type == etype for d in dropped)


def test_labeled_values_are_kept(hybrid_analyzer):
    """True positives with proper context labels must survive the gate."""
    cases = [
        ("Pincode: 560001", "INDIAN_PINCODE", "560001"),
        ("Policy No: 1000000012345678", "POLICY_OR_CUSTOMER_ID", "1000000012345678"),
        ("Mobile: 9876543210", "INDIAN_PHONE_NUMBER", "9876543210"),
    ]
    for text, etype, value in cases:
        kept, dropped = hybrid_analyzer.analyze(
            text, entities=[etype], score_threshold=0.50, use_slm=False
        )
        assert any(text[r.start:r.end] == value for r in kept), (
            f"{etype} labeled value not preserved"
        )


def test_slm_catches_names_without_title(hybrid_analyzer):
    """Obvious names without an honorific prefix or in all-caps must be redacted."""
    cases = ["Rajesh Kumar", "Shri RAJESH KUMAR", "M. Srinivasan"]
    for text in cases:
        kept, _ = hybrid_analyzer.analyze(
            text,
            entities=["PERSON", "TITLE_PERSON_NAME"],
            score_threshold=0.50,
            use_slm=True,
        )
        covered = {text[r.start:r.end] for r in kept}
        assert any(t in covered for t in ["Rajesh Kumar", "RAJESH KUMAR", "M. Srinivasan"]), (
            f"obvious name not redacted: {text!r}"
        )


def test_gliner_single_pass_is_fast(hybrid_analyzer):
    """Performance guardrail: one GLiNER pass on a ~2KB page must stay well under
    the per-page budget so batch processing remains snappy (CPU only)."""
    if not hybrid_analyzer.slm_engine or not hybrid_analyzer.slm_engine.is_available():
        pytest.skip("GLiNER not available")
    text = (
        "PAN Card Number: ABCDE1234F. Aadhaar: 9876 5432 1012. "
        "Mobile: 9876543210. Pincode: 560001. Name: Rajesh Kumar. "
        "Policy No: 1234567890123456. Sum Assured 10000000. "
    ) * 3
    start = time.perf_counter()
    hybrid_analyzer.slm_engine.analyze(text=text, score_threshold=0.5)
    elapsed = time.perf_counter() - start
    assert elapsed < 4.0, f"GLiNER pass too slow: {elapsed:.2f}s"

