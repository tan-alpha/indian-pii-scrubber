"""
Presidio Analyzer Orchestrator with spaCy en_core_web_lg model initialization,
Indian PII pattern recognizer integration, and Local GLiNER SLM enhancement.
"""

import re
import sys
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
import spacy

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from scrubber.recognizers import get_indian_recognizers
from scrubber.slm import GlinerPiiEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hybrid redaction policy
# ---------------------------------------------------------------------------
#
# Why this exists: Presidio's `context=` parameter is a *confidence boost*, not
# a gate — a regex match fires at its base score regardless of context (verified
# against presidio_analyzer source: only LemmaContextAwareEnhancer adds +0.35,
# it never lowers a score). Several structural regexes here have base scores
# above the default 0.50 threshold, so they redact unconditionally and cause
# over-redaction (e.g. a 6-digit amount flagged as PINCODE, a sum-assured as a
# policy number, "BUILDING CODE" as an address).
#
# To make redaction reliable we add an explicit, deterministic *context gate*
# that runs BEFORE redaction. High-precision structural IDs (PAN, Aadhaar,
# IFSC, Passport, Voter, DOB, Email) are "trusted" — their regexes are specific
# enough that false positives are practically nil, so the SLM is NEVER allowed
# to veto them (avoids ever un-redacting a real ID). The noisy types below
# (PINCODE, POLICY, ADDRESS, PHONE) are only kept when there is explicit
# context evidence.
GATED_TYPES = {
    "INDIAN_PINCODE",
    "POLICY_OR_CUSTOMER_ID",
    "INDIAN_ADDRESS",
    "INDIAN_PHONE_NUMBER",
}

# Trusted structural IDs: never vetoes by the context gate or the SLM.
TRUSTED_TYPES = {
    "INDIAN_PAN",
    "INDIAN_AADHAAR",
    "INDIAN_PASSPORT",
    "INDIAN_VOTER_ID",
    "INDIAN_IFSC",
    "DATE_OF_BIRTH",
    "EMAIL_ADDRESS",
}


@dataclass
class DroppedEntity:
    """A regex hit suppressed by the context gate (kept out of the redaction set)."""

    entity_type: str
    start: int
    end: int
    score: float
    text: str
    reason: str


def build_context_map(recognizers) -> Dict[str, List[str]]:
    """Build {entity_type: [context keywords]} from registered recognizers.

    Single source of truth for the gate: reuses each recognizer's own `context`
    list so the keyword sets are never duplicated or drift out of sync.
    """
    return {
        rec.supported_entities[0]: list(rec.context)
        for rec in recognizers
        if getattr(rec, "context", None)
    }


def ensure_spacy_model(model_name: str = "en_core_web_lg") -> str:
    """
    Ensure the requested spaCy model is installed and loadable.
    If en_core_web_lg is missing, attempts fallback to en_core_web_sm with a warning.
    """
    if spacy.util.is_package(model_name):
        return model_name

    logger.warning(f"spaCy model '{model_name}' is not installed.")

    # Try fallback to en_core_web_sm if available
    fallback_model = "en_core_web_sm"
    if spacy.util.is_package(fallback_model):
        logger.warning(f"Falling back to installed spaCy model '{fallback_model}'.")
        return fallback_model

    # Attempt auto-downloading en_core_web_lg or fallback
    try:
        logger.info(f"Attempting to download spaCy model '{model_name}'...")
        spacy.cli.download(model_name)
        return model_name
    except Exception as e:
        logger.error(f"Failed to auto-download '{model_name}': {e}")
        try:
            logger.info(f"Attempting to download fallback model '{fallback_model}'...")
            spacy.cli.download(fallback_model)
            return fallback_model
        except Exception as e2:
            raise RuntimeError(
                f"Could not load or download any spaCy model. Please run: 'python -m spacy download {model_name}'"
            ) from e2


class HybridAnalyzerEngine:
    """
    Hybrid Analyzer Engine combining Presidio Regex/NER with Local GLiNER SLM.

    The SLM does TWO jobs here (not just "add" results as it used to):
      1. *Adjudicate* noisy regex hits — a PINCODE/POLICY/ADDRESS/PHONE regex hit
         is suppressed unless a context keyword is nearby OR the SLM corroborates
         it in sentence context. This is the "SLM validates properly" path.
      2. *Fill* genuine misses that pure regex + spaCy NER missed (e.g. bare
         person names, unlabeled addresses) by contributing its own spans.

    Exactly ONE GLiNER pass is run per analyze() call, so there is no extra
    latency versus the previous additive-only behaviour.
    """

    def __init__(
        self,
        presidio_analyzer: AnalyzerEngine,
        slm_engine: Optional[GlinerPiiEngine] = None,
        context_map: Optional[Dict[str, List[str]]] = None,
        gated_types: Optional[set] = None,
    ):
        self.presidio_analyzer = presidio_analyzer
        self.slm_engine = slm_engine
        self._context_map = context_map or {}
        self._gated_types = gated_types or GATED_TYPES

    def _has_context(self, text: str, res: RecognizerResult, entity_type: str) -> bool:
        """
        True if a recognizer-defined context keyword is on the SAME physical
        line as the match.

        Same-line (not char-window) matching is deliberate and what makes the
        gate bulletproof: a nearby label that actually belongs to a different
        value must NOT keep an unrelated number. Concretely, in::

            Pincode: 560001
            INR 150000 credited to your account.

        '150000' lives on the "INR 150000 ..." line, which contains no pincode
        keyword, so it is suppressed — even though "Pincode:" is only one line
        above. Whole-word/phrase token matching is used so keyword 'pin' does
        NOT match 'pink'. Cheap and deterministic.
        """
        keywords = self._context_map.get(entity_type, [])
        if not keywords:
            return False
        line_start = text.rfind("\n", 0, res.start) + 1
        line_end = text.find("\n", res.end)
        if line_end == -1:
            line_end = len(text)
        tokens = re.findall(r"[a-z]+", text[line_start:line_end].lower())
        for kw in keywords:
            kw_tokens = re.findall(r"[a-z]+", kw.lower())
            n = len(kw_tokens)
            if n == 0:
                continue
            for i in range(len(tokens) - n + 1):
                if tokens[i : i + n] == kw_tokens:
                    return True
        return False

    def _apply_context_gate(
        self,
        results: List[RecognizerResult],
        text: str,
        slm_results: List[RecognizerResult],
        entities: Optional[List[str]],
    ) -> Tuple[List[RecognizerResult], List[DroppedEntity]]:
        """
        Suppress noisy regex hits that lack context support.

        For each result:
          - Trusted structural IDs are always kept.
          - Gated types are kept only if a context keyword is nearby OR the SLM
            corroborates the hit (one GLiNER pass only). Otherwise dropped.
        """
        target = set(entities) if entities else None
        kept: List[RecognizerResult] = []
        dropped: List[DroppedEntity] = []
        for res in results:
            etype = res.entity_type
            # Only gate types the user actually requested (or all, if none).
            if target and etype not in target:
                continue
            if etype not in self._gated_types or etype in TRUSTED_TYPES:
                kept.append(res)
                continue
            if self._has_context(text, res, etype):
                kept.append(res)
            elif slm_results and GlinerPiiEngine.corroborates(
                slm_results, res.start, res.end, etype
            ):
                kept.append(res)
            else:
                dropped.append(
                    DroppedEntity(
                        entity_type=etype,
                        start=res.start,
                        end=res.end,
                        score=res.score,
                        text=text[res.start : res.end],
                        reason="no_context_and_no_slm_corroboration",
                    )
                )
        return kept, dropped

    def analyze(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        language: str = "en",
        score_threshold: float = 0.50,
        use_slm: bool = True,
    ) -> Tuple[List[RecognizerResult], List[DroppedEntity]]:
        """
        Analyze text using Presidio (Regex + spaCy NER) and a single Local GLiNER
        SLM pass, then apply the deterministic context gate.

        Returns (kept_results, dropped_entities). ``dropped_entities`` lists the
        noisy regex hits suppressed by the gate (for explainable previews).
        """
        # Step 1: Run Presidio Analyzer (Regex + spaCy NER). Presidio already
        # applies its context *boost* here — but a boost only ever raises a
        # score, it never removes a match, so the gate below is what enforces
        # true context-gating for the noisy types.
        presidio_results = self.presidio_analyzer.analyze(
            text=text,
            entities=entities,
            language=language,
            score_threshold=score_threshold,
        )

        # Step 2: Run the Local GLiNER SLM Engine ONCE (when available). Its
        # results feed both SLM-corroboration in the gate and additive fills.
        slm_results: List[RecognizerResult] = []
        if use_slm and self.slm_engine and self.slm_engine.is_available():
            slm_results = self.slm_engine.analyze(
                text=text, score_threshold=score_threshold
            )
            if entities:
                slm_results = [r for r in slm_results if r.entity_type in entities]

        # Step 3: Deterministic context gate (drops noisy regex hits that have
        # neither context nor SLM corroboration). This is what eliminates the
        # over-redaction caused by Presidio's boost-only context handling.
        presidio_kept, dropped = self._apply_context_gate(
            presidio_results, text, slm_results, entities
        )

        # Step 4: Merge SLM results, adding the ones that don't overlap a kept
        # Presidio result of the same type (fills genuine misses).
        combined = list(presidio_kept)
        for slm_res in slm_results:
            is_dup = False
            for p_res in presidio_kept:
                if (
                    p_res.entity_type == slm_res.entity_type
                    and max(p_res.start, slm_res.start) < min(p_res.end, slm_res.end)
                ):
                    is_dup = True
                    break
            if not is_dup:
                combined.append(slm_res)

        # Stable ordering + exact-duplicate removal (no overlap merging: the
        # redactor draws one box per span, overlapping spans are intentional).
        combined.sort(key=lambda r: (r.start, -r.score))
        seen = set()
        final: List[RecognizerResult] = []
        for r in combined:
            key = (r.entity_type, r.start, r.end)
            if key not in seen:
                seen.add(key)
                final.append(r)

        return final, dropped


def build_indian_analyzer(
    spacy_model: str = "en_core_web_lg",
    custom_recognizers: Optional[List] = None,
    enable_slm: bool = True,
) -> HybridAnalyzerEngine:
    """
    Construct and return a HybridAnalyzerEngine loaded with spaCy NLP, custom Indian recognizers,
    and local GLiNER SLM enabled by default.
    """
    active_model = ensure_spacy_model(spacy_model)
    logger.info(f"Initializing Presidio AnalyzerEngine with spaCy model '{active_model}'...")

    # Configure Presidio NLP engine provider with spaCy
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": active_model}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()

    # Load default Presidio recognizers and add Indian PII recognizers
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    indian_recognizers = get_indian_recognizers()
    for recognizer in indian_recognizers:
        registry.add_recognizer(recognizer)

    if custom_recognizers:
        for recognizer in custom_recognizers:
            registry.add_recognizer(recognizer)

    presidio_analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)

    slm_engine = None
    if enable_slm:
        slm_engine = GlinerPiiEngine()

    # Build the entity_type -> context-keywords map the context gate reuses.
    context_map = build_context_map(indian_recognizers)

    logger.info("Hybrid Presidio + Local GLiNER SLM AnalyzerEngine initialized successfully.")
    return HybridAnalyzerEngine(
        presidio_analyzer=presidio_analyzer,
        slm_engine=slm_engine,
        context_map=context_map,
    )
