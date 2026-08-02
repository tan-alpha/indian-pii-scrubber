"""
Local Small Language Model (SLM) Engine using GLiNER (Generalist Model for Named Entity Recognition).
Provides zero-shot semantic PII extraction 100% offline without external servers.
"""

import logging
from typing import List, Dict, Any, Optional
from presidio_analyzer import RecognizerResult

logger = logging.getLogger(__name__)

# Entity types the Local SLM (GLiNER) can corroborate. Pincode/Policy have no
# GLI zero-shot label, so their regex hits can only be corroborated by a nearby
# context keyword — never by the SLM.
SLM_CORROBORATABLE_TYPES = {
    "INDIAN_ADDRESS",
    "INDIAN_PHONE_NUMBER",
    "INDIAN_AADHAAR",
    "INDIAN_PAN",
    "DATE_OF_BIRTH",
    "PERSON",
}

# Target zero-shot labels for Indian PII documents
SLM_PII_LABELS = [
    "person name",
    "policyholder name",
    "residential address",
    "street name or locality",
    "aadhaar number",
    "pan card number",
    "personal phone number",
    "date of birth",
]

# Mapping GLiNER label names to standardized Presidio entity types
LABEL_TO_ENTITY_TYPE = {
    "person name": "PERSON",
    "policyholder name": "PERSON",
    "residential address": "INDIAN_ADDRESS",
    "street name or locality": "INDIAN_ADDRESS",
    "aadhaar number": "INDIAN_AADHAAR",
    "pan card number": "INDIAN_PAN",
    "personal phone number": "INDIAN_PHONE_NUMBER",
    "date of birth": "DATE_OF_BIRTH",
}

_GLINER_MODEL_CACHE = None


def load_gliner_model(model_name: str = "urchade/gliner_small-v2.1"):
    """
    Load and cache GLiNER model locally.
    Downloads once on first run (~300MB) and reuses local PyTorch weights offline.
    """
    global _GLINER_MODEL_CACHE
    if _GLINER_MODEL_CACHE is not None:
        return _GLINER_MODEL_CACHE

    try:
        from gliner import GLiNER
        logger.info(f"Loading local GLiNER SLM model '{model_name}'...")
        # Attempt loading with local_files_only first for true offline guarantee
        try:
            _GLINER_MODEL_CACHE = GLiNER.from_pretrained(model_name, local_files_only=True)
            logger.info("Local GLiNER SLM model loaded from local cache (100% offline).")
        except Exception:
            logger.info(f"Downloading model '{model_name}' to local cache for offline execution...")
            _GLINER_MODEL_CACHE = GLiNER.from_pretrained(model_name)
            logger.info("Local GLiNER SLM model downloaded and cached successfully.")
        return _GLINER_MODEL_CACHE
    except Exception as e:
        logger.warning(f"Could not load GLiNER SLM model '{model_name}': {e}")
        return None


class GlinerPiiEngine:
    """
    Local SLM PII Extractor wrapping GLiNER.
    Converts zero-shot semantic entity predictions into Presidio RecognizerResult objects.
    """

    def __init__(self, model_name: str = "urchade/gliner_small-v2.1"):
        self.model_name = model_name
        self.model = load_gliner_model(model_name)

    def is_available(self) -> bool:
        return self.model is not None

    @staticmethod
    def corroborates(slm_results, start: int, end: int, entity_type: str) -> bool:
        """
        True if a same-entity_type GLiNER result overlaps [start, end).

        Used by the HybridAnalyzerEngine to let the SLM *validate* a regex hit
        in full sentence context instead of merely adding new detections.
        No extra model call: operates on results already produced by ``analyze``.
        """
        if entity_type not in SLM_CORROBORATABLE_TYPES:
            return False
        for r in slm_results:
            if r.entity_type == entity_type and max(r.start, start) < min(r.end, end):
                return True
        return False

    def analyze(
        self,
        text: str,
        score_threshold: float = 0.40,
        labels: Optional[List[str]] = None,
    ) -> List[RecognizerResult]:
        """
        Analyze text using local GLiNER SLM and return Presidio-compatible RecognizerResult objects.
        """
        if not self.model or not text.strip():
            return []

        target_labels = labels if labels else SLM_PII_LABELS

        try:
            # Run zero-shot entity prediction via GLiNER
            predictions = self.model.predict_entities(
                text,
                target_labels,
                threshold=score_threshold,
            )

            results = []
            for pred in predictions:
                label = pred["label"]
                entity_type = LABEL_TO_ENTITY_TYPE.get(label, "PII_GENERIC")
                start = pred["start"]
                end = pred["end"]
                score = float(pred["score"])

                rec_result = RecognizerResult(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    score=score,
                )
                results.append(rec_result)

            return results

        except Exception as e:
            logger.error(f"Error running GLiNER SLM prediction: {e}")
            return []
