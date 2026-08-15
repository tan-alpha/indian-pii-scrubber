"""
PyMuPDF (fitz) Spatial Coordinate Mapping & Vector Redaction Engine.
Extracts page word quads, matches Presidio/SLM PII character spans to precise bounding boxes,
and applies permanent blackbox visual redactions while wiping underlying text streams.
Supports scanned page OCR fallback via pytesseract.
"""

import logging
from typing import List, Dict, Tuple, Any, Optional
import fitz  # PyMuPDF
from presidio_analyzer import RecognizerResult

from scrubber.ocr import extract_ocr_words, is_ocr_available
from scrubber.utils import render_page_to_image, draw_bounding_boxes_on_image

logger = logging.getLogger(__name__)

# Default PII entities to redact — all standard Indian PII types enabled by default
# for maximum privacy protection. Trusted structural IDs are always redacted;
# gated types require context or SLM corroboration (see analyzer.py GATED_TYPES).
DEFAULT_ENTITIES = [
    "INDIAN_PAN",
    "INDIAN_AADHAAR",
    "INDIAN_PASSPORT",
    "INDIAN_PASSPORT_MRZ",
    "INDIAN_VOTER_ID",
    "DATE_OF_BIRTH",
    "INDIAN_PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "TITLE_PERSON_NAME",
    "INDIAN_ADDRESS",
    "POLICY_OR_CUSTOMER_ID",
    "INDIAN_IFSC",
    "INDIAN_PINCODE",
    "INDIAN_DRIVING_LICENSE",
    "INDIAN_GSTIN",
    "INDIAN_VEHICLE_REGISTRATION",
    "INDIAN_BANK_ACCOUNT",
    "ITR_ACKNOWLEDGEMENT_NUMBER",
    "PERSON",
]


def map_char_spans_to_rects(
    words: List[Tuple[float, float, float, float, str, int, int, int]],
    results: List[RecognizerResult],
    page_text: str,
) -> List[Tuple[fitz.Rect, RecognizerResult]]:
    """
    Map RecognizerResult character spans [start, end] to exact PyMuPDF word Rects.
    `words` is a list of tuples from page.get_text("words"):
    (x0, y0, x1, y1, "word_string", block_no, line_no, word_no)
    """
    rect_matches = []

    # Build character index mapping for words on the page
    word_spans = []
    current_pos = 0

    for w in words:
        w_text = w[4]
        # Search for w_text in page_text starting from current_pos
        idx = page_text.find(w_text, current_pos)
        if idx != -1:
            w_start = idx
            w_end = idx + len(w_text)
            word_spans.append((w_start, w_end, fitz.Rect(w[0], w[1], w[2], w[3])))
            current_pos = w_end
        else:
            # Fallback search from beginning if not found sequentially
            idx2 = page_text.find(w_text)
            if idx2 != -1:
                word_spans.append((idx2, idx2 + len(w_text), fitz.Rect(w[0], w[1], w[2], w[3])))

    # For each PII result, find all overlapping word bounding boxes
    for res in results:
        res_start = res.start
        res_end = res.end

        # Find words that fall within or overlap [res_start, res_end]
        matched_rects = []
        for w_start, w_end, w_rect in word_spans:
            if max(w_start, res_start) < min(w_end, res_end):
                matched_rects.append(w_rect)

        if matched_rects:
            for r in matched_rects:
                rect_matches.append((r, res))

    return rect_matches


def process_page_pii(
    page: fitz.Page,
    analyzer,
    entities: Optional[List[str]] = None,
    score_threshold: float = 0.50,
    force_ocr: bool = False,
    use_slm: bool = True,
) -> Dict[str, Any]:
    """
    Process a single PDF page: analyze text for PII using Hybrid Presidio + SLM Engine and return bounding boxes.
    """
    target_entities = entities if entities else DEFAULT_ENTITIES
    page_text = page.get_text("text")
    words = page.get_text("words")

    is_scanned = len(words) == 0 or force_ocr
    ocr_used = False
    rect_matches = []
    results = []
    dropped = []

    if not is_scanned and page_text.strip():
        # Digital PDF path via Hybrid Presidio + SLM Engine
        results, dropped = analyzer.analyze(
            text=page_text,
            entities=target_entities,
            language="en",
            score_threshold=score_threshold,
            use_slm=use_slm,
        )
        rect_matches = map_char_spans_to_rects(words, results, page_text)

    else:
        # Scanned PDF path via Tesseract OCR
        ocr_ok, ocr_msg = is_ocr_available()
        if ocr_ok:
            ocr_used = True
            page_img = render_page_to_image(page, dpi=300)
            ocr_words = extract_ocr_words(page_img)

            # Reconstruct OCR text and mapping
            ocr_text = " ".join([w["text"] for w in ocr_words])
            if ocr_text.strip():
                results, dropped = analyzer.analyze(
                    text=ocr_text,
                    entities=target_entities,
                    language="en",
                    score_threshold=score_threshold,
                    use_slm=use_slm,
                )

                # Map pixel bboxes to PDF point coordinates
                img_w, img_h = page_img.size
                pdf_w, pdf_h = page.rect.width, page.rect.height
                scale_x = pdf_w / img_w if img_w > 0 else 1.0
                scale_y = pdf_h / img_h if img_h > 0 else 1.0

                ocr_spans = []
                cur_pos = 0
                for w in ocr_words:
                    w_str = w["text"]
                    idx = ocr_text.find(w_str, cur_pos)
                    if idx != -1:
                        w_start = idx
                        w_end = idx + len(w_str)
                        px0, py0, px1, py1 = w["bbox"]
                        pdf_rect = fitz.Rect(
                            px0 * scale_x, py0 * scale_y, px1 * scale_x, py1 * scale_y
                        )
                        ocr_spans.append((w_start, w_end, pdf_rect))
                        cur_pos = w_end

                for res in results:
                    for w_start, w_end, w_rect in ocr_spans:
                        if max(w_start, res.start) < min(w_end, res.end):
                            rect_matches.append((w_rect, res))
        else:
            logger.warning(f"Page {page.number + 1} is scanned, but OCR is unavailable: {ocr_msg}")

    # Format summary stats for this page
    entity_counts = {}
    bounding_boxes = []
    for rect, res in rect_matches:
        entity_counts[res.entity_type] = entity_counts.get(res.entity_type, 0) + 1
        bounding_boxes.append((rect.x0, rect.y0, rect.x1, rect.y1))

    # Context-gate suppressions (regex hits dropped for lacking context/SLM support)
    dropped_counts = {}
    for d in dropped:
        dropped_counts[d.entity_type] = dropped_counts.get(d.entity_type, 0) + 1

    return {
        "page_number": page.number + 1,
        "is_scanned": is_scanned,
        "ocr_used": ocr_used,
        "results_count": len(results),
        "rect_matches": rect_matches,
        "bounding_boxes": bounding_boxes,
        "entity_counts": entity_counts,
        "dropped_counts": dropped_counts,
        "dropped": [
            {
                "entity_type": d.entity_type,
                "start": d.start,
                "end": d.end,
                "score": d.score,
                "text": d.text,
                "reason": d.reason,
            }
            for d in dropped
        ],
    }


def redact_pdf(
    input_path: str,
    output_path: str,
    analyzer,
    entities: Optional[List[str]] = None,
    score_threshold: float = 0.50,
    force_ocr: bool = False,
    use_slm: bool = True,
) -> Dict[str, Any]:
    """
    Open PDF, detect PII using Hybrid Engine, apply permanent vector blackbox redactions, wipe text streams, and save.
    Returns structured processing stats.
    """
    doc = fitz.open(input_path)
    total_pages = len(doc)
    total_redactions = 0
    total_dropped = 0
    all_entity_counts = {}
    all_dropped_counts = {}
    page_summaries = []

    for page_idx in range(total_pages):
        page = doc[page_idx]
        page_info = process_page_pii(
            page,
            analyzer,
            entities=entities,
            score_threshold=score_threshold,
            force_ocr=force_ocr,
            use_slm=use_slm,
        )

        rect_matches = page_info["rect_matches"]

        # Apply redaction annotations
        for rect, res in rect_matches:
            page.add_redact_annot(rect, fill=(0, 0, 0))
            total_redactions += 1

            ent = res.entity_type
            all_entity_counts[ent] = all_entity_counts.get(ent, 0) + 1

        # Roll up context-gate suppressions across the document
        for ent, cnt in page_info.get("dropped_counts", {}).items():
            all_dropped_counts[ent] = all_dropped_counts.get(ent, 0) + cnt
            total_dropped += cnt

        # Apply redactions to permanently strip text stream underneath annotations
        if rect_matches:
            page.apply_redactions()

        page_summaries.append(page_info)

    doc.save(output_path, garbage=4, deflate=True)
    doc.close()

    return {
        "input_path": input_path,
        "output_path": output_path,
        "total_pages": total_pages,
        "total_redactions": total_redactions,
        "total_dropped": total_dropped,
        "entity_counts": all_entity_counts,
        "dropped_counts": all_dropped_counts,
        "page_summaries": page_summaries,
    }
