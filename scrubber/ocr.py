"""
Tesseract OCR Engine integration for Scanned PDF pages.
Extracts text and word-level bounding box coordinates from rendered PDF page images.
Provides graceful availability checks to prevent app crashes when Tesseract is missing.
"""

import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger(__name__)

# Check pytesseract availability
try:
    import pytesseract
    from PIL import Image
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False


def is_ocr_available() -> Tuple[bool, str]:
    """
    Check if pytesseract is installed and the Tesseract system binary is reachable.
    Returns (is_available, status_message).
    """
    if not PYTESSERACT_AVAILABLE:
        return False, "pytesseract library is not installed in current Python environment."

    try:
        # Quick version check to verify binary existence
        version = pytesseract.get_tesseract_version()
        return True, f"Tesseract OCR v{version} is available."
    except Exception as e:
        return False, (
            "Tesseract OCR system binary is not found on PATH. "
            "Install Tesseract OCR on your OS or run via Docker for scanned PDF support."
        )


def extract_ocr_words(image: "Image.Image") -> List[Dict[str, Any]]:
    """
    Run Tesseract OCR on a PIL Image object.
    Returns a list of word metadata dictionaries:
    [
        {
            'text': str,
            'bbox': (left, top, right, bottom), # pixel coordinates
            'confidence': float
        }, ...
    ]
    """
    available, msg = is_ocr_available()
    if not available:
        logger.warning(msg)
        return []

    try:
        # Get detailed word box data from pytesseract
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        words = []

        n_boxes = len(data["text"])
        for i in range(n_boxes):
            text = data["text"][i].strip()
            conf = float(data["conf"][i])

            if text and conf > 30:  # Filter out empty and extremely low-confidence noisy tokens
                x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                words.append({
                    "text": text,
                    "bbox": (x, y, x + w, y + h),
                    "confidence": conf / 100.0,
                })

        return words

    except Exception as e:
        logger.error(f"Error executing Tesseract OCR on page image: {e}")
        return []
