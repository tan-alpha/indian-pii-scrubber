"""
Utility functions for PDF page rendering, thumbnail generation,
and coordinate transformations for UI previews.
"""

import io
from typing import List, Tuple, Dict, Any
import fitz  # PyMuPDF
from PIL import Image, ImageDraw


def render_page_to_image(page: fitz.Page, dpi: int = 150) -> Image.Image:
    """Render a PyMuPDF Page object to a PIL Image."""
    zoom = dpi / 72.0
    matrix = fitz.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=matrix, alpha=False)
    img_data = pix.tobytes("png")
    return Image.open(io.BytesIO(img_data))


def draw_bounding_boxes_on_image(
    image: Image.Image,
    bboxes: List[Tuple[float, float, float, float]],
    pdf_page_size: Tuple[float, float],
    color: str = "red",
    fill_alpha: int = 60,
) -> Image.Image:
    """
    Draw highlight bounding boxes on a page image.
    bboxes are in PDF point coordinates (x0, y0, x1, y1).
    pdf_page_size is (width, height) of the PDF page in points.
    """
    img = image.copy().convert("RGBA")
    draw = ImageDraw.Draw(img)

    img_w, img_h = img.size
    pdf_w, pdf_h = pdf_page_size

    scale_x = img_w / pdf_w if pdf_w > 0 else 1.0
    scale_y = img_h / pdf_h if pdf_h > 0 else 1.0

    for rect in bboxes:
        x0, y0, x1, y1 = rect
        px0 = x0 * scale_x
        py0 = y0 * scale_y
        px1 = x1 * scale_x
        py1 = y1 * scale_y

        # Draw semi-transparent rectangle overlay
        draw.rectangle(
            [px0, py0, px1, py1],
            fill=(255, 0, 0, fill_alpha),
            outline=(255, 0, 0, 255),
            width=2,
        )

    return img.convert("RGB")
