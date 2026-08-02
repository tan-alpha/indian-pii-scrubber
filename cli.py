#!/usr/bin/env python3
"""
Indian PII Scrubber - CLI Interface

Sanitize Indian PII (PAN, Aadhaar, Passport, Voter ID, DOB, Phone, Email, Names, Addresses)
from PDF documents completely offline using Hybrid Presidio + Local GLiNER SLM.

Usage:
    python cli.py input.pdf -o output_redacted.pdf
    python cli.py /path/to/pdf_folder -o /path/to/output_folder --force-ocr
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from scrubber import build_indian_analyzer, redact_pdf, DEFAULT_ENTITIES, is_ocr_available

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scrubber-cli")


def parse_args():
    parser = argparse.ArgumentParser(
        description="🔒 Indian PII Scrubber - 100% Offline PDF Redaction Engine (Hybrid Presidio + Local SLM)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "input",
        type=str,
        help="Input PDF file path or directory containing PDF files.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output PDF file path or output directory. Defaults to appending '_redacted.pdf'.",
    )
    parser.add_argument(
        "-e", "--entities",
        nargs="+",
        default=DEFAULT_ENTITIES,
        help="List of PII entity types to redact.",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.50,
        help="Confidence score threshold (0.0 to 1.0).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="en_core_web_lg",
        help="spaCy language model to use for NER.",
    )
    parser.add_argument(
        "--no-slm",
        action="store_true",
        help="Disable Local GLiNER SLM semantic filter (enabled by default).",
    )
    parser.add_argument(
        "--force-ocr",
        action="store_true",
        help="Force Tesseract OCR on all PDF pages.",
    )
    return parser.parse_args()


def process_single_file(input_path: Path, output_path: Path, analyzer, entities, threshold, force_ocr, use_slm):
    logger.info(f"Processing PDF: {input_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats = redact_pdf(
        str(input_path),
        str(output_path),
        analyzer=analyzer,
        entities=entities,
        score_threshold=threshold,
        force_ocr=force_ocr,
        use_slm=use_slm,
    )

    print("\n" + "=" * 60)
    print(f"✅ REDACTION COMPLETE")
    print(f"📄 Input:  {stats['input_path']}")
    print(f"🔒 Output: {stats['output_path']}")
    print(f"📑 Pages Processed: {stats['total_pages']}")
    print(f"✂️  Total Redactions Applied: {stats['total_redactions']}")
    print("-" * 60)
    print("📊 Redactions per PII Entity Type:")
    if stats["entity_counts"]:
        for entity, count in sorted(stats["entity_counts"].items()):
            print(f"  • {entity:<24}: {count}")
    else:
        print("  (No PII detected matching current criteria)")
    print("=" * 60 + "\n")


def main():
    args = parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        logger.error(f"Input path does not exist: {input_path}")
        sys.exit(1)

    # Check OCR status
    ocr_ok, ocr_msg = is_ocr_available()
    logger.info(f"OCR Status: {ocr_msg}")

    use_slm = not args.no_slm

    # Build hybrid analyzer engine
    print(f"\n⏳ Initializing Presidio + Local GLiNER SLM Analyzer Engine (SLM Enabled: {use_slm})...")
    analyzer = build_indian_analyzer(spacy_model=args.model, enable_slm=use_slm)

    if input_path.is_file():
        if not input_path.suffix.lower() == ".pdf":
            logger.error("Input file must be a PDF document (.pdf).")
            sys.exit(1)

        if args.output:
            output_path = Path(args.output).resolve()
        else:
            output_path = input_path.parent / f"{input_path.stem}_redacted.pdf"

        process_single_file(input_path, output_path, analyzer, args.entities, args.threshold, args.force_ocr, use_slm)

    elif input_path.is_dir():
        pdf_files = list(input_path.glob("*.pdf")) + list(input_path.glob("*.PDF"))
        if not pdf_files:
            logger.warning(f"No PDF files found in directory: {input_path}")
            sys.exit(0)

        out_dir = Path(args.output).resolve() if args.output else input_path / "redacted_output"
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n📂 Found {len(pdf_files)} PDF files in directory. Processing batch...\n")
        for pdf_file in pdf_files:
            out_file = out_dir / f"{pdf_file.stem}_redacted.pdf"
            try:
                process_single_file(pdf_file, out_file, analyzer, args.entities, args.threshold, args.force_ocr, use_slm)
            except Exception as e:
                logger.error(f"Failed to process {pdf_file}: {e}")

    print("🎉 All operations completed successfully.")


if __name__ == "__main__":
    main()
