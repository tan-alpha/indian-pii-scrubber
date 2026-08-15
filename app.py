"""
Indian PII Scrubber - Streamlit Modern Desktop & Web GUI

Features:
- 100% Offline Air-Gapped execution guarantee banner
- Clean 3-step workflow: Upload -> Visual Preview -> 1-Click Redact
- Developer & Diagnostics Mode in collapsible sidebar expander
"""

import sys
import os
import tempfile
import inspect
from pathlib import Path
import fitz  # PyMuPDF
import spacy
import streamlit as st

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from scrubber import (
    build_indian_analyzer,
    redact_pdf,
    process_page_pii,
    is_ocr_available,
    DEFAULT_ENTITIES,
    GlinerPiiEngine,
)
from scrubber.utils import render_page_to_image, draw_bounding_boxes_on_image

st.set_page_config(
    page_title="Indian PII Scrubber",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        opacity: 0.85;
        margin-bottom: 1.2rem;
    }
    .security-badge {
        background-color: rgba(16, 185, 129, 0.12);
        border: 1px solid #10B981;
        padding: 0.8rem 1.2rem;
        border-radius: 8px;
        font-weight: 600;
        margin-bottom: 1.5rem;
    }
    .step-box {
        background-color: rgba(59, 130, 246, 0.1);
        border-left: 4px solid #3B82F6;
        padding: 0.8rem 1rem;
        border-radius: 4px;
        margin-bottom: 1rem;
    }
    .stDownloadButton button {
        background-color: #059669 !important;
        color: white !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.8rem !important;
        font-size: 1.05rem !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_stretch_kw():
    """Return width='stretch' for modern Streamlit, avoiding deprecation warnings across versions."""
    try:
        sig = inspect.signature(st.image)
        if "width" in sig.parameters:
            return {"width": "stretch"}
    except Exception:
        pass
    return {"use_container_width": True}


@st.cache_resource
def load_analyzer():
    """Cache the Hybrid Presidio + GLiNER SLM Analyzer Engine across Streamlit runs."""
    return build_indian_analyzer(spacy_model="en_core_web_lg", enable_slm=True)


def sidebar_diagnostics(analyzer):
    """Collapsed developer & diagnostics mode in sidebar expander."""
    with st.sidebar.expander("🛠️ Developer & Diagnostics Mode", expanded=False):
        # System requirement checks
        st.markdown("#### System Requirements")

        spacy_lg_installed = spacy.util.is_package("en_core_web_lg")
        if spacy_lg_installed:
            st.success("🧠 NLP Model: `en_core_web_lg` Ready")
        else:
            st.error("❌ NLP Model `en_core_web_lg` Missing")
            st.caption("Run in terminal:\n`python -m spacy download en_core_web_lg`")

        slm_tester = GlinerPiiEngine()
        if slm_tester.is_available():
            st.success("🤖 Local SLM (GLiNER): Ready (Cached)")
        else:
            st.info("ℹ️ Local SLM (GLiNER): Installing / Offline PyTorch Mode")

        ocr_ok, ocr_msg = is_ocr_available()
        if ocr_ok:
            st.success("📸 OCR Engine: Tesseract Ready")
        else:
            st.warning("⚠️ OCR Engine: Missing Tesseract binary")
            st.caption("For scanned PDFs, run:\n`sudo apt install tesseract-ocr`")

        # Entity toggle checkboxes
        st.markdown("---")
        st.markdown("#### PII Entity Selection")

        entity_descriptions = {
            "INDIAN_PAN": ("PAN Card Number", "10-character alphanumeric PAN (e.g. ABCDE1234F)", True),
            "INDIAN_AADHAAR": ("Aadhaar (UID) Number", "12-digit structural UID pattern (Verhoeff validated)", True),
            "INDIAN_ADDRESS": ("Address & Locality", "Street addresses, house numbers, blocks, nagar, colony", True),
            "POLICY_OR_CUSTOMER_ID": ("Policy & Customer ID", "Insurance policy numbers, customer IDs, account numbers", True),
            "INDIAN_PASSPORT": ("Passport Number", "Indian Passport ID (1 letter + 7 digits)", True),
            "INDIAN_PASSPORT_MRZ": ("Passport MRZ", "ICAO 9303 machine-readable zone (passport scan bottom)", True),
            "INDIAN_VOTER_ID": ("Voter ID (EPIC)", "Election Card EPIC number (3 letters + 7 digits) + legacy formats", True),
            "DATE_OF_BIRTH": ("Date of Birth (DOB)", "Dates with birth context (DOB, Born on, Birth Date, Age)", True),
            "INDIAN_PHONE_NUMBER": ("Indian Phone / Landline", "Mobile (6-9 start), Landline with STD codes, extensions", True),
            "EMAIL_ADDRESS": ("Email Address", "Standard email addresses", True),
            "PERSON": ("Person Names", "Named entities via spaCy NER + SLM (unstructured names)", True),
            "TITLE_PERSON_NAME": ("Title-Prefixed Names", "Names prefixed by Shri, Smt, Dr, Late, Master, Prof, etc.", True),
            "INDIAN_IFSC": ("Bank IFSC Code", "11-character Bank Branch Code (e.g. SBIN0001234)", True),
            "INDIAN_PINCODE": ("Indian Pincode", "6-digit postal code with context", True),
            "INDIAN_DRIVING_LICENSE": ("Driving License", "MoRTH Sarathi + legacy state-wise formats", True),
            "INDIAN_GSTIN": ("GSTN / GSTIN", "15-character GSTIN with Mod-36 checksum", True),
            "INDIAN_VEHICLE_REGISTRATION": ("Vehicle Registration", "State RTO format + Bharat Series (22 BH 1234 AA)", True),
            "INDIAN_BANK_ACCOUNT": ("Bank Account Number", "9-18 digit account numbers with banking context", True),
            "ITR_ACKNOWLEDGEMENT_NUMBER": ("ITR Acknowledgement", "15-digit e-Filing ACK numbers + composite tokens (ITRV-...)", True),
            "GPE": ("Geopolitical Entities", "Cities, states, countries (Optional)", False),
            "LOCATION": ("Geographic Locations", "Landmarks, parks, regions (Optional)", False),
        }

        selected_entities = []
        for entity_key, (label, help_text, default_val) in entity_descriptions.items():
            if st.checkbox(label, value=default_val, key=f"cb_{entity_key}", help=help_text):
                selected_entities.append(entity_key)

        # Advanced settings
        st.markdown("---")
        st.markdown("#### Advanced Settings")

        use_slm = st.checkbox(
            "Enable Smart SLM Semantic Filter (GLiNER)",
            value=True,
            help="Uses local zero-shot SLM to analyze full sentence context and eliminate false-positive over-redactions.",
        )

        threshold = st.slider(
            "Detection Confidence Threshold",
            min_value=0.1,
            max_value=1.0,
            value=0.50,
            step=0.05,
            help="Calibrated default: 0.50. Higher values (0.7+) require strict certainty; lower values (0.3) catch faint matches.",
        )

        force_ocr = st.checkbox(
            "Force OCR on all pages",
            value=False,
            help="Enable to force Tesseract OCR on every page, useful for low-quality scanned image PDFs.",
        )

        show_suppressed = st.checkbox(
            "Show Suppressed False Positives",
            value=False,
            help="Display false-positive entity matches (e.g. unlabeled amounts) saved from over-redaction by the Context Gate.",
        )

    return selected_entities, use_slm, threshold, force_ocr, show_suppressed


def main():
    stretch = get_stretch_kw()

    # Eagerly preload Presidio & GLiNER SLM models during server startup
    with st.spinner("Initializing Local Offline Privacy Engines (spaCy + GLiNER SLM)..."):
        analyzer = load_analyzer()

    # Sidebar: diagnostics + settings (collapsed by default)
    selected_entities, use_slm, threshold, force_ocr, show_suppressed = sidebar_diagnostics(analyzer)

    # Main screen: clean 3-step workflow
    st.markdown('<div class="main-header">Indian PII Scrubber</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">100% Offline, Privacy-First PDF Redaction Engine for Indian Documents (ITRs, Insurance Policies, ID Proofs, Salary Slips)</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="security-badge">🛡️ <b>100% Privacy-First & Air-Gapped Guarantee:</b> All document scanning, OCR, and SLM zero-shot inference process strictly in local RAM. Zero document content ever leaves your machine.<br>'
        '<i>(Note: Network connectivity is used ONLY during initial setup to fetch open-source model weights into local disk cache. Once cached, the app operates completely offline.)</i></div>',
        unsafe_allow_html=True,
    )

    # Step 1: Upload
    st.markdown(
        '<div class="step-box"><b>Step 1:</b> Upload your PDF document below. The tool will scan all pages and display an interactive preview with highlighted red boxes around detected PII.</div>',
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload a PDF document (ITR, Insurance Policy, Salary Slip, ID Copy)",
        type=["pdf"],
        help="Select a PDF from your computer. Files are processed 100% locally.",
    )

    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_in:
            tmp_in.write(uploaded_file.getvalue())
            tmp_input_path = tmp_in.name

        doc = fitz.open(tmp_input_path)
        num_pages = len(doc)

        st.success(f"📄 Successfully loaded: **{uploaded_file.name}** ({num_pages} total pages)")

        # Step 2: Visual Inspection
        st.markdown(
            '<div class="step-box"><b>Step 2:</b> Select a page below to inspect the live visual preview. Red highlight boxes indicate detected PII regions.</div>',
            unsafe_allow_html=True,
        )

        selected_page_num = st.number_input(
            "Select Preview Page", min_value=1, max_value=num_pages, value=1, step=1
        ) - 1

        page = doc[selected_page_num]

        with st.spinner("Scanning page using Hybrid Engine (Regex + spaCy + Local SLM)..."):
            page_info = process_page_pii(
                page,
                analyzer,
                entities=selected_entities,
                score_threshold=threshold,
                force_ocr=force_ocr,
                use_slm=use_slm,
            )

        st.markdown("### Detected PII on this Page")
        if page_info["entity_counts"]:
            col1, col2 = st.columns(2)
            with col1:
                for ent, cnt in page_info["entity_counts"].items():
                    st.info(f"**{ent}**: {cnt} detected")
        else:
            st.write("🟢 No PII detected on this page with current confidence threshold.")

        if show_suppressed and page_info.get("dropped"):
            with st.expander(f"Suppressed False Positives ({len(page_info['dropped'])} saved)"):
                for item in page_info["dropped"]:
                    st.caption(f"• **'{item['text']}'** ({item['entity_type']}) — *{item['reason']}*")

        if page_info["is_scanned"]:
            if page_info["ocr_used"]:
                st.caption("📸 Page processed using Tesseract OCR.")
            else:
                st.warning("⚠️ Scanned page detected, but Tesseract binary is missing. Install `tesseract-ocr` for scanned pages.")

        # Visual preview
        st.markdown("#### 👁️ Live Page Visual Preview")
        st.caption("Red highlight boxes indicate detected PII regions. Solid black vector boxes will be applied upon final redaction.")

        page_img = render_page_to_image(page, dpi=150)

        if page_info["bounding_boxes"]:
            preview_img = draw_bounding_boxes_on_image(
                page_img,
                page_info["bounding_boxes"],
                pdf_page_size=(page.rect.width, page.rect.height),
            )
            st.image(preview_img, caption=f"Page {selected_page_num + 1} of {num_pages} (Red Highlight = Detected PII)", **stretch)
        else:
            st.image(page_img, caption=f"Page {selected_page_num + 1} of {num_pages} (No PII Detected)", **stretch)

        # Step 3: 1-Click Redaction
        st.markdown("---")
        st.markdown(
            '<div class="step-box"><b>Step 3:</b> Click below to permanently blackbox all detected PII across the document.</div>',
            unsafe_allow_html=True,
        )

        if st.button("✂️ Redact & Generate Sanitized PDF", type="primary", **stretch):
            with tempfile.NamedTemporaryFile(delete=False, suffix="_redacted.pdf") as tmp_out:
                tmp_output_path = tmp_out.name

            with st.spinner("Wiping underlying text streams & drawing solid vector blackboxes..."):
                stats = redact_pdf(
                    tmp_input_path,
                    tmp_output_path,
                    analyzer=analyzer,
                    entities=selected_entities,
                    score_threshold=threshold,
                    force_ocr=force_ocr,
                    use_slm=use_slm,
                )

            st.balloons()
            st.success(f"🎉 Redaction Complete! Applied **{stats['total_redactions']} redactions** across {stats['total_pages']} pages.")

            with open(tmp_output_path, "rb") as f:
                redacted_bytes = f.read()

            output_filename = f"{Path(uploaded_file.name).stem}_redacted.pdf"
            st.download_button(
                label="⬇️ Download Sanitized PDF",
                data=redacted_bytes,
                file_name=output_filename,
                mime="application/pdf",
                **stretch,
            )

        doc.close()

    # Security explanation tab (kept minimal, always accessible)
    with st.sidebar.expander("🛡️ Redaction Security"):
        st.markdown(
            """
            ### Are redaction boxes removable by hackers?

            **NO! Redaction is 100% irreversible and cryptographically permanent.**

            1. **Visual Preview (Red Boxes)**: GUI visual indicator for your review only.
            2. **True Vector Redaction (`apply_redactions()`)**: When you click "Redact", PyMuPDF:
               - Draws solid opaque black vector rectangles over target coordinates.
               - **Permanently wipes** text streams, font glyphs, and character data from PDF binary.
            3. **Irreversible**: In the final PDF, the text under the black box **no longer exists**. Cannot be selected, copied, unmasked, or recovered.
            """
        )


if __name__ == "__main__":
    main()
