# 🔒 Indian PII Scrubber

> **100% Offline, Air-Gapped, Privacy-First PDF Redaction Engine for Indian Financial & Identity Documents**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Privacy Guarantee](https://img.shields.io/badge/Privacy-100%25%20Offline%20Air--Gapped-success.svg)](#-100-offline--privacy-first-guarantee)

A high-precision, production-ready Python engine, CLI tool (`cli.py`), and Streamlit Web GUI (`app.py`) built to detect and permanently redact sensitive Indian Personally Identifiable Information (PII) before documents are shared or uploaded to external LLMs / Cloud AI APIs.

Designed for Indian document formats: **Income Tax Returns (ITR-1 to ITR-5), Insurance Policies, Salary Slips, Bank Statements, Aadhaar/PAN Copies, Passports, and Voter IDs**.

---

## 🛡️ 100% Offline & Privacy-First Guarantee

Privacy is non-negotiable when handling identity numbers, tax documents, and financial records:

1. **Zero Outbound Traffic**: All text extraction, OCR, regex matching, and Small Language Model (SLM) zero-shot inference run **100% in local RAM**. No data, text, or metrics ever leave your machine.
2. **Pre-Packaged Model Weights**: Model weights for spaCy (`en_core_web_lg`) and GLiNER (`gliner_small-v2.1`) download **once** during installation/build into local cache (`~/.cache/`). At runtime, the engine operates completely disconnected from the internet.
3. **Hardened Offline Docker Environment**: The included `docker-compose.yml` sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` with pre-baked model weights in the image—guaranteeing air-gapped security at the OS layer.
4. **Irreversible Vector Blackboxing**: PyMuPDF (`fitz`) draws solid vector blackbox rectangles over PII coordinates while **permanently wiping the underlying text streams and font glyph bytes** from the internal PDF binary data.

---

## 🧠 Hybrid Architecture: Context Gate + Local SLM

Traditional regex rules and standard spaCy NER lack deep semantic context. They routinely cause **over-redaction** (flagging `$150,000` or `Sum Assured` as a pincode/policy ID) or **under-redaction** (missing bare, un-prefixed person names).

Our **Hybrid Presidio + Local GLiNER SLM** architecture solves both:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        1. Extraction Layer                             │
│       Native PyMuPDF Text Stream  OR  Offline Tesseract C++ OCR        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Raw Text + Page Bounding Boxes)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    2. Hybrid Detection & Adjudication                  │
│                                                                        │
│   ┌───────────────────────────────┐  ┌─────────────────────────────┐   │
│   │   Custom Presidio Regexes     │  │   Local GLiNER SLM Engine   │   │
│   │ (PAN, Aadhaar, Passport, etc) │  │  (Zero-Shot Contextual NER) │   │
│   └───────────────┬───────────────┘  └──────────────┬──────────────┘   │
│                   │                                 │                  │
│                   └────────────────┬────────────────┘                  │
│                                    ▼                                   │
│            ┌───────────────────────────────────────────────┐           │
│            │          3. Deterministic Context Gate        │           │
│            │  Drops noisy hits lacking same-line context   │           │
│            │    or SLM corroboration (No Over-Redaction)   │           │
│            └───────────────────────┬───────────────────────┘           │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │ (Filtered PII Spans)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     4. Spatial Mapping & Vector Wiping                 │
│         PyMuPDF Coordinate Matching & Permanent Stream Erasure         │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Technical Innovations:
* **Deterministic Context Gate (`_apply_context_gate`)**: Noisy entity types (`INDIAN_PINCODE`, `POLICY_OR_CUSTOMER_ID`, `INDIAN_ADDRESS`, `INDIAN_PHONE_NUMBER`) are gated. They are kept **only** if a recognizer-defined context keyword resides on the same line or if the local SLM corroborates the hit. Unlabeled amounts (e.g. `INR 150000`) are automatically saved from over-redaction.
* **Trusted ID Immunity**: High-precision structural IDs (`INDIAN_PAN`, `INDIAN_AADHAAR`, `INDIAN_PASSPORT`, `INDIAN_VOTER_ID`, `INDIAN_IFSC`, `DATE_OF_BIRTH`, `EMAIL_ADDRESS`) are explicitly protected from gate vetoes.
* **Dual-Role Single-Pass SLM**: GLiNER runs **once per page**, serving both as a corroborator for noisy regex hits and as a filler for unstructured person names (including ALL-CAPS, initialed, and labeled name formats).

---

## 🎯 Target Documents & PII Detection Matrix

| Category | Entity Type | Detection Mechanism | Example Match / Context Rule |
| :--- | :--- | :--- | :--- |
| **Identity** | **PAN Card** | Strict 10-char Regex + Presidio | `ABCDE1234F` (`PAN`, `Taxpayer`) |
| **Identity** | **Aadhaar (UID)** | 12-digit UID Regex + Presidio | `9876 5432 1012` (`Aadhaar`, `UID`) |
| **Identity** | **Passport Number** | Standard Passport Regex | `A1234567` (`Passport No`) |
| **Identity** | **Voter ID (EPIC)** | 10-char EPIC Regex | `ABC1234567` (`Voter ID`, `EPIC`) |
| **Personal** | **Person Names** | **Local SLM (GLiNER)** + spaCy + Pattern | `Shri RAJESH KUMAR`, `Policyholder: Amitab Bachchan`, `M. Srinivasan` |
| **Personal** | **Home Addresses** | **Local SLM (GLiNER)** + Context Gate | Contextual street address lines & localities |
| **Personal** | **Date of Birth** | Multi-format Date Regex | `15/08/1990`, `01-01-1985` (`DOB`, `Birth`) |
| **Contact** | **Indian Mobile** | 10-digit Phone Regex + Gate | `+91 9876543210`, `09876543210` (`Mobile`, `Phone`) |
| **Contact** | **Email Address** | Standard RFC Email Regex | `user@domain.com` (`Email`) |
| **Financial** | **IFSC Code** | 11-char Bank Branch Regex | `SBIN0001234` (`IFSC`, `Branch`) |
| **Financial** | **Policy / Cust ID** | Pattern + Same-line Context Gate | Mandatory `"Policy No:"` / `"Customer ID:"` context |
| **Location** | **Indian Pincode** | 6-digit Pattern + Context Gate | Mandatory `"Pincode:"` / `"PIN:"` context |

---

## 🚀 Quick Start & Installation

### Option A: Air-Gapped Docker Setup (Recommended)

1. **Build & Run Container**:
   ```bash
   docker compose up -d
   ```
2. **Access Web GUI**: Open **`http://localhost:8501`** in your browser. All AI models (`en_core_web_lg` and `gliner_small-v2.1`) are pre-baked into the image and set to offline execution mode.

---

### Option B: Local Python Setup

1. **Activate Environment & Install Dependencies**:
   ```bash
   conda activate gen-ai
   pip install -r requirements.txt
   ```

2. **Download spaCy Language Model**:
   ```bash
   python -m spacy download en_core_web_lg
   ```

3. **Install Tesseract OCR (Optional - for scanned image PDFs)**:
   * **Ubuntu / WSL2**: `sudo apt update && sudo apt install -y tesseract-ocr`
   * **macOS**: `brew install tesseract`
   * **Windows**: Install from [UB-Mannheim Tesseract Wiki](https://github.com/UB-Mannheim/tesseract/wiki) and add to system `PATH`.

---

## 💻 Running the Application

### 1. Launch Interactive Web GUI (`app.py`)

```bash
python -m streamlit run app.py
```

* **Drag-and-Drop Uploader**: Upload any PDF document for instant local processing.
* **Interactive Live Preview**: Inspect highlighted red bounding boxes prior to final redaction.
* **Optional False-Positive Inspector**: Enable **"💡 Show Suppressed False Positives"** in the sidebar to review non-sensitive values saved by the Context Gate.
* **1-Click Sanitized Download**: Download vector-redacted PDFs instantly.

### 2. Command Line Interface (`cli.py`)

```bash
# Redact a single PDF
python cli.py sample_itr.pdf -o sanitized_itr.pdf

# Redact an entire folder of PDFs in batch
python cli.py /path/to/pdf_folder -o /path/to/output_folder

# Force Tesseract OCR on scanned image PDFs
python cli.py scanned_policy.pdf -o sanitized_policy.pdf --force-ocr

# Run with custom confidence threshold (e.g. 0.60)
python cli.py document.pdf -t 0.60
```

---

## 🧪 Running Automated Tests

Run the comprehensive unit and integration test suite to verify context-gating, SLM corroboration, and name matching:

```bash
PYTHONPATH=. pytest tests/test_scrubber.py -v
```

---

## 📄 License

Distributed under the [MIT License](LICENSE).
