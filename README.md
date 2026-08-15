# 🔒 Indian PII Scrubber

> **100% Offline, Air-Gapped, Privacy-First PDF Redaction Engine for Indian Financial & Identity Documents**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Privacy Guarantee](https://img.shields.io/badge/Privacy-100%25%20Offline%20Air--Gapped-success.svg)](#-100-offline--privacy-first-guarantee)
[![Tests](https://img.shields.io/badge/Tests-69%20Passed%20(100%25)-brightgreen.svg)](#-running-automated-tests)
[![Version](https://img.shields.io/badge/Version-v0.3.0%20(Community%20Audit%20Release)-purple.svg)](#-whats-new-in-v030-community-audit-release)

A high-precision, production-ready Python engine, CLI tool (`cli.py`), and Streamlit Web GUI (`app.py`) built to detect and permanently redact sensitive Indian Personally Identifiable Information (PII) before documents are shared or uploaded to external LLMs / Cloud AI APIs.

Designed for Indian document formats: **Income Tax Returns (ITR-1 to ITR-7), Form 16, Insurance Policies, Salary Slips, Bank Statements, Aadhaar/PAN Copies, Passports (including MRZ), Driving Licenses, Vehicle RC Books, and Voter IDs**.

---

## ✨ What's New in v0.3.0 (Community Audit Release)

Following a comprehensive community audit of Indian PII recognition patterns, **v0.3.0** brings major architectural improvements, mathematical checksum validators, multi-line form support, and new recognizers:

### 🛡️ 1. Deterministic Mathematical Validators (`validators.py`)
* **Verhoeff Checksum Engine for Aadhaar**: Implements the dihedral group $D_5$ algorithm defined by UIDAI. Validates 12-digit Aadhaar numbers mathematically and eliminates false positives on random invoice/transaction numbers.
* **PAN 4th-Character Entity Status Validation**: Strictly verifies entity status codes (`[P, C, H, F, A, T, B, L, J, G, K]`), 5th-character alphabet, and masked formats (`XXXXX1234F`).
* **GSTIN Luhn Mod-36 Checksum**: Verifies the 15-character Goods & Services Tax ID, state codes (01–38), embedded PAN, and Mod-36 check digits.
* **Passport MRZ Parser (ICAO Doc 9303)**: Validates 44-character 2-line machine-readable zones with 7-3-1 weight cycling.
* **DOB Calendar Plausibility**: Validates leap years, Gregorian calendars, and eliminates future/implausible dates.
* **MoRTH State/UT Code Validator**: Validates all 28 states, 8 union territories, and `BH` (Bharat Series).

### 🎯 2. New Document Recognizers & Embedded String Extraction
* **`INDIAN_PASSPORT_MRZ`**: Redacts and parses 44-character MRZ lines at the bottom of passport scans.
* **`ITR_ACKNOWLEDGEMENT_NUMBER` & Embedded PAN**: Extracts embedded PANs and 15-digit e-Filing tokens from barcodes/tokens (`ITRV-ABCDE1234F-2023`, `Ack: 123456789012345/ABCDE1234F`).
* **`INDIAN_DRIVING_LICENSE`**: Supports MoRTH Sarathi format (`SS-RR-YYYYNNNNNNN`) and legacy state formats.
* **`INDIAN_GSTIN`**: 15-character GST registration with Mod-36 checksum.
* **`INDIAN_VEHICLE_REGISTRATION`**: State RTO number plates and Bharat Series (`22 BH 1234 AA`).
* **`INDIAN_BANK_ACCOUNT`**: Dedicated 9–18 digit account numbers with banking context.
* **`INDIAN_VOTER_ID`**: Modern EPIC + legacy slash-delimited EPIC formats (`ABC/12/345/678901`).
* **Masked Formats & Landlines**: Supports masked Aadhaar (`XXXX-XXXX-1234`, `•••• •••• 1234`), dot-separated Aadhaar (`9876.5432.1012`), and STD landlines (`(022) 2345 6789`).

### 📑 3. Multi-Line & Form-Aware Context Gate
* **Preceding Line Headers**: Handles label-on-line-1, value-on-line-2 layouts (`Pincode:\n560001`, `DOB:\n15/08/1990`).
* **Over-Redaction Elimination**: Moved `DATE_OF_BIRTH` to gated types to protect regular invoice dates, transaction dates, and maturity dates from accidental masking.

### 🧼 4. Frictionless UI with Developer & Diagnostics Mode
* **Clean 3-Step Main Flow**: Simple **Upload $\rightarrow$ Visual Preview $\rightarrow$ 1-Click Redact** workflow.
* **Collapsible Diagnostics Expander**: Threshold sliders, system health checks, and 19 fine-grained entity toggles organized inside a `🛠️ Developer & Diagnostics Mode` sidebar expander.

### 🧪 5. Comprehensive Automated Test Suite
* Expanded test suite from 13 to **69 automated unit & integration tests** covering all edge cases, over-masking regressions, and mathematical validators.

---

## 🛡️ 100% Offline & Privacy-First Guarantee

Privacy is non-negotiable when handling identity numbers, tax documents, and financial records:

1. **Zero Outbound Traffic**: All text extraction, OCR, regex matching, and Small Language Model (SLM) zero-shot inference run **100% in local RAM**. No data, text, or metrics ever leave your machine.
2. **Pre-Packaged Model Weights**: Model weights for spaCy (`en_core_web_lg`) and GLiNER (`gliner_small-v2.1`) download **once** during installation/build into local cache (`~/.cache/`). At runtime, the engine operates completely disconnected from the internet.
3. **Hardened Offline Docker Environment**: The included `docker-compose.yml` sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` with pre-baked model weights in the image—guaranteeing air-gapped security at the OS layer.
4. **Irreversible Vector Blackboxing**: PyMuPDF (`fitz`) draws solid vector blackbox rectangles over PII coordinates while **permanently wiping the underlying text streams and font glyph bytes** from the internal PDF binary data.

---

## 🧠 Hybrid Architecture: Context Gate + Local SLM

Traditional regex rules and standard spaCy NER lack deep semantic context. They routinely cause **over-redaction** (flagging `$150,000` or `Sum Assured` as a pincode/policy ID) or **under-redaction** (missing bare, un-prefixed person names or embedded strings).

Our **Hybrid Presidio + Local GLiNER SLM + Mathematical Validation** architecture solves both:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        1. Extraction Layer                             │
│       Native PyMuPDF Text Stream  OR  Offline Tesseract C++ OCR        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Raw Text + Page Bounding Boxes)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    2. Hybrid Detection & Validation                    │
│                                                                        │
│   ┌───────────────────────────────┐  ┌─────────────────────────────┐   │
│   │   Custom Presidio Regexes     │  │   Local GLiNER SLM Engine   │   │
│   │ (PAN, Aadhaar, Passport, etc) │  │  (Zero-Shot Contextual NER) │   │
│   └───────────────┬───────────────┘  └──────────────┬──────────────┘   │
│                   │                                 │                  │
│                   └────────────────┬────────────────┘                  │
│                                    ▼                                   │
│            ┌───────────────────────────────────────────────┐           │
│            │          3. Mathematical Validators           │           │
│            │  Verhoeff, PAN Status, GSTIN Mod-36, MRZ      │           │
│            └───────────────────────┬───────────────────────┘           │
│                                    ▼                                   │
│            ┌───────────────────────────────────────────────┐           │
│            │       4. Multi-Line Context Gate (±1 Line)    │           │
│            │  Drops noisy hits lacking context or SLM      │           │
│            │    corroboration (No Over-Redaction)          │           │
│            └───────────────────────┬───────────────────────┘           │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │ (Filtered PII Spans)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     5. Spatial Mapping & Vector Wiping                 │
│         PyMuPDF Coordinate Matching & Permanent Stream Erasure         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Target Documents & PII Detection Matrix

| Category | Entity Type | Detection Mechanism | Example Match / Context Rule |
| :--- | :--- | :--- | :--- |
| **Identity** | **PAN Card** | 10-char Regex + Status Validation | `ABCPE1234F`, `XXXXX1234F` (`PAN`, `Taxpayer`) |
| **Identity** | **Aadhaar (UID)** | 12-digit UID + **Verhoeff Checksum** | `9876 5432 1012`, `XXXX-XXXX-1234`, `9876.5432.1012` |
| **Identity** | **Passport Number** | Regular, Diplomatic, Official Regex | `A1234567`, `D12345678` (`Passport No`) |
| **Identity** | **Passport MRZ** | ICAO 9303 2-Line 44-char Parser | `P<INDKUMAR<<RAJESH...`, `A1234567<8IND9008154...` |
| **Identity** | **Voter ID (EPIC)** | Modern (10-char) + Legacy Regex | `ABC1234567`, `ABC/12/345/678901` (`Voter ID`) |
| **Identity** | **Driving License** | MoRTH Sarathi + Legacy State Regex | `DL-01-2010-1234567`, `MH12 20190001234` |
| **Personal** | **Person Names** | **Local SLM (GLiNER)** + spaCy NER | `Shri RAJESH KUMAR`, `Late Atal Bihari Vajpayee`, `M. Srinivasan` |
| **Personal** | **Home Addresses** | **Local SLM (GLiNER)** + Context Gate | Contextual street address lines & localities |
| **Personal** | **Date of Birth** | Multi-format Date + Calendar Check | `15/08/1990`, `15 Aug 1990` (Strictly context-gated) |
| **Contact** | **Phone / Landline** | Mobile (10-digit) + Landline STD + Ext | `+91 9876543210`, `(022) 2345 6789`, `ext 102` |
| **Contact** | **Email Address** | Standard RFC Email Regex | `user@domain.com` (`Email`) |
| **Financial** | **Bank Account** | 9–18 digit Pattern + Context Gate | `A/C No: 123456789012` (`Account Number`, `SB A/C`) |
| **Financial** | **IFSC Code** | 11-char Bank Branch Regex | `SBIN0001234` (`IFSC`, `Branch`) |
| **Financial** | **ITR Acknowledgement** | 15-digit Ack + Composite Tokens | `ITRV-ABCPE1234F-2023`, `Ack: 123456789012345/ABCPE1234F` |
| **Financial** | **Policy / Cust ID** | Pattern + Proximity Context Gate | Mandatory `"Policy No:"` / `"Customer ID:"` context |
| **Commercial** | **GSTIN / Tax ID** | 15-char Pattern + **Mod-36 Checksum** | `27AAECC5491G1Z4` (`GSTIN`, `GST No`) |
| **Transport** | **Vehicle Registration** | State RTO + Bharat Series (`BH`) | `MH 12 AB 1234`, `22 BH 1234 AA` (`RC No`, `Vehicle`) |
| **Location** | **Indian Pincode** | 6-digit Pattern + Proximity Gate | Mandatory `"Pincode:"` / `"PIN:"` context (`560001`) |

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

* **Clean 3-Step Experience**: Upload PDF $\rightarrow$ Inspect live visual red highlight boxes $\rightarrow$ 1-Click Redact & Download.
* **Developer & Diagnostics Mode**: Expand the sidebar drawer to inspect system diagnostics (spaCy, GLiNER, Tesseract), tweak confidence sliders, toggle granular entities, or view suppressed false positives.

### 2. Command Line Interface (`cli.py`)

```bash
# Redact a single PDF (all 19 standard Indian PII types enabled by default)
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

Run the comprehensive unit and integration test suite (69 tests) to verify checksum validators, context-gating, SLM corroboration, and edge-case protection:

```bash
PYTHONPATH=. pytest tests/test_scrubber.py -v
```

---

## 📄 License

Distributed under the [MIT License](LICENSE).
