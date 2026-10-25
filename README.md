# Indian PII Scrubber

> **100% Offline, Air-Gapped, Privacy-First PDF Redaction Engine for Indian Financial & Identity Documents**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/Tests-69%20Passed%20(100%25)-success.svg?style=flat-square&logo=pytest&logoColor=white)](#tests)
[![Docker](https://img.shields.io/badge/Docker-Ready%20Air--Gapped-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](#quickstart)
[![Streamlit](https://img.shields.io/badge/GUI-Streamlit-FF4B4B.svg?style=flat-square&logo=streamlit&logoColor=white)](#gui)
[![Air-Gapped Privacy](https://img.shields.io/badge/Privacy-100%25%20Offline-10B981.svg?style=flat-square&logo=shield&logoColor=white)](#privacy)

A high-precision, production-grade Python library, CLI utility, and Streamlit web application engineered to detect and permanently redact sensitive Indian Personally Identifiable Information (PII) before documents are shared, archived, or uploaded to Cloud AI models (such as ChatGPT, Claude, or Gemini).

Engineered specifically for Indian document layouts: **Income Tax Returns (ITR-1 to ITR-7), Form 16, Salary Slips, Bank Statements, Insurance Policies, Aadhaar/PAN cards, Passport scans (including MRZ), Driving Licenses, and Vehicle RC books**.

---

## Why This Tool?

When sharing financial documents with external AI tools or third-party vendors, redacting sensitive data is critical. Traditional redaction tools suffer from two major flaws:

1. **Under-Redaction (Leaking Secrets)**: Standard tools miss Indian names without honorifics, masked numbers (`XXXX-XXXX-1234`), landlines with STD codes, or embedded tax tokens (`ITRV-ABCDE1234F-2023`).
2. **Over-Redaction (Destroying Documents)**: Primitive keyword or regex tools flag a bank balance like `₹1,50,000` as a pincode, an invoice date like `31/12/2023` as a date of birth, or the phrase `BUILDING CODE compliance` as a home address.

**Indian PII Scrubber** solves both problems with a **Hybrid Engine**:
* **Deterministic Math Checksums**: Mathematical checks (like UIDAI's Verhoeff algorithm for Aadhaar and Luhn Mod-36 for GSTIN) confirm whether a number is genuine identity data or just an invoice reference.
* **Smart Context Gatekeeper**: Numbers are only redacted when accompanied by supporting context (e.g. `Pincode: 560001` is redacted, but an account balance of `150000` is kept intact).
* **Local Zero-Shot AI (GLiNER)**: A lightweight Small Language Model (SLM) running 100% locally in RAM detects bare names and addresses from sentence context without sending a single byte to the internet.

---

<a id="privacy"></a>
## 100% Offline & Air-Gapped Privacy Guarantee

Your data privacy is guaranteed at the hardware and networking level:

* **Zero Network Requests**: Once initial model weights are downloaded, all OCR, text parsing, regex matching, and AI inference execute strictly on your local CPU/GPU in RAM.
* **Pre-Baked Docker Image**: The Docker container sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` with all model weights pre-installed. You can disconnect your Wi-Fi entirely and the tool runs seamlessly.
* **Permanent Vector Erasure (Not a Black Box Sticker)**: In many basic viewers, black boxes are simply drawing layers placed over the text — meaning anyone can copy-paste the hidden text underneath. This engine uses PyMuPDF (`fitz`) to **permanently sanitize the binary text stream and font glyphs** underneath the black box. The data ceases to exist in the resulting PDF.

---

## Target Indian PII Matrix (19 Supported Types)

| Category | Entity Type | How It Works | Examples Handled |
| :--- | :--- | :--- | :--- |
| **Tax & ID** | **PAN Card** | 10-char regex + 4th-char CBDT status code validation | `ABCPE1234F`, `XXXXX1234F`, `*****1234F` |
| **Identity** | **Aadhaar (UID)** | 12-digit regex + **UIDAI Verhoeff (D5) checksum** | `9876 5432 1012`, `XXXX-XXXX-1234`, `9876.5432.1012` |
| **Identity** | **Passport Number** | Regular, diplomatic (`D`), and official (`S`) series | `A1234567`, `D12345678`, `S12345678` |
| **Identity** | **Passport MRZ** | ICAO Doc 9303 TD3 44-character 2-line parser & check digits | Bottom MRZ lines of passport scans (`P<IND...`) |
| **Identity** | **Voter ID (EPIC)** | Modern 10-char alphanumeric + legacy slash-delimited formats | `ABC1234567`, `ABC/12/345/678901` |
| **Identity** | **Driving License** | MoRTH Sarathi format + state RTO legacy formats | `DL-01-2010-1234567`, `MH12 20190001234` |
| **Personal** | **Person Names** | **Local SLM (GLiNER)** + spaCy NER + Indian honorifics | `Shri RAJESH KUMAR`, `Late Atal Bihari Vajpayee`, `Amitabh Bachchan` |
| **Personal** | **Home Addresses** | Local SLM + contextual address keywords & locality tokens | Flat/House numbers, Marg, Nagar, Sector, Enclave, Society |
| **Personal** | **Date of Birth** | Multi-format date regex + calendar plausibility + birth gate | `15/08/1990`, `15 Aug 1990` (Protects invoice dates) |
| **Contact** | **Phone / Landline** | Mobile (starts 6–9), STD landlines, and extension numbers | `+91 9876543210`, `(022) 2345 6789`, `ext 102` |
| **Contact** | **Email Address** | Standard RFC 5322 regex parser | `name@company.com`, `user.name+tag@domain.co.in` |
| **Banking** | **Bank Account** | 9–18 digit account numbers with banking context gating | `A/C No: 123456789012`, `Savings Account: 98765432101` |
| **Banking** | **Bank IFSC Code** | 11-character RBI bank branch identification code | `SBIN0001234`, `HDFC0000123` |
| **Taxation** | **ITR Acknowledgement** | 15-digit e-Filing tokens and embedded composite barcodes | `ITRV-ABCPE1234F-2023`, `Ack: 123456789012345/ABCPE1234F` |
| **Taxation** | **GSTIN (GST Number)** | 15-char GSTIN with **CBIC Luhn Mod-36 checksum** | `27AAPFU0939F1ZV`, `29AAACI4916L1ZH` |
| **Vehicle** | **Vehicle Registration** | State RTO number plates and Bharat Series (`BH`) | `MH 12 AB 1234`, `22 BH 1234 AA` |
| **Location** | **Indian Pincode** | 6-digit postal code with proximity context requirement | `Pincode: 560001` (Leaves amounts like `₹150000` safe) |
| **Insurance** | **Policy / Customer ID** | 8–16 digit identifier with strict proximity context gate | `Policy No: 123456789012` |

---

## Recommended Settings by Document Type

| Document Type | Recommended Confidence | Recommended Toggles | Why? |
| :--- | :---: | :--- | :--- |
| **Income Tax Return (ITR / Form 16)** | `0.50` (Default) | All enabled | Catches PAN, salary figures contextually, bank details, and ITR-V tokens. |
| **Bank Account Statements** | `0.55` | Enable `INDIAN_BANK_ACCOUNT`, `INDIAN_IFSC`, `PERSON` | Ensures balance amounts aren't touched while account numbers & IFSC are scrubbed. |
| **Salary Slips / Payslips** | `0.50` | Enable `INDIAN_PAN`, `PERSON`, `INDIAN_BANK_ACCOUNT` | Redacts employee name, bank account, and PAN while leaving salary components legible. |
| **Insurance Policies** | `0.50` | Enable `POLICY_OR_CUSTOMER_ID`, `PERSON`, `DATE_OF_BIRTH` | Protects customer ID and policyholder while keeping Sum Assured visible. |
| **KYC Identity Cards (Aadhaar / PAN)** | `0.45` | Enable `INDIAN_AADHAAR`, `INDIAN_PAN`, `DATE_OF_BIRTH` | Catches masked/unmasked numbers and DOB with mathematical checksum validation. |
| **Scanned Paper / Phone Camera PDFs** | `0.45` | Check `Force OCR on all pages` | Runs Tesseract OCR to extract text from images before running the redaction pipeline. |

---

<a id="quickstart"></a>
## Quick Start

### Option A: Docker (Recommended — Instant & 100% Air-Gapped)

The fastest and most isolated way to run the scrubber without worrying about system dependencies:

```bash
# 1. Clone repository
git clone https://github.com/tanalpha/indian-pii-scrubber.git
cd indian-pii-scrubber

# 2. Build and launch container
docker compose up -d

# 3. Open Web GUI in browser
# Navigate to: http://localhost:8501
```

---

### Option B: Local Python Installation

#### 1. Setup Virtual Environment
```bash
# Using Conda / Miniforge
conda create -n gen-ai python=3.10 -y
conda activate gen-ai

# Or using standard venv
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

#### 2. Install Dependencies & Pre-Download Models
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

#### 3. Install Tesseract OCR (Optional — only needed for scanned PDFs)
* **Ubuntu / Debian / WSL2**: `sudo apt update && sudo apt install -y tesseract-ocr tesseract-ocr-eng`
* **macOS**: `brew install tesseract`
* **Windows**: Download installer from [UB-Mannheim Tesseract Wiki](https://github.com/UB-Mannheim/tesseract/wiki) and add to system `PATH`.

---

## How to Use

<a id="gui"></a>
### 1. Interactive Web Application (`app.py`)

Launch the Streamlit web interface:

```bash
streamlit run app.py
```

* **Step 1: Upload Document**: Drag and drop any Indian PDF file.
* **Step 2: Live Visual Preview**: Inspect red highlight overlays indicating detected PII boundaries before committing.
* **Step 3: 1-Click Redact & Download**: Click "Redact & Generate Sanitized PDF" to download a permanently scrubbed document.
* **Developer & Diagnostics Expander**: Tucked in the sidebar to review system readiness, tweak thresholds, or inspect false positives saved by the Context Gate.

---

### 2. Command Line Interface (`cli.py`)

Batch process files or integrate directly into automated backend pipelines:

```bash
# Redact a single PDF (outputs to <name>_redacted.pdf)
python cli.py sample_itr.pdf -o sanitized_itr.pdf

# Redact an entire folder of PDFs in batch
python cli.py ./raw_invoices/ -o ./sanitized_invoices/

# Force OCR on low-quality scanned documents
python cli.py scanned_document.pdf --force-ocr

# Adjust confidence threshold (e.g. strict 0.60)
python cli.py statement.pdf -t 0.60

# Select specific entity types to redact
python cli.py salary_slip.pdf -e INDIAN_PAN PERSON INDIAN_BANK_ACCOUNT
```

---

<a id="tests"></a>
## Automated Testing

The codebase includes an extensive automated test suite covering checksum algorithms, proximity context gates, multi-line headers, and edge-case protection:

```bash
PYTHONPATH=. pytest tests/ -v
```

```text
======================== 69 passed, 1 warning in 23.96s ========================
```

---

## Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        1. Document Ingestion                           │
│       Native PyMuPDF Text Stream   OR   Offline Tesseract C++ OCR      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Character Coordinates + Spans)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    2. Hybrid Detection Pipeline                        │
│                                                                        │
│   ┌───────────────────────────────┐  ┌─────────────────────────────┐   │
│   │   Custom Presidio Recognizers │  │   Local GLiNER SLM Engine   │   │
│   │  (PAN, Aadhaar, Passport, DL) │  │ (Zero-Shot Contextual NER)  │   │
│   └───────────────┬───────────────┘  └──────────────┬──────────────┘   │
│                   │                                 │                  │
│                   └────────────────┬────────────────┘                  │
│                                    ▼                                   │
│            ┌───────────────────────────────────────────────┐           │
│            │          3. Mathematical Validators           │           │
│            │   Verhoeff (D5), PAN Status, GSTIN Mod-36,    │           │
│            │   ICAO 9303 MRZ, DOB Calendar Plausibility    │           │
│            └───────────────────────┬───────────────────────┘           │
│                                    ▼                                   │
│            ┌───────────────────────────────────────────────┐           │
│            │     4. Proximity Context Gate (±1 Line)       │           │
│            │   Suppresses uncontextualized noise & saves   │           │
│            │   amounts / dates from over-redaction         │           │
│            └───────────────────────┬───────────────────────┘           │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │ (Sanitized Bounding Box Spans)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     5. Binary Vector Redaction                         │
│         PyMuPDF Coordinate Matching & Permanent Stream Erasure         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Limitations & Planned Enhancements

While Indian PII Scrubber provides deterministic math validation and local SLM inference for standard Indian financial and identity documents, the following limitations are identified for future enhancements:

1. **Non-Latin Indic Scripts**:
   * *Limitation*: Regex patterns and the local GLiNER model are trained on Latin-script text. Documents printed entirely in regional Indian scripts (such as Devanagari, Tamil, Telugu, Bengali, Kannada, or Marathi) are not currently parsed.
   * *Enhancement*: Integrate multilingual Indic NER models and regional language Tesseract OCR language packs (`hin`, `tam`, `tel`, etc.).

2. **Handwritten Content & Signatures**:
   * *Limitation*: Detection is optimized for printed, digital, and OCR-extracted typography. Handwritten text in physical application forms and handwritten signatures on cheques or certificates are not consistently detected.
   * *Enhancement*: Incorporate handwritten text recognition (HTR) and vision-based signature segmentation and masking.

3. **Non-PDF Document Ingestion**:
   * *Limitation*: The redaction pipeline operates exclusively on PDF files. Standalone image formats (`.jpg`, `.png`, `.tiff`) and office documents (`.docx`, `.xlsx`) must be converted to PDF before processing.
   * *Enhancement*: Add direct image file ingestion and vector sanitization for spreadsheets and document formats.

4. **Pseudonymization & Synthetic Data Replacement**:
   * *Limitation*: Detected entities are permanently wiped using solid vector blackboxes. The engine does not currently support reversible tokenization or synthetic pseudonym replacement (e.g., swapping real names/PANs with valid synthetic dummy equivalents).
   * *Enhancement*: Implement format-preserving synthetic entity substitution for machine learning datasets and LLM fine-tuning pipelines.

5. **Throughput on Large Documents**:
   * *Limitation*: Running local SLM token classification across 100+ page documents on CPU-only machines introduces processing latency.
   * *Enhancement*: Introduce batched GPU inference, ONNX runtime acceleration, and page-level parallel worker pools.

6. **Declarative Rule Configuration**:
   * *Limitation*: Adding custom entity recognizers or modifying context proximity rules currently requires editing Python source files.
   * *Enhancement*: Support external YAML/JSON configuration files and GUI rule-builders for organization-specific PII schemas.

---

## Contributing

Contributions from the community are warmly welcomed! Whether you want to add support for new regional document formats, refine context keywords, or optimize OCR performance:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'feat: Add support for X'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

Distributed under the [MIT License](LICENSE). Free for academic, personal, and commercial use.
