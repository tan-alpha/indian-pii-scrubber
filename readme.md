# 🔒 Indian PII Scrubber

A 100% offline, privacy-first desktop application and engine to detect and visually redact Indian-specific Personally Identifiable Information (PII) from PDF documents.

Built to ensure sensitive documents (such as insurance policies, identity proofs, and financial statements) can be sanitized locally on your own machine before sharing or uploading to external web models.

---

## 🎯 Objective

Generic PII tools (or cloud APIs) often fail on Indian data formats, cost money, or require sending sensitive files to third-party servers. 

**Indian PII Scrubber** solves this by bundling rule matching, NLP entity detection, and PDF redaction into a single, offline execution pipeline with zero data residency risks.

---

## ✨ Target PII Entities

- **PAN Cards:** Standard 10-character alphanumeric formats (`[A-Z]{5}[0-9]{4}[A-Z]{1}`)
- **Aadhaar Numbers:** 12-digit structural regex matching
- **Indian Mobile Numbers:** Standard prefixes (`+91`, `0`, or direct `6-9` start digits)
- **Names & Emails:** Natural Language Processing (NLP) entity mapping via Microsoft Presidio & spaCy

---

## 🏗️ Architecture & Tech Stack

- **Presidio Analyzer:** Microsoft's open-source framework for offline rule matching and entity registry.
- **spaCy (`en_core_web_lg`):** Named Entity Recognition engine for local name and contextual detection.
- **PyMuPDF (`fitz`):** Layout-safe text extraction and coordinate-aware visual bounding-box redaction.
- **Tkinter:** Lightweight, native cross-platform GUI for file browsing and local saving.