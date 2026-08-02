# 100% Offline Air-Gapped Docker Container for Indian PII Scrubber
FROM python:3.10-slim

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies (Tesseract OCR, MuPDF / OpenGL libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download spaCy & GLiNER SLM model weights into Docker image at build time
RUN python -m spacy download en_core_web_lg
RUN python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_small-v2.1')"

# Copy application source code
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Run Streamlit Web GUI
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
