# Use Python 3 (yarGen v0.23+ supports Python 3)
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Clone the repository
WORKDIR /app
RUN git clone https://github.com/Neo23x0/yarGen.git .


# Install Python requirements
RUN pip install --no-cache-dir -r requirements.txt

# Create directories for databases and malware
RUN mkdir -p /app/dbs /app/malware /app/output /app/clean_wasm_files
COPY wasm /app/clean_wasm_files
# Run the update to pull the goodware databases (Caution: ~1GB+ download)
# Note: You might prefer to do this as a separate step or via volume
RUN python yarGen.py --update
RUN python yarGen.py -c -i wasm_clean -g /app/clean_wasm_files

ENTRYPOINT ["python", "yarGen.py"]