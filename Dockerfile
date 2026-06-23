FROM python:3.11-slim

LABEL maintainer="CyberGuard IDS v3"
LABEL description="AI-powered Intrusion Detection System"

# System deps for Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Create directories
RUN mkdir -p dataset logs pcap_exports backend/models

EXPOSE 5000

# Need NET_ADMIN for iptables, NET_RAW for packet capture
CMD ["python3", "backend/app.py"]
