# Use a slim, production-grade Python runtime environment baseline
FROM python:3.11-slim

# Install low-level host OS system dependencies required for packet sniffing (libpcap) and firewall commands
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iptables \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory boundaries inside the container
WORKDIR /app

# Copy over the dependency manifests first to leverage Docker's layer caching
COPY requirements.txt .

# Install dependencies directly into the container filesystem
RUN pip install --no-cache-dir -r requirements.txt

# Copy the remaining software components into the container workspace
COPY . .

# Expose port 8501—the default networking port Streamlit binds onto
EXPOSE 8501

# Command statement to boot up your dashboard application interface upon container container initialization
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]