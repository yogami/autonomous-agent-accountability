# Stage 1: Build Rust Daemon
FROM rust:1.80-slim-bookworm as builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev
COPY daemon/ daemon/
RUN cd daemon && cargo build --release

# Stage 2: Python Environment
FROM python:3.10-slim-bookworm
WORKDIR /app

# Install required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy FastAPI app
COPY . .

# Copy compiled Rust daemon from builder
COPY --from=builder /app/daemon/target/release/autonomous-agent-accountability ./daemon_bin

# Create data directory for ledger
RUN mkdir -p /app/data
ENV LEDGER_DB_PATH=/app/data/ledger.db

# Command to run 
CMD ["sh", "-c", "python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
