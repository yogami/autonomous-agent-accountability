# Stage 1: Build Rust Daemon
FROM rust:1.80-slim-bookworm as builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev
# We use the original daemon directory in the root
COPY daemon/ daemon/
RUN cd daemon && cargo build

# Stage 2: Python Environment
FROM python:3.10-slim-bookworm
WORKDIR /app

# Install required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all code
COPY . .

# Copy compiled Rust daemon from builder into ledger directory
COPY --from=builder /app/daemon/target/debug/autonomous-agent-accountability ./ledger/daemon_bin

# Create data directory for ledger
RUN mkdir -p /app/data
ENV LEDGER_DB_PATH=/app/data/ledger.db

# Command to run (run from inside ledger folder so relative static files work)
WORKDIR /app/ledger
CMD ["sh", "-c", "python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
