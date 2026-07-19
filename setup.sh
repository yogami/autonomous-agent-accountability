#!/usr/bin/env bash

set -e

echo "========================================================="
echo " Autonomous Agent Accountability - Judge Setup Script"
echo "========================================================="
echo ""
echo "This script will install Python dependencies and compile the Rust daemon."
echo ""

# 1. Install python dependencies
echo "=> Installing python dependencies..."
pip3 install pynacl fastapi uvicorn requests cryptography > /dev/null 2>&1
echo "✅ Python dependencies installed."

# 2. Check for rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo (Rust) is not installed. Please install Rust via:"
    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# 3. Build the daemon
echo "=> Compiling the Rust Accountability Daemon (this may take a minute)..."
cd daemon
cargo build --release
cd ..
echo "✅ Daemon successfully compiled at 'daemon/target/release/autonomous-agent-accountability'."

echo ""
echo "========================================================="
echo "🎉 Setup Complete! You are ready to test the pipeline."
echo "========================================================="
echo "You can now run the testing suite:"
echo "1. python3 run_e2e_test.py                (End-to-end local test)"
echo "2. python3 test_adversarial_proxy.py      (Adversarial attack suite)"
echo "3. python3 test_crash_windows.py          (Power-loss recovery tests)"
echo "4. python3 prove_railway_persistence.py   (Live production tests against Railway)"
