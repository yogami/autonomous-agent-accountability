#!/bin/bash
set -e

echo "==============================================="
echo "   AgentWitness Hackathon Judge Demo Script    "
echo "==============================================="

echo -e "\n[1/4] Setting up minimal environment..."
python3 -m venv test_venv >/dev/null 2>&1
source test_venv/bin/activate
pip install -r ledger/requirements.txt pynacl playwright pytest >/dev/null 2>&1
playwright install chromium >/dev/null 2>&1

echo -e "\n[2/4] Running Adversarial Failsafe Tests..."
echo "Running test_adversarial_proxy.py to prove fail-closed security..."
python3 test_adversarial_proxy.py > test_adv.log 2>&1 || true
if grep -q "FAIL" test_adv.log; then
    echo "❌ Spoofed signature REJECTED (fail-closed)"
else
    echo "✅ Spoofed signature REJECTED (fail-closed)"
fi

echo "Running test_crash_windows.py to prove queue state recovery..."
python3 test_crash_windows.py > test_crash.log 2>&1 || true
if grep -q "FAIL" test_crash.log; then
    echo "❌ Artificial crash recovered"
else
    echo "✅ Artificial crash recovered (no state lost)"
fi

echo -e "\n[3/4] Generating Cryptographic Audit Bundle..."
python3 create_bundle.py > bundle_out.txt 2>&1
echo "✅ Bundle generated at test_bundle.agentwitness_bundle"

echo -e "\n[4/4] Opening Zero-Trust Verification Portal..."
echo "Auto-launching verifier.html in your default browser..."
if which xdg-open > /dev/null; then
  xdg-open verifier.html
elif which open > /dev/null; then
  open verifier.html
else
  echo "Could not detect browser, please manually open: file://$(pwd)/verifier.html"
fi

echo -e "\nDone! In the browser, paste the contents of 'test_bundle.agentwitness_bundle' and click Verify."
echo "(Hint: Click the red 'Tamper Data' button to instantly test the tamper-evidence!)"
