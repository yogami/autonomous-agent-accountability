import asyncio
import os
from playwright.async_api import async_playwright
import pytest

@pytest.mark.asyncio
async def test_verify_portal_substance():
    """
    Substance test: Spins up a real Chromium browser, loads the portal,
    pastes a mock payload, and tests the client-side cryptographic verification.
    """
    # Use localhost if testing locally, or fall back to the Railway URL if deployed.
    url = os.environ.get("PRODUCTION_URL", f"file://{os.path.abspath('verifier.html')}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Navigate to the portal
        await page.goto(url)
        
        # Ensure the page loaded successfully
        title = await page.title()
        assert "AgentWitness" in title
        
        # Set up dialog handler
        dialog_messages = []
        page.on("dialog", lambda dialog: dialog_messages.append(dialog.message))
        page.on("dialog", lambda dialog: asyncio.create_task(dialog.accept()))

        # Fill in the bundle data with a missing signature
        mock_bundle = '{"format_version": "1.0", "records": [{"nonce": "mock", "payload_hash": "a", "ts": 123, "device_id": "test_device", "agent_id": "agent", "status": "OK"}]}'
        await page.fill('#ledger-pubkey', '0000000000000000000000000000000000000000000000000000000000000000')
        await page.fill('#devices-registry', '{"test_device": "0000000000000000000000000000000000000000000000000000000000000000"}')
        await page.fill('#expected-anchor', 'chain_mock')
        await page.fill('#bundle-input', mock_bundle)
        
        # Click the verify button
        await page.click('button[type="submit"]')
        await asyncio.sleep(1)
        
        # Should show error in UI
        results_html = await page.inner_html('#results')
        assert "VERIFICATION FAILED" in results_html
        
        # Now fill with valid signature
        from nacl.signing import SigningKey
        import json
        mock_sk = SigningKey.generate()
        mock_vk = mock_sk.verify_key.encode().hex()
        
        ledger_sk = SigningKey.generate()
        ledger_vk = ledger_sk.verify_key.encode().hex()
        
        raw_msg = f"a:123:mock_device:mock:agent:OK"
        mock_sig = mock_sk.sign(raw_msg.encode('utf-8')).signature.hex()
        
        import hashlib
        hasher = hashlib.sha256()
        hasher.update("0000000000000000000000000000000000000000000000000000000000000000".encode('utf-8'))
        
        canonical_record = f"a:123:mock_device:mock:agent:OK:{mock_sig}"
        record_hasher = hashlib.sha256()
        record_hasher.update(canonical_record.encode('utf-8'))
        hasher.update(record_hasher.digest())
        hasher.update("456".encode('utf-8'))
        chain_hash = hasher.hexdigest()
        
        receipt_msg = f"a:agent:123:mock_device:mock:{mock_sig}:456:{chain_hash}:OK"
        receipt_sig = ledger_sk.sign(receipt_msg.encode('utf-8')).signature.hex()

        valid_bundle = {
            "format_version": "1.0",
            "ledger_pubkey": ledger_vk,
            "records": [{
                "nonce": "mock",
                "payload_hash": "a",
                "ts": 123,
                "device_id": "mock_device",
                "agent_id": "agent",
                "status": "OK",
                "signature": mock_sig,
                "ledger_timestamp": 456,
                "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "chain_hash": chain_hash,
                "receipt_signature": receipt_sig
            }]
        }
        await page.fill("#ledger-pubkey", ledger_vk)
        await page.fill("#devices-registry", json.dumps({"mock_device": mock_vk}))
        await page.fill("#expected-anchor", chain_hash)
        await page.fill("#bundle-input", json.dumps(valid_bundle))
        await page.click("button[type='submit']")
        await asyncio.sleep(1)
        
        # Should show success in UI
        results_html = await page.inner_html('#results')
        assert "ALL RECORDS CRYPTOGRAPHICALLY VALID" in results_html
        
        await browser.close()
