import os
import urllib.parse
import base64

def build_verifier():
    # Read the vendored crypto library
    crypto_js_path = os.path.join("ledger", "static", "crypto.js")
    with open(crypto_js_path, "r") as f:
        crypto_js = f.read()

    # The easiest way to import a bundled ESM script without external files
    # is to serve it as a Data URI in an import map or directly import the data URI.
    crypto_b64 = base64.b64encode(crypto_js.encode('utf-8')).decode('utf-8')
    data_uri = f"data:text/javascript;base64,{crypto_b64}"

    # Define the verifier HTML with the embedded crypto and XSS-safe DOM building
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>AgentWitness Verification Portal</title>
    <style>
        body {{ background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 50px; text-align: center; }}
        h1 {{ color: #58a6ff; }}
        .container {{ border: 1px solid #30363d; padding: 20px; border-radius: 8px; max-width: 800px; margin: auto; }}
        input, button, textarea {{ padding: 10px; margin-top: 20px; border-radius: 5px; border: 1px solid #30363d; background:#161b22; color:#c9d1d9; box-sizing: border-box; }}
        button {{ background-color: #238636; color: white; cursor: pointer; border: 1px solid rgba(240, 246, 252, 0.1); }}
        #results {{ margin-top: 20px; text-align: left; padding: 10px; background: #0d1117; border-radius: 5px; border: 1px solid #30363d; }}
        .error {{ color: #f85149; font-weight: bold; }}
        .success {{ color: #2ea043; font-weight: bold; }}
        .record {{ margin-bottom: 5px; padding-bottom: 5px; border-bottom: 1px solid #30363d; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AgentWitness Zero-Trust Verifier</h1>
        <p>Cryptographically verifies .agentwitness_bundle locally in your browser.</p>
        <form id="verify-form">
            <input type="text" id="ledger-pubkey" placeholder="Enter Trusted Ledger Public Key (Hex)" style="width:100%;" required /><br>
            <textarea id="devices-registry" rows="3" placeholder='Enter Trusted Device Registry JSON (e.g. {{"device_1": "pubkey_hex"}})' style="width:100%;" required></textarea><br>
            <input type="text" id="expected-anchor" placeholder="Enter Expected Final Anchor Hash (from OTS)" style="width:100%;" required /><br>
            <textarea id="bundle-input" rows="10" placeholder='Enter Project Bundle JSON' style="width:100%;" required></textarea><br>
            <button type="submit">Verify Cryptographic Integrity</button>
        </form>
        <div id="results"></div>
    </div>
    
    <script type="module">
        // Import our fully self-contained vendored cryptographic library from the Data URI
        import {{ ed, sha512, sha256 }} from '{data_uri}';
        
        // @noble/ed25519 requires setting sha512Sync
        ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
        
        const hexToBytes = (hex) => {{
            let bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {{
                bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
            }}
            return bytes;
        }};

        const bytesToHex = (bytes) => {{
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }};

        document.getElementById('verify-form').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = ""; // Clear previous results safely
            
            // Safe DOM updater
            const addLog = (text, className) => {{
                const el = document.createElement('div');
                el.textContent = text;
                if (className) el.className = className;
                resultsDiv.appendChild(el);
            }};
            
            addLog("Verifying signatures...", "");
            
            try {{
                const bundleText = document.getElementById('bundle-input').value;
                const bundle = JSON.parse(bundleText);
                const pubkey = document.getElementById('ledger-pubkey').value;
                const devicesRegistryText = document.getElementById('devices-registry').value;
                const devicesRegistry = JSON.parse(devicesRegistryText);
                const expectedAnchor = document.getElementById('expected-anchor').value;
                
                if (bundle.format_version !== "1.0") throw new Error("Invalid format_version");
                if (!pubkey) throw new Error("Ledger public key required");
                if (!expectedAnchor) throw new Error("Expected anchor hash required");
                
                let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
                let isValid = true;
                
                for (const record of bundle.records) {{
                    if (!record.signature || !record.device_id || !record.receipt_signature || !record.chain_hash) {{
                       isValid = false;
                       throw new Error(`Missing signature/hash fields for nonce ${{record.nonce}}`);
                    }}
                    
                    // Device registry lookup (Zero-Trust Blocker Fix)
                    const devicePubkeyHex = devicesRegistry[record.device_id];
                    if (!devicePubkeyHex) {{
                        throw new Error(`Device ID "${{record.device_id}}" not found in Trusted Device Registry`);
                    }}
                    
                    // 1. Reconstruct exact device payload string
                    const rawMsg = `${{record.payload_hash}}:${{record.ts}}:${{record.device_id}}:${{record.nonce}}:${{record.agent_id}}:${{record.status}}`;
                    const msgBytes = new TextEncoder().encode(rawMsg);
                    
                    // Verify device signature against the TRUSTED registry key, not the record's self-proclaimed key
                    try {{
                        const isSigValid = await ed.verify(record.signature, msgBytes, devicePubkeyHex);
                        if (!isSigValid) {{
                            throw new Error("Invalid Ed25519 device signature");
                        }}
                    }} catch (e) {{
                        throw new Error("Device signature verification failed: " + e.message);
                    }}
                    
                    // 2. Walk the Chain using canonical string matching ledger
                    const enc = new TextEncoder();
                    const hasher = sha256.create();
                    
                    if (record.previous_hash !== prevHash) {{
                        throw new Error(`Chain break! Record ${{record.nonce}} expected prev ${{record.previous_hash}} but chain was ${{prevHash}}`);
                    }}
                    
                    // Hash the complete canonical record to verify Bitcoin anchoring validity
                    // chain_hash = SHA256(previous_hash + SHA256(canonical_record))
                    hasher.update(enc.encode(record.previous_hash));
                    
                    const recordHasher = sha256.create();
                    const canonicalRecord = `${{record.payload_hash}}:${{record.ts}}:${{record.device_id}}:${{record.nonce}}:${{record.agent_id}}:${{record.status}}:${{record.signature}}`;
                    recordHasher.update(enc.encode(canonicalRecord));
                    
                    hasher.update(recordHasher.digest());
                    hasher.update(enc.encode(record.ledger_timestamp.toString()));
                    
                    const computedChainHash = bytesToHex(hasher.digest());
                    
                    if (computedChainHash !== record.chain_hash) {{
                        throw new Error(`Chain hash mismatch at nonce ${{record.nonce}}. Expected ${{record.chain_hash}}, got ${{computedChainHash}}`);
                    }}
                    
                    // 3. Verify Receipt Signature from Ledger
                    const receiptMsg = `${{record.payload_hash}}:${{record.agent_id}}:${{record.ts}}:${{record.device_id}}:${{record.nonce}}:${{record.signature}}:${{record.ledger_timestamp}}:${{computedChainHash}}:${{record.status}}`;
                    const receiptMsgBytes = enc.encode(receiptMsg);
                    
                    try {{
                        const isReceiptValid = await ed.verify(record.receipt_signature, receiptMsgBytes, pubkey);
                        if (!isReceiptValid) {{
                            throw new Error("Invalid Ed25519 ledger receipt signature");
                        }}
                    }} catch (e) {{
                        throw new Error("Ledger receipt verification failed: " + e.message);
                    }}
                    
                    prevHash = computedChainHash;
                    addLog(`Record ${{record.nonce}}: Device Sig, Ledger Sig, & Chain Hash Valid`, "success record");
                }}
                
                if (prevHash !== expectedAnchor) {{
                    throw new Error(`Chain completeness violation! Final chain hash (${{prevHash}}) does not match expected anchor (${{expectedAnchor}}). Records may have been truncated.`);
                }}
                
                if (isValid) {{
                    addLog("ALL RECORDS CRYPTOGRAPHICALLY VALID AND FULLY ANCHORED", "success");
                }}
            }} catch (err) {{
                addLog(`VERIFICATION FAILED: ${{err.message}}`, "error");
            }}
        }});
    </script>
</body>
</html>
"""
    with open("verifier.html", "w") as f:
        f.write(html_content)
    print("Created verifier.html (Zero-Trust Standalone Verifier)")

if __name__ == "__main__":
    build_verifier()
