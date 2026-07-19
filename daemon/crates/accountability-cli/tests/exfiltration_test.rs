#![cfg(target_os = "macos")]

use assert_cmd::Command;
use serde_json::json;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
#[cfg(target_os = "macos")]
fn test_block_exfiltration() {
    // 1. We create a safe file and a secret file
    let mut safe_file = NamedTempFile::new().unwrap();
    write!(safe_file, "safe content").unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let secret_path_buf = temp_dir.path().join(".env");
    let mut secret_file = std::fs::File::create(&secret_path_buf).unwrap();
    write!(secret_file, "super secret").unwrap();

    let safe_path = safe_file.path().to_str().unwrap();
    let secret_path = secret_path_buf.to_str().unwrap();

    // 2. We start autonomous-agent-accountability wrapping vulnerable-server
    // We allow read to safe_path, but implicitly deny secret_path
    let mut cmd = Command::cargo_bin("autonomous-agent-accountability").unwrap();
    cmd.arg("--allow-read")
        .arg(safe_path)
        .arg("--")
        .arg(assert_cmd::cargo::cargo_bin("vulnerable-server"));

    // 3. We send JSON-RPC for safe file
    let safe_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": safe_path
            }
        }
    });

    let secret_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": secret_path
            }
        }
    });

    let payload = format!("{}\n{}\n", safe_req.to_string(), secret_req.to_string());

    let assert = cmd.write_stdin(payload).assert();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("STDERR: {}", stderr);

    // 4. Assert safe file was read
    println!("STDOUT: {}", stdout);
    assert!(stdout.contains("safe content"));

    // 5. Assert secret file read was blocked (Operation not permitted)
    assert!(stdout.contains("Operation not permitted"));
}
