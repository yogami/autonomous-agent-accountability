use serde_json::Value;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tokio::sync::Mutex;
use crate::ledger_client::LedgerClient;

pub async fn relay_with_intercept(mut child: Child) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = tokio::io::stdin();
    let shared_stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let ledger_client = LedgerClient::new();
    ledger_client.start_background_sync();

    let pending_calls: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let pending_calls_clone = Arc::clone(&pending_calls);
    let ledger_client_clone = ledger_client.clone();

    let stdout_clone1 = Arc::clone(&shared_stdout);
    let ledger_client_final = ledger_client.clone();
    let parent_to_child = tokio::spawn(async move {
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        while let Ok(bytes) = reader.read_line(&mut line).await {
            if bytes == 0 { break; }

            match serde_json::from_str::<Value>(&line) {
                Ok(val) => {
                    let mut has_tool_call = false;
                    let mut req_id_str = String::new();
                    let mut tool_name_str = String::new();

                    if let Some(req) = val.as_object() {
                        if req.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                            has_tool_call = true;
                            if let Some(id) = req.get("id") {
                                req_id_str = id.to_string();
                            }
                            if let Some(params) = req.get("params") {
                                if let Some(name) = params.get("name") {
                                    tool_name_str = name.as_str().unwrap_or("").to_string();
                                }
                            }
                        }
                    } else if val.is_array() {
                        let mut stdout_lock = stdout_clone1.lock().await;
                        let error_msg = serde_json::json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32600, "message": "JSON-RPC batches are unsupported" },
                            "id": serde_json::Value::Null
                        });
                        let _ = stdout_lock.write_all(format!("{}\n", error_msg).as_bytes()).await;
                        let _ = stdout_lock.flush().await;
                        line.clear();
                        continue;
                    }

                    let req_obj = val.as_object();
                    if has_tool_call {
                        let params_val = req_obj.and_then(|r| r.get("params"));
                        let is_irreversible = {
                            let policy_json_str = std::env::var("ACCOUNTABILITY_POLICY_JSON").unwrap_or_else(|_| "{}".to_string());
                            let policy: Value = serde_json::from_str(&policy_json_str).unwrap_or(serde_json::json!({}));
                            let default_mode = policy.get("default_mode").and_then(|v| v.as_str()).unwrap_or("require_ledger");
                            let mut requires = default_mode == "require_ledger";
                            
                            if let Some(rules) = policy.get("rules").and_then(|v| v.as_array()) {
                                for rule in rules {
                                    if rule.get("tool").and_then(|v| v.as_str()) == Some(&tool_name_str) {
                                        let mode = rule.get("mode").and_then(|v| v.as_str()).unwrap_or("require_ledger");
                                        if mode == "bypass" {
                                            requires = false;
                                        } else if mode == "bypass_if" {
                                            requires = true;
                                            if let Some(cond) = rule.get("bypass_condition") {
                                                if let Some(param_name) = cond.get("param").and_then(|v| v.as_str()) {
                                                    if let Some(less_than) = cond.get("less_than").and_then(|v| v.as_f64()) {
                                                        if let Some(p) = params_val {
                                                            if let Some(val) = p.get(param_name).and_then(|v| v.as_f64()) {
                                                                if val < less_than {
                                                                    requires = false;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            requires = true;
                                        }
                                        break;
                                    }
                                }
                            }
                            
                            eprintln!("CRITICAL-DEBUG: TOOL='{}', POLICY='{}', IRREVERSIBLE={}", tool_name_str, policy_json_str, requires);
                            let is_irreversible = requires;
                            is_irreversible
                        };

                        if !is_irreversible {
                            // Fast-path bypass!
                            if child_stdin.write_all(line.as_bytes()).await.is_err() { break; }
                            line.clear();
                            continue;
                        }

                        if req_id_str.is_empty() || req_id_str == "null" {
                            let mut stdout_lock = stdout_clone1.lock().await;
                            let error_msg = serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": { "code": -32600, "message": "JSON-RPC notifications (missing ID) are unsupported for tool calls" },
                                "id": serde_json::Value::Null
                            });
                            let _ = stdout_lock.write_all(format!("{}\n", error_msg).as_bytes()).await;
                            let _ = stdout_lock.flush().await;
                            line.clear();
                            continue;
                        }

                        if pending_calls.lock().await.contains_key(&req_id_str) {
                            let mut stdout_lock = stdout_clone1.lock().await;
                            let error_msg = serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": { "code": -32000, "message": "Duplicate/in-flight JSON-RPC request ID blocked by accountability proxy." },
                                "id": req_id_str
                            });
                            let _ = stdout_lock.write_all(format!("{}\n", error_msg).as_bytes()).await;
                            let _ = stdout_lock.flush().await;
                            line.clear();
                            continue;
                        }

                        let raw_json_bytes = line.trim_end().as_bytes();
                        
                        let device_id = std::env::var("ACCOUNTABILITY_DEVICE_ID").unwrap_or_default();
                        
                        let mut semantic_map = std::collections::BTreeMap::new();
                        if let Some(req_obj) = val.as_object() {
                            if let Some(id) = req_obj.get("id") { semantic_map.insert("id", id); }
                            if let Some(m) = req_obj.get("method") { semantic_map.insert("method", m); }
                            if let Some(p) = req_obj.get("params") { semantic_map.insert("params", p); }
                        }
                        let canonical_json = serde_json::to_string(&semantic_map).unwrap();
                        
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(device_id.as_bytes());
                        hasher.update(canonical_json.as_bytes());
                        let hash_bytes = hasher.finalize();
                        let stable_nonce = uuid::Uuid::from_slice(&hash_bytes[0..16]).unwrap().to_string();
                        
                        if ledger_client.has_nonce(&stable_nonce).await {
                            let mut stdout_lock = stdout_clone1.lock().await;
                            let error_msg = serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": { "code": -32000, "message": "Duplicate request blocked by accountability proxy idempotency layer." },
                                "id": req_id_str
                            });
                            let _ = stdout_lock.write_all(format!("{}\n", error_msg).as_bytes()).await;
                            let _ = stdout_lock.flush().await;
                            line.clear();
                            continue;
                        }
                        
                        if let Err(e) = ledger_client.ensure_lease().await {
                            if let Some(req_obj) = val.as_object() {
                                if let Some(id) = req_obj.get("id") {
                                    let error_response = serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": -32000,
                                            "message": format!("Accountability proxy denied execution: {}", e)
                                        }
                                    });
                                    let mut out_str = serde_json::to_string(&error_response).unwrap();
                                    out_str.push('\n');
                                    let mut stdout_lock = stdout_clone1.lock().await;
                                    let _ = stdout_lock.write_all(out_str.as_bytes()).await;
                                    let _ = stdout_lock.flush().await;
                                }
                            }
                            line.clear();
                            continue;
                        }

                        match ledger_client.insert_local_event(raw_json_bytes, "SEAL_REQUESTED", Some(stable_nonce.clone())).await {
                            Ok(nonce) => {
                                pending_calls.lock().await.insert(req_id_str, stable_nonce);
                                if child_stdin.write_all(line.as_bytes()).await.is_err() { break; }
                            }
                            Err(e) => {
                                if let Some(req_obj) = val.as_object() {
                                    if let Some(id) = req_obj.get("id") {
                                        let error_response = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": id,
                                            "error": {
                                                "code": -32000,
                                                "message": format!("Accountability proxy denied execution: {}", e)
                                            }
                                        });
                                        let mut out_str = serde_json::to_string(&error_response).unwrap();
                                        out_str.push('\n');
                                        let mut stdout_lock = stdout_clone1.lock().await;
                                        let _ = stdout_lock.write_all(out_str.as_bytes()).await;
                                        let _ = stdout_lock.flush().await;
                                    }
                                }
                            }
                        }
                    } else {
                        if child_stdin.write_all(line.as_bytes()).await.is_err() { break; }
                    }
                }
                Err(_) => {
                    if child_stdin.write_all(line.as_bytes()).await.is_err() { break; }
                }
            }
            line.clear();
        }
        drop(child_stdin);
    });

    let stdout_clone2 = Arc::clone(&shared_stdout);
    let child_to_parent = tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout);
        let mut line = String::new();

        while let Ok(bytes) = reader.read_line(&mut line).await {
            if bytes == 0 { break; }

            if let Ok(val) = serde_json::from_str::<Value>(&line) {
                if let Some(res) = val.as_object() {
                    if let Some(id) = res.get("id") {
                        let id_str = id.to_string();
                        let mut map = pending_calls_clone.lock().await;
                        if let Some(nonce) = map.remove(&id_str) {
                            drop(map);
                            let raw_json_bytes = line.trim_end().as_bytes();
                            let status = if res.contains_key("error") { "SEAL_FAILED" } else { "SEAL_COMPLETED" };
                            
                            if std::env::var("CRASH_AFTER_EXECUTION").is_ok() {
                                eprintln!("FAULT INJECTION: Crashing after execution but before terminal sealing!");
                                std::process::exit(9);
                            }
                            
                            if let Err(err) = ledger_client_clone.insert_local_event(raw_json_bytes, status, Some(nonce)).await {
                                eprintln!("CRITICAL: Failed to durably seal terminal event! Halting accountability proxy to prevent unaccounted execution. Error: {}", err);
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }

            let mut stdout_lock = stdout_clone2.lock().await;
            if stdout_lock.write_all(line.as_bytes()).await.is_err() { break; }
            let _ = stdout_lock.flush().await;
            drop(stdout_lock);
            line.clear();
        }
    });

    let _ = parent_to_child.await;
    let _ = child.wait().await;
    let _ = child_to_parent.await;
    
    // FLUSH QUEUE BEFORE EXITING
    // Ensures short-lived commands sync their events to the ledger
    for _ in 0..10 {
        ledger_client_final.sync_queue().await;
    }
    
    Ok(())
}
