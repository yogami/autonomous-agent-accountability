use serde_json::{json, Value};
use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if let Ok(val) = serde_json::from_str::<Value>(&line) {
            if val["method"] == "tools/call" {
                let tool = val
                    .pointer("/params/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if tool == "read_file" {
                    let path = val
                        .pointer("/params/arguments/path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    match std::fs::read_to_string(path) {
                        Ok(content) => {
                            let resp = json!({
                                "jsonrpc": "2.0",
                                "id": val["id"],
                                "result": { "content": content }
                            });
                            println!("{}", resp);
                        }
                        Err(e) => {
                            let resp = json!({
                                "jsonrpc": "2.0",
                                "id": val["id"],
                                "error": { "code": -32603, "message": e.to_string() }
                            });
                            println!("{}", resp);
                        }
                    }
                }
            }
        }
    }
}
