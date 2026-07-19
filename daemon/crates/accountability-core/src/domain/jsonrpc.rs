use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(serde_json::Value), // We don't strongly type responses yet
    Notification(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ToolCallRequest {
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("Not a tool call")]
    NotToolCall,
}

pub struct JsonRpcParser;

impl JsonRpcParser {
    pub fn parse(data: &[u8]) -> Result<Vec<JsonRpcMessage>, ParseError> {
        let mut messages = Vec::new();
        // Since we may receive multiple objects, we use serde_json::Deserializer::from_slice
        let stream = serde_json::Deserializer::from_slice(data).into_iter::<JsonRpcMessage>();
        for result in stream {
            match result {
                Ok(msg) => messages.push(msg),
                Err(e) if e.is_eof() => break, // Partial message, handle upstream
                Err(e) => return Err(ParseError::InvalidJson(e)),
            }
        }
        Ok(messages)
    }

    pub fn extract_tool_call(msg: &JsonRpcRequest) -> Option<ToolCallRequest> {
        if msg.method == "tools/call" {
            if let Some(params) = &msg.params {
                if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                    let arguments = params
                        .get("arguments")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    return Some(ToolCallRequest {
                        tool_name: name.to_string(),
                        arguments,
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_tool_call() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({
                "name": "read_file",
                "arguments": { "path": "/etc/passwd" }
            })),
        };

        let tool_call = JsonRpcParser::extract_tool_call(&req).unwrap();
        assert_eq!(tool_call.tool_name, "read_file");
        assert_eq!(tool_call.arguments, json!({ "path": "/etc/passwd" }));
    }

    #[test]
    fn test_parse_multiple() {
        let json_str =
            r#"{"jsonrpc": "2.0", "method": "test"} {"jsonrpc": "2.0", "method": "test2"}"#;
        let msgs = JsonRpcParser::parse(json_str.as_bytes()).unwrap();
        assert_eq!(msgs.len(), 2);
    }
}
