use crate::domain::jsonrpc::JsonRpcMessage;
use std::result::Result;

#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Port for intercepting stdio JSON-RPC messages.
pub trait StdioInterceptor: Send + Sync {
    /// Called when a JSON-RPC message is received from the client (going to the MCP server).
    fn on_client_message(&self, msg: &JsonRpcMessage) -> Result<(), InterceptError>;

    /// Called when a JSON-RPC message is received from the MCP server (going to the client).
    fn on_server_message(&self, msg: &JsonRpcMessage) -> Result<(), InterceptError>;
}
