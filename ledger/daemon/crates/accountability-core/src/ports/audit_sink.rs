use crate::domain::audit::AuditEvent;
use std::result::Result;

#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    #[error("Failed to write audit event: {0}")]
    WriteFailed(String),
}

/// Port for emitting structured audit events.
pub trait AuditSink: Send + Sync {
    /// Emit an audit event to the configured sink.
    fn emit(&self, event: &AuditEvent) -> Result<(), AuditSinkError>;
}
