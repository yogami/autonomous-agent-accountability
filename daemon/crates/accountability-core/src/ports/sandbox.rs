use crate::domain::policy::Policy;
use std::result::Result;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Failed to apply sandbox policy: {0}")]
    ApplyFailed(String),
    #[error("Failed to revoke sandbox: {0}")]
    RevokeFailed(String),
    #[error("Platform not supported: {0}")]
    Unsupported(String),
}

/// Port for OS-level sandbox enforcement.
/// Each platform provides its own adapter implementing this trait.
pub trait SandboxEnforcer: Send + Sync {
    /// Apply the given policy to the process with the specified PID.
    fn apply_policy(&self, pid: u32, policy: &Policy) -> Result<(), SandboxError>;

    /// Revoke all sandbox restrictions for the given PID.
    fn revoke(&self, pid: u32) -> Result<(), SandboxError>;

    /// Returns the name of this sandbox backend.
    fn backend_name(&self) -> &str;
}
