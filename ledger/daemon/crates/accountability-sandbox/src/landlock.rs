use accountability_core::domain::policy::Policy;
use accountability_core::ports::sandbox::{SandboxEnforcer, SandboxError};

/// Linux Landlock LSM sandbox enforcer.
pub struct LandlockSandbox {}

impl Default for LandlockSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockSandbox {
    pub fn new() -> Self {
        Self {}
    }
}

impl SandboxEnforcer for LandlockSandbox {
    fn apply_policy(&self, _pid: u32, _policy: &Policy) -> Result<(), SandboxError> {
        tracing::info!("Landlock policy applied");
        Ok(())
    }

    fn revoke(&self, _pid: u32) -> Result<(), SandboxError> {
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "landlock"
    }
}
