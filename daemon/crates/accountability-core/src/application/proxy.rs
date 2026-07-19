use crate::domain::audit::{AuditAction, AuditEvent};
use crate::domain::jsonrpc::ToolCallRequest;
use crate::domain::policy::Policy;
use crate::ports::audit_sink::AuditSink;
use crate::ports::sandbox::SandboxEnforcer;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] crate::ports::sandbox::SandboxError),
    #[error("Audit error: {0}")]
    Audit(#[from] crate::ports::audit_sink::AuditSinkError),
}

pub struct ProxySession<'a> {
    sandbox: &'a dyn SandboxEnforcer,
    audit_sink: &'a dyn AuditSink,
    policy: &'a Policy,
}

impl<'a> ProxySession<'a> {
    pub fn new(
        sandbox: &'a dyn SandboxEnforcer,
        audit_sink: &'a dyn AuditSink,
        policy: &'a Policy,
    ) -> Self {
        Self {
            sandbox,
            audit_sink,
            policy,
        }
    }

    pub fn on_tool_call(&self, tool_call: &ToolCallRequest, pid: u32) -> Result<(), ProxyError> {
        let action = AuditAction::ProcessSpawn(format!("tool_call: {}", tool_call.tool_name));
        let event = AuditEvent::new_allowed(pid, tool_call.tool_name.clone(), action, None);
        self.audit_sink.emit(&event)?;

        // Apply policy to sandbox
        self.sandbox.apply_policy(pid, self.policy)?;

        Ok(())
    }
}
