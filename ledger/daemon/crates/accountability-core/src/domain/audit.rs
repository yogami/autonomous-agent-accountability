use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub tool_name: String,
    pub action: AuditAction,
    pub result: AuditResult,
    pub policy_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    FileRead(String),
    FileWrite(String),
    NetworkConnect(String, u16),
    ProcessSpawn(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Allowed,
    Blocked(String),
}

impl AuditEvent {
    pub fn new_blocked(
        pid: u32,
        tool_name: String,
        action: AuditAction,
        reason: String,
        rule: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            pid,
            tool_name,
            action,
            result: AuditResult::Blocked(reason),
            policy_rule: rule,
        }
    }

    pub fn new_allowed(
        pid: u32,
        tool_name: String,
        action: AuditAction,
        rule: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            pid,
            tool_name,
            action,
            result: AuditResult::Allowed,
            policy_rule: rule,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization() {
        let event = AuditEvent::new_blocked(
            1234,
            "read_file".into(),
            AuditAction::FileRead("/etc/passwd".into()),
            "Default deny".into(),
            None,
        );
        let json = event.to_json();
        assert!(json.contains("read_file"));
        assert!(json.contains("Blocked"));
    }
}
