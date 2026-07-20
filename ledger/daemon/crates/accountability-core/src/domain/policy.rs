use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub default_deny: bool,
    #[serde(default)]
    pub tool_policies: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPolicy {
    pub tool_name: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Capability {
    FileRead(String),
    FileWrite(String),
    NetworkConnect(Vec<String>), // list of hosts
    NetworkDeny,
    FileDenyAll,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Failed to parse policy: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub tool_name: String,
    pub attempted_action: String,
    pub matched_rule: Option<String>,
}

impl Policy {
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(json).map_err(PolicyError::Parse)
    }

    pub fn check_file_access(&self, tool_name: &str, path: &str) -> Result<(), PolicyViolation> {
        let is_ssh = path.contains("/.ssh/") || path.ends_with("/.ssh");
        if is_ssh {
            return Err(PolicyViolation {
                tool_name: tool_name.to_string(),
                attempted_action: format!("File access: {}", path),
                matched_rule: Some("Hardcoded SSH block".to_string()),
            });
        }

        let tool_policy = match self.tool_policies.get(tool_name) {
            Some(p) => p,
            None => {
                if self.default_deny {
                    return Err(PolicyViolation {
                        tool_name: tool_name.to_string(),
                        attempted_action: format!("File access: {}", path),
                        matched_rule: Some("Default deny".to_string()),
                    });
                }
                return Ok(());
            }
        };

        for cap in &tool_policy.capabilities {
            if let Capability::FileDenyAll = cap {
                return Err(PolicyViolation {
                    tool_name: tool_name.to_string(),
                    attempted_action: format!("File access: {}", path),
                    matched_rule: Some("FileDenyAll".to_string()),
                });
            }
        }

        let mut allowed = false;
        for cap in &tool_policy.capabilities {
            match cap {
                Capability::FileRead(pattern) | Capability::FileWrite(pattern)
                    if glob_match::glob_match(pattern, path) =>
                {
                    allowed = true;
                    break;
                }
                _ => {}
            }
        }

        if allowed {
            Ok(())
        } else {
            Err(PolicyViolation {
                tool_name: tool_name.to_string(),
                attempted_action: format!("File access: {}", path),
                matched_rule: Some("No matching allow capability".to_string()),
            })
        }
    }

    pub fn check_network_access(
        &self,
        tool_name: &str,
        host: &str,
        _port: u16,
    ) -> Result<(), PolicyViolation> {
        let tool_policy = match self.tool_policies.get(tool_name) {
            Some(p) => p,
            None => {
                if self.default_deny {
                    return Err(PolicyViolation {
                        tool_name: tool_name.to_string(),
                        attempted_action: format!("Network connect: {}", host),
                        matched_rule: Some("Default deny".to_string()),
                    });
                }
                return Ok(());
            }
        };

        for cap in &tool_policy.capabilities {
            if let Capability::NetworkDeny = cap {
                return Err(PolicyViolation {
                    tool_name: tool_name.to_string(),
                    attempted_action: format!("Network connect: {}", host),
                    matched_rule: Some("NetworkDeny".to_string()),
                });
            }
        }

        let mut allowed = false;
        for cap in &tool_policy.capabilities {
            if let Capability::NetworkConnect(hosts) = cap {
                if hosts.iter().any(|h| glob_match::glob_match(h, host)) {
                    allowed = true;
                    break;
                }
            }
        }

        if allowed {
            Ok(())
        } else {
            Err(PolicyViolation {
                tool_name: tool_name.to_string(),
                attempted_action: format!("Network connect: {}", host),
                matched_rule: Some("No matching allow capability".to_string()),
            })
        }
    }

    pub fn tool_policies(&self) -> &HashMap<String, ToolPolicy> {
        &self.tool_policies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        let policy = Policy {
            name: "test".into(),
            description: None,
            default_deny: true,
            tool_policies: HashMap::new(),
        };

        assert!(policy
            .check_file_access("unknown_tool", "/tmp/foo")
            .is_err());
        assert!(policy
            .check_network_access("unknown_tool", "example.com", 80)
            .is_err());
    }

    #[test]
    fn test_glob_match() {
        let mut tool_policies = HashMap::new();
        tool_policies.insert(
            "read_tool".into(),
            ToolPolicy {
                tool_name: "read_tool".into(),
                capabilities: vec![Capability::FileRead("/workspace/*".into())],
            },
        );

        let policy = Policy {
            name: "test".into(),
            description: None,
            default_deny: true,
            tool_policies,
        };

        assert!(policy
            .check_file_access("read_tool", "/workspace/test.txt")
            .is_ok());
        assert!(policy
            .check_file_access("read_tool", "/etc/passwd")
            .is_err());
    }

    #[test]
    fn test_ssh_block() {
        let mut tool_policies = HashMap::new();
        tool_policies.insert(
            "read_tool".into(),
            ToolPolicy {
                tool_name: "read_tool".into(),
                capabilities: vec![
                    Capability::FileRead("/workspace/*".into()),
                    Capability::FileRead("/home/user/.ssh/*".into()),
                ],
            },
        );

        let policy = Policy {
            name: "test".into(),
            description: None,
            default_deny: true,
            tool_policies,
        };

        assert!(policy
            .check_file_access("read_tool", "/workspace/test.txt")
            .is_ok());
        assert!(policy
            .check_file_access("read_tool", "/home/user/.ssh/id_rsa")
            .is_err());
    }
}
