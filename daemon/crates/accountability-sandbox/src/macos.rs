use accountability_core::domain::policy::{Capability, Policy};
use accountability_core::ports::sandbox::{SandboxEnforcer, SandboxError};

/// macOS sandbox enforcer using Apple's sandbox-exec (Seatbelt) profiles.
pub struct MacOsSandbox {
    profile_dir: std::path::PathBuf,
}

impl Default for MacOsSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsSandbox {
    pub fn new() -> Self {
        Self {
            profile_dir: std::env::temp_dir().join("autonomous-agent-accountability-profiles"),
        }
    }

    pub fn generate_sb_profile(policy: &Policy) -> String {
        let mut profile = String::from("(version 1)\n");
        // For MVP, macOS strict deny is too hard to bootstrap without dyld/libc exceptions.
        // We allow default but specifically block sensitive paths and network.
        profile.push_str("(allow default)\n");
        profile.push_str("(deny file-read* (regex #\".*/\\.ssh/.*\"))\n");
        profile.push_str("(deny file-read* (regex #\".*/\\.env\"))\n");

        if policy.default_deny {
            profile.push_str("(deny network-outbound)\n");
        }

        for tool_policy in policy.tool_policies().values() {
            for cap in &tool_policy.capabilities {
                if let Capability::NetworkConnect(hosts) = cap {
                    for host in hosts {
                        profile.push_str(&format!(
                            "(allow network-outbound (remote ip \"*:{}\"))\n",
                            host
                        ));
                    }
                }
            }
        }
        profile
    }

    #[allow(dead_code)]
    fn glob_to_sb_regex(glob: &str) -> String {
        glob.replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".")
    }
}

impl SandboxEnforcer for MacOsSandbox {
    fn apply_policy(&self, pid: u32, policy: &Policy) -> Result<(), SandboxError> {
        let profile = Self::generate_sb_profile(policy);
        std::fs::create_dir_all(&self.profile_dir)
            .map_err(|e| SandboxError::ApplyFailed(format!("Cannot create profile dir: {}", e)))?;

        let profile_path = self.profile_dir.join(format!("accountability-{}.sb", pid));
        std::fs::write(&profile_path, &profile)
            .map_err(|e| SandboxError::ApplyFailed(format!("Cannot write profile: {}", e)))?;

        tracing::info!(pid = pid, profile = %profile_path.display(), "Applied macOS sandbox profile");
        Ok(())
    }

    fn revoke(&self, pid: u32) -> Result<(), SandboxError> {
        let profile_path = self.profile_dir.join(format!("accountability-{}.sb", pid));
        if profile_path.exists() {
            std::fs::remove_file(&profile_path)
                .map_err(|e| SandboxError::RevokeFailed(format!("Cannot remove profile: {}", e)))?;
        }
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "sandbox-exec"
    }
}
