#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod landlock;

#[cfg(target_os = "linux")]
pub mod seccomp;

/// Returns the appropriate SandboxEnforcer for the current platform.
pub fn default_enforcer() -> Box<dyn accountability_core::ports::sandbox::SandboxEnforcer> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsSandbox::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(landlock::LandlockSandbox::new())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        panic!("Autonomous Agent AccountabilityMCP is not supported on this platform")
    }
}
