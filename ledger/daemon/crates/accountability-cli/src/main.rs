use clap::Parser;
use std::path::PathBuf;

/// Autonomous Agent AccountabilityMCP — Kernel-level security daemon for Model Context Protocol.
///
/// Wraps any stdio-based MCP server with OS-level sandboxing to prevent
/// prompt-injection data exfiltration.
///
/// Example:
///   autonomous-agent-accountability --policy filesystem.json -- npx @modelcontextprotocol/server-filesystem /workspace
#[derive(Parser, Debug)]
#[command(name = "autonomous-agent-accountability", version, about, long_about = None)]
struct Cli {
    /// Path to a policy JSON file defining allowed capabilities.
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Allow file reads matching this glob pattern (can be repeated).
    #[arg(long, action = clap::ArgAction::Append)]
    allow_read: Vec<String>,

    /// Allow file writes matching this glob pattern (can be repeated).
    #[arg(long, action = clap::ArgAction::Append)]
    allow_write: Vec<String>,

    /// Allow network connections to this host (can be repeated).
    #[arg(long, action = clap::ArgAction::Append)]
    allow_net: Vec<String>,

    /// Block all outbound network connections (default behavior).
    #[arg(long, default_value_t = true)]
    deny_net_all: bool,

    /// Path to write audit log (default: stderr).
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,

    /// The command and arguments for the MCP server to wrap.
    /// Everything after '--' is treated as the server command.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .json()
        .init();

    tracing::info!(
        command = ?cli.command,
        policy = ?cli.policy,
        "Autonomous Agent AccountabilityMCP starting — wrapping MCP server"
    );

    use accountability_proxy::stdio_proxy::relay_with_intercept;
    use tokio::process::Command;
    use std::process::Stdio;

    // Load policy...
    let policy_json = if let Some(path) = &cli.policy {
        std::fs::read_to_string(path).unwrap_or_else(|_| "{\"name\": \"default\", \"tool_policies\": {}}".into())
    } else {
        "{\"name\": \"default\", \"tool_policies\": {}}".into()
    };

    let policy = accountability_core::domain::policy::Policy::from_json(&policy_json).unwrap_or_else(|_| accountability_core::domain::policy::Policy {
        name: "fallback".into(),
        description: None,
        default_deny: cli.deny_net_all,
        tool_policies: std::collections::HashMap::new(),
    });

    #[cfg(target_os = "macos")]
    let (cmd, args) = {
        use accountability_sandbox::macos::MacOsSandbox;
        let profile_content = MacOsSandbox::generate_sb_profile(&policy);
        let profile_path = std::env::temp_dir().join("autonomous-agent-accountability-runtime.sb");
        std::fs::write(&profile_path, profile_content)?;
        
        let mut final_args = vec!["-f".to_string(), profile_path.to_string_lossy().into_owned(), "--".to_string()];
        final_args.extend(cli.command);
        ("sandbox-exec".to_string(), final_args)
    };

    #[cfg(not(target_os = "macos"))]
    let (cmd, args) = {
        let mut cmd_iter = cli.command.iter();
        let cmd = cmd_iter.next().cloned().unwrap_or_default();
        let final_args = cmd_iter.cloned().collect::<Vec<String>>();
        (cmd, final_args)
    };

    let child = Command::new(&cmd)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if let Err(e) = relay_with_intercept(child).await {
        eprintln!("[ACCOUNTABILITY] 🚨 Daemon relay terminated with error: {}", e);
    }

    Ok(())
}
