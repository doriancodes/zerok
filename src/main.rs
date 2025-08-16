#![forbid(unsafe_code)]
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use zerok::audit::{audit_elf, audit_trace};
use zerok::inspect::inspect;

#[derive(Parser)]
#[command(name = "zerok", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a manifest file
    Inspect(InspectArgs),

    /// Audit binaries or traces to suggest a manifest
    Audit(AuditCmd),
}

#[derive(Args)]
struct InspectArgs {
    /// Path to the manifest to validate
    #[arg(value_name = "MANIFEST")]
    path: PathBuf,
}

#[derive(Args)]
struct AuditCmd {
    #[command(subcommand)]
    target: AuditTarget,
}

#[derive(Subcommand)]
enum AuditTarget {
    /// Static ELF audit
    Elf(ElfArgs),

    /// Audit from an strace log
    Trace(TraceArgs),
}

#[derive(Args)]
struct ElfArgs {
    /// Path to the ELF binary
    #[arg(value_name = "ELF_PATH")]
    path: PathBuf,

    /// Write JSON report to this file
    #[arg(long)]
    json: Option<PathBuf>,

    /// Write suggested manifest to this file
    #[arg(long)]
    manifest: Option<PathBuf>,
}

#[derive(Args)]
struct TraceArgs {
    /// Path to strace text log
    #[arg(value_name = "TRACE_LOG")]
    path: PathBuf,

    /// Fail with non-zero exit if risky syscalls are detected
    #[arg(long)]
    strict: bool,

    /// Write JSON report to this file
    #[arg(long)]
    json: Option<PathBuf>,

    /// Write suggested manifest to this file
    #[arg(long)]
    manifest: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => {
            inspect(args.path)?;
        }
        Commands::Audit(cmd) => match cmd.target {
            AuditTarget::Elf(args) => {
                // thread these options into audit_elf later
                audit_elf(args.path)?;
                // if let Some(j) = args.json { write_report_json(j, …)?; }
                // if let Some(m) = args.manifest { write_manifest(m, …)?; }
            }
            AuditTarget::Trace(args) => {
                audit_trace(args.path)?;
                // if args.strict { std::process::exit(if found_risks { 2 } else { 0 }); }
                // if let Some(j) = args.json { ... }
                // if let Some(m) = args.manifest { ... }
            }
        },
    }

    Ok(())
}
