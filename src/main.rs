#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zerok::inspect::inspect;

#[derive(Parser)]
#[command(name = "zerok", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inspect {
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { path } => {
            inspect(path)?;
        }
    }

    Ok(())
}
