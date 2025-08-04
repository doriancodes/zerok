mod inspect;
mod kpkg;
mod package;

use clap::{Parser, Subcommand};
use package::{PackageOptions, package};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zerok", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Package {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Inspect {
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Package { input, output } => {
            package(PackageOptions { input, output })?;
        }
        Commands::Inspect { path } => {
            inspect::inspect(path)?;
        }
    }

    Ok(())
}
