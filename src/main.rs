mod inspect;
mod kpkg;
mod package;
mod signature;

use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use package::{PackageOptions, package};
use signature::{load_keypair, load_public_key, load_signature, sign_file, verify_file};
// use signature::{load_keypair, load_public_key, load_signature, sign_file, verify_file};
use std::fs;
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
    Sign {
        #[arg(short, long)]
        path: PathBuf,
        #[arg(short = 'k', long)]
        key: PathBuf,
    },
    Verify {
        #[arg(short, long)]
        path: PathBuf,
        #[arg(short = 'k', long)]
        pubkey: PathBuf,
        #[arg(short = 's', long)]
        signature: PathBuf,
    },
    GenKey {
        #[arg(long)]
        private: PathBuf,
        #[arg(long)]
        public: PathBuf,
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
        Commands::Sign { path, key } => {
            let keypair = load_keypair(&key)?;
            let sig = sign_file(&path, &keypair);
            fs::write("signature.sig", sig?.to_bytes())?;
            println!("File signed. Signature written to signature.sig");
        }
        Commands::Verify {
            path,
            pubkey,
            signature,
        } => {
            let public_key = load_public_key(&pubkey)?;
            let sig = load_signature(&signature)?;
            let valid = verify_file(&path, &public_key, &sig);
            if valid? {
                println!("Signature is valid.");
            } else {
                println!("Signature is INVALID.");
            }
        }
        Commands::GenKey { private, public } => {
            signature::generate_keypair(&private, &public)?;
        }
    }

    Ok(())
}
