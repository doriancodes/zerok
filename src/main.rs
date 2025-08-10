use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use zerok::inspect::inspect;
use zerok::package::{PackageOptions, package};
use zerok::signature::{
    generate_keypair, load_keypair, load_public_key, load_signature, sign_file, verify_file,
};

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
            inspect(path)?;
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
            generate_keypair(&private, &public)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_package_then_inspect_prints_expected() {
        use assert_cmd::prelude::*;
        use assert_fs::prelude::*;
        use predicates::prelude::PredicateBooleanExt;
        use predicates::str::contains;
        use std::process::Command;

        let tmp = assert_fs::TempDir::new().unwrap();
        let proj = tmp.child("proj");
        proj.create_dir_all().unwrap();
        proj.child(".kpkg.toml")
            .write_str("name=\"demo\"\nversion=\"0.1.0\"\n")
            .unwrap();
        proj.child("binary").write_binary(b"\x7fELF").unwrap();
        let out = tmp.child("demo.kpkg");

        Command::cargo_bin("zerok")
            .unwrap()
            .args([
                "package",
                "--input",
                proj.path().to_str().unwrap(),
                "--output",
                out.path().to_str().unwrap(),
            ])
            .assert()
            .success();

        Command::cargo_bin("zerok")
            .unwrap()
            .args(["inspect", "--path", out.path().to_str().unwrap()])
            .assert()
            .success()
            .stdout(contains("KPKG v1").and(contains("name = \"demo\"")));
    }
}
