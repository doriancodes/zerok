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
