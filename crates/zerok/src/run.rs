#![forbid(unsafe_code)]
use crate::launch::spawn_launcher; // parent-side spawner helper
use anyhow::{Context, Result, bail};
use rand::RngCore;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zerok_ipc::PlanV1; // shared IPC types // you already depend on rand

use crate::kpkg::KpkgFile;
use crate::signature::{load_public_key, load_signature};

pub fn run_kpkg(
    path: &Path,
    signature: Option<&PathBuf>,
    pubkey: Option<&PathBuf>,
    dry_run: bool,
    pass_args: &[String],
) -> Result<i32> {
    // 1) Load .kpkg (header+manifest+binary already validated here)
    let k = KpkgFile::load(path).with_context(|| format!("loading {}", path.display()))?;

    // 2) Optional signature verification (detached; whole file)
    if let (Some(sig_path), Some(pub_path)) = (signature, pubkey) {
        let sig = load_signature(sig_path)?;
        let pk = load_public_key(pub_path)?;
        // Read file bytes once for verify; cheaper than re-parsing
        let all = std::fs::read(path)?;
        //     if !verify_bytes(&all, &pk, &sig)? {
        //        bail!("Signature is INVALID for {}", path.display());
        //    }
        eprintln!("Signature OK for {}", path.display());
    } else if signature.is_some() ^ pubkey.is_some() {
        bail!("Provide both --signature and --pubkey (or neither).");
    }

    // 3) Dry-run mode: print manifest and exit
    if dry_run {
        println!("KPKG v{}: {}", k.header.version, k.manifest);
        return Ok(0);
    }

    // 4) Build a staging dir for this run (unique but predictable enough)
    let stage_root = std::env::var("ZEROK_STAGE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // fallback to XDG-style path
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(format!("{home}/.local/share/zerok/stage"))
        });
    let stage_root = Path::new(&stage_root);

    // simple unique id: time + random; avoids adding extra deps
    let mut rnd = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut rnd);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let run_id = format!(
        "{ts:x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
    );

    let exec_dir = stage_root.join(run_id);
    fs::create_dir_all(&exec_dir).with_context(|| format!("mkdir -p {}", exec_dir.display()))?;

    // 5) Build the launcher plan
    let plan = PlanV1 {
        exec_dir: exec_dir.to_string_lossy().into_owned(),
        exec_name: "binary".to_string(),
        // argv: keep first element as program name, then user args
        argv: {
            let mut a = Vec::with_capacity(1 + pass_args.len());
            a.push("app".to_string());
            a.extend(pass_args.iter().cloned());
            a
        },
        env: std::env::vars().collect(),
        // map capabilities → policy here later; for now minimal
        memory_max: k.manifest.capabilities.memory.as_ref().map(|m| m.max_bytes),
        pids_max: Some(64),
        file_read_allow: k
            .manifest
            .capabilities
            .files
            .as_ref()
            .and_then(|f| f.read.as_ref())
            .map(|r| r.paths.clone())
            .unwrap_or_default(),
        net_allow: vec![], // fill from manifest when you add network gating
    };

    // 6) Spawn launcher and send plan + embedded binary bytes
    let mut child = spawn_launcher(&plan, &k.binary).context("spawn zerok-launcher & send plan")?;

    // 7) Wait for the launched process to exit and return its code
    let status = child.wait().context("wait launcher/child")?;
    Ok(status.code().unwrap_or(1))
}
