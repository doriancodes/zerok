use anyhow::{Context, Result};
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use zerok_ipc::read_framed;

fn main() -> Result<()> {
    // Control socket is FD 3
    let mut ctl = unsafe { UnixStream::from_raw_fd(3) };
    let (plan, bin) = read_framed(&mut ctl).context("read plan/bin")?;

    // 1) Stage executable (tmp + fsync + atomic rename). Audit-visible path.
    let target = Path::new(&plan.exec_dir).join(&plan.exec_name);
    stage_tmp_atomic(&target, &bin).with_context(|| format!("stage {}", target.display()))?;

    // 2) Apply sandbox *here* (NO_NEW_PRIVS, unshare, mounts, cgroups, Landlock, seccomp, drop caps/uids)
    //    Keep this path single-threaded and syscall-focused.
    //    (left as TODOs—you can add them incrementally)

    // 3) Execve. Replace ourselves with the target. Never returns on success.
    exec_now(&target, &plan.argv, &plan.env)
        .with_context(|| format!("exec {}", target.display()))?;
    Ok(())
}

/// Write to hidden tmp, fsync, chmod 0555, atomic rename to `dest`.
fn stage_tmp_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    use std::fs::{File, OpenOptions, Permissions, create_dir_all, set_permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let parent = dest.parent().context("dest has no parent")?;
    create_dir_all(parent).with_context(|| format!("mkdir -p {}", parent.display()))?;

    let tmp = parent.join(format!(".{}.tmp", nanoid::nanoid!(8)));
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;

    // Write all + fsync
    rustix::io::write(&f, bytes).context("write payload")?;
    rustix::fs::fsync(&f).ok();

    // chmod 0555
    let mut p: Permissions = f.metadata()?.permissions();
    p.set_mode(0o555);
    set_permissions(&tmp, p)?;

    drop(f); // close writer to avoid ETXTBUSY

    // Atomic rename into place
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;

    // fsync directory to persist the rename
    let dfd = OpenOptions::new().read(true).open(parent)?;
    rustix::fs::fsync(&dfd).ok();

    Ok(())
}

fn exec_now(path: &Path, argv: &[String], env: &[(String, String)]) -> Result<!> {
    use nix::unistd::execve;
    use std::ffi::CString;

    let prog = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut av: Vec<CString> = Vec::with_capacity(argv.len().max(1));
    if argv.is_empty() {
        av.push(CString::new("app").unwrap());
    } else {
        for a in argv {
            av.push(CString::new(a.as_str()).unwrap());
        }
    }
    let avp: Vec<&std::ffi::CStr> = av.iter().map(|s| s.as_c_str()).collect();

    let envc: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
        .collect();
    let envp: Vec<&std::ffi::CStr> = envc.iter().map(|s| s.as_c_str()).collect();

    unsafe { execve(&prog, &avp, &envp) }?;
    unreachable!("execve returned");
}
