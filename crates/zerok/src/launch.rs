use anyhow::{Context, Result};
use nix::libc;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use zerok_ipc::{PlanV1, write_framed};

/// Spawn `zerok-launcher`, pass control socket on FD 3, send plan+binary.
/// Returns the Child handle so you can supervise/wait.
pub fn spawn_launcher(plan: &PlanV1, binary: &[u8]) -> Result<std::process::Child> {
    // Control channel
    let (mut parent_sock, child_sock) = UnixStream::pair().context("socketpair")?;
    let fd3 = child_sock.into_raw_fd();

    // Spawn the dedicated launcher binary (cleanest; not hacky)
    let mut cmd = Command::new("zerok-launcher");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Install FD 3 in the child process
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd3, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(fd3);
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("spawn zerok-launcher")?;

    // Send framed plan + binary bytes
    write_framed(&mut parent_sock, plan, binary).context("send plan+binary")?;

    Ok(child)
}
