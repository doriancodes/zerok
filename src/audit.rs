#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use goblin::elf;
use regex::Regex;
use std::{collections::BTreeSet, fs, path::Path};

fn map_machine(m: u16) -> &'static str {
    use goblin::elf::header::*;
    match m {
        EM_X86_64 => "EM_X86_64",
        EM_AARCH64 => "EM_AARCH64",
        EM_386 => "EM_386",
        EM_ARM => "EM_ARM",
        EM_RISCV => "EM_RISCV",
        EM_MIPS => "EM_MIPS",
        _ => "UNKNOWN",
    }
}

pub fn audit_elf<P: AsRef<Path>>(path: P) -> Result<()> {
    let buf =
        fs::read(&path).with_context(|| format!("failed to read {}", path.as_ref().display()))?;

    // --- Basic ELF parse (goblin) ---
    let elf = elf::Elf::parse(&buf).map_err(|e| anyhow!("not a valid ELF: {e}"))?;
    let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    let has_gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);
    let bind_now = elf
        .dynamic
        .as_ref()
        .map(|dyninfo| {
            use goblin::elf::dynamic::*;
            let mut now = false;
            for d in &dyninfo.dyns {
                match d.d_tag {
                    DT_BIND_NOW => now = true,
                    DT_FLAGS => {
                        let v = d.d_val;
                        if (v & (DF_BIND_NOW as u64)) != 0 {
                            now = true;
                        }
                    }
                    DT_FLAGS_1 => {
                        let v = d.d_val;
                        if (v & (DF_1_NOW as u64)) != 0 {
                            now = true;
                        }
                    }
                    _ => {}
                }
            }
            now
        })
        .unwrap_or(false);

    // NX: check PT_GNU_STACK executable flag
    let nx_enabled = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK)
        .map(|ph| ph.p_flags & goblin::elf::program_header::PF_X == 0)
        .unwrap_or(true);

    // Imported symbols we care about (network/files/process/etc.)
    let mut imports = BTreeSet::new();
    if !elf.dynsyms.is_empty() {
        for sym in elf.dynsyms.iter() {
            if sym.st_name == 0 {
                continue;
            }
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if is_interesting_symbol(name) {
                    imports.insert(name.to_string());
                }
            }
        }
    }

    // Needed shared libraries
    let needed: BTreeSet<_> = elf.libraries.iter().map(|s| s.to_string()).collect();

    // --------------- strings: use section-bounded scan -----------------
    let ascii_strings = strings_from_elf_sections(&elf, &buf, 4); // Strings: harvest candidate hosts and config paths

    let path_re = Regex::new(r#"(/(?:etc|var|usr|home)/[^\s"']+)"#).unwrap();

    let mut paths = BTreeSet::new();
    for s in &ascii_strings {
        if let Some(c) = path_re.captures(s) {
            paths.insert(c[1].to_string());
        }
    }
    let net_intent = has_net_intent_from_imports(&imports);

    // Report
    println!("== ELF Audit ==");
    println!("File: {}", path.as_ref().display());
    println!(
        "Arch: {} ({})",
        elf.header.e_machine,
        map_machine(elf.header.e_machine)
    );
    // println!("Arch: {}", arch);
    println!("PIE : {}", yesno(is_pie));
    println!("NX  : {}", yesno(nx_enabled));
    println!("RELRO (GNU_RELRO): {}", yesno(has_gnu_relro));
    println!("BIND_NOW         : {}", yesno(bind_now));

    let full_relro = has_gnu_relro && bind_now;
    println!("Full RELRO          : {}", yesno(full_relro));

    if !needed.is_empty() {
        println!("\nShared libs (DT_NEEDED):");
        for n in &needed {
            println!("  - {}", n);
        }
    }

    if !imports.is_empty() {
        println!("\nInteresting imports:");
        for i in &imports {
            println!("  - {}", i);
        }
    }

    if !paths.is_empty() {
        println!("\nCandidate config/data paths (from strings):");
        for p in &paths {
            println!("  - {}", p);
        }
    }

    println!("\nNetwork capability required: {}", yesno(net_intent));

    // Suggested manifest skeleton
    println!("\n== Suggested manifest (skeleton) ==");
    println!(
        "name = \"{}\"",
        path.as_ref()
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("app")
    );
    println!("version = \"0.0.0\"");
    println!();
    println!("[capabilities.memory]");
    println!("max_bytes = 134217728  # TODO: adjust");
    if !paths.is_empty() {
        println!("\n[capabilities.files.read]");
        print!("paths = [");
        print_csv(&paths);
        println!("]");
    }
    if net_intent {
        println!("\n[capabilities.network.connect]");
        print!("hosts = []\n");
    }

    Ok(())
}

pub fn audit_trace<P: AsRef<Path>>(path: P) -> Result<()> {
    let s = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.as_ref().display()))?;

    // very light extraction from strace text logs
    let host_re =
        Regex::new(r#"([a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,})(?::(\d{2,5}))?"#).unwrap();
    let path_re = Regex::new(r#""(/[^"\s]+)""#).unwrap();

    let mut hosts = BTreeSet::new();
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();

    for line in s.lines() {
        for c in host_re.captures_iter(line) {
            let host = match (c.get(1), c.get(2)) {
                (Some(h), Some(p)) => format!("{}:{}", h.as_str(), p.as_str()),
                (Some(h), None) => h.as_str().to_string(),
                _ => continue,
            };
            hosts.insert(host);
        }

        if line.contains("open") || line.contains("openat") {
            for c in path_re.captures_iter(line) {
                let p = c[1].to_string();
                // naive: decide RO/RW based on flags in the line
                if line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT")
                {
                    writes.insert(p);
                } else {
                    reads.insert(p);
                }
            }
        }
    }

    println!("== Trace Audit ==");
    println!("File: {}", path.as_ref().display());

    if !reads.is_empty() {
        println!("\nRead paths:");
        for p in &reads {
            println!("  - {}", p);
        }
    }
    if !writes.is_empty() {
        println!("\nWrite paths:");
        for p in &writes {
            println!("  - {}", p);
        }
    }
    if !hosts.is_empty() {
        println!("\nHosts:");
        for h in &hosts {
            println!("  - {}", h);
        }
    }

    // Suggested manifest from trace
    println!("\n== Suggested manifest (from trace) ==");
    println!("name = \"app\"");
    println!("version = \"0.0.0\"");
    println!();
    println!("[capabilities.memory]");
    println!("max_bytes = 134217728  # TODO: infer from mmap/brk");
    if !reads.is_empty() {
        println!("\n[capabilities.files.read]");
        print!("paths = [");
        print_csv(&reads);
        println!("]");
    }
    if !hosts.is_empty() {
        println!("\n[capabilities.network.connect]");
        print!("hosts = [");
        print_csv(&hosts);
        println!("]");
    }
    if !writes.is_empty() {
        eprintln!(
            "\n⚠️  Write attempts detected; write capabilities are not modeled yet. Consider redesign or read-only policies."
        );
    }

    Ok(())
}

fn is_interesting_symbol(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "open",
        "openat",
        "fopen",
        "read",
        "write",
        "close",
        "socket",
        "connect",
        "send",
        "recv",
        "getaddrinfo",
        "fork",
        "vfork",
        "clone",
        "execve",
        "system",
        "popen",
        "ptrace",
        "ioctl",
        "mprotect",
        "dlopen",
        "setuid",
        "capset",
        "futex",
        "prctl",
    ];
    KEYWORDS.iter().any(|k| name.contains(k))
}

/// Extract ASCII-ish strings from a byte slice
fn extract_ascii_strings(buf: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in buf {
        if (0x20..=0x7E).contains(&b) || b == b'\t' {
            cur.push(b);
        } else if !cur.is_empty() {
            if cur.len() >= min {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    out.push(s);
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        if let Ok(s) = String::from_utf8(cur) {
            out.push(s);
        }
    }
    out
}

/// Collect strings **only** from allocated, non-exec PROGBITS sections.
/// Falls back to whole-file if sections look bogus.
fn strings_from_elf_sections<'a>(elf: &elf::Elf<'a>, bytes: &'a [u8], min: usize) -> Vec<String> {
    use goblin::elf::section_header::*;
    let mut out = Vec::new();
    let mut any = false;

    for sh in &elf.section_headers {
        let is_alloc = (sh.sh_flags & (SHF_ALLOC as u64)) != 0;
        let is_prog = sh.sh_type == SHT_PROGBITS;
        let is_exec = (sh.sh_flags & (SHF_EXECINSTR as u64)) != 0;
        if is_alloc && is_prog && !is_exec {
            let start = sh.sh_offset as usize;
            let end = start.saturating_add(sh.sh_size as usize);
            if end <= bytes.len() {
                out.extend(extract_ascii_strings(&bytes[start..end], min));
                any = true;
            }
        }
    }

    if any {
        out
    } else {
        extract_ascii_strings(bytes, min)
    }
}

fn has_net_intent_from_imports(imports: &std::collections::BTreeSet<String>) -> bool {
    // cover common libc + OpenSSL entry points; `contains` handles versioned names (e.g. "connect@@GLIBC_2.2.5")
    const NET_SYMS: &[&str] = &[
        "socket",
        "socketpair",
        "bind",
        "connect",
        "listen",
        "accept",
        "accept4",
        "getsockname",
        "getpeername",
        "send",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
        "setsockopt",
        "getsockopt",
        "shutdown",
        // libc name variants you sometimes see
        "__socket",
        "__connect",
        "__send",
        "__recv",
        // common TLS front doors (optional, helps catch HTTPS tools)
        "SSL_",
        "TLS_",
        "BIO_",
        // DNS helpers
        "getaddrinfo",
        "getnameinfo",
        "gethostbyname",
        "gethostbyaddr",
    ];
    imports
        .iter()
        .any(|s| NET_SYMS.iter().any(|p| s.contains(p)))
}

fn print_csv(set: &BTreeSet<String>) {
    let mut first = true;
    for v in set {
        if !first {
            print!(", ");
        }
        first = false;
        print!("{:?}", v); // quoted TOML string
    }
}

fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
