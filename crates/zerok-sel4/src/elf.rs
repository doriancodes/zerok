#![allow(dead_code)]

extern crate alloc;

use core::{mem, ptr};

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_LOAD: u32 = 1;
const EM_AARCH64: u16 = 183;
const ELFCLASS64: u8 = 2;

fn align_up(x: usize, a: usize) -> usize {
    (x + (a - 1)) & !(a - 1)
}
fn align_down(x: usize, a: usize) -> usize {
    x & !(a - 1)
}

pub struct Loaded {
    pub entry: extern "C" fn() -> !,
}

/// Load a *PIE* ELF into a single contiguous buffer and return its entry.
/// NOTE: MVP loader (no relocations, permissions, or icache maintenance).
pub unsafe fn load_elf64_pie_in_place(blob: &[u8]) -> Result<Loaded, &'static str> {
    if blob.len() < mem::size_of::<Elf64Ehdr>() {
        return Err("short");
    }

    // Read ELF header unaligned (avoid UB).
    let ehdr: Elf64Ehdr = unsafe { core::ptr::read_unaligned(blob.as_ptr() as *const _) };
    if &ehdr.e_ident[0..4] != b"\x7FELF" {
        return Err("not elf");
    }
    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err("not 64");
    }
    if ehdr.e_machine != EM_AARCH64 {
        return Err("not aarch64");
    }
    if ehdr.e_ehsize as usize != core::mem::size_of::<Elf64Ehdr>() {
        return Err("bad ehsize");
    }
    if ehdr.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        return Err("bad phentsize");
    }

    let phoff = ehdr.e_phoff as usize;
    let phentsz = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;
    if phoff + phentsz * phnum > blob.len() {
        return Err("ph overflow");
    }

    // 1) Find the virtual span [min_vaddr, max_vaddr)
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;
    for i in 0..phnum {
        let off = phoff + i * phentsz;
        let ph: Elf64Phdr =
            unsafe { core::ptr::read_unaligned(blob.as_ptr().add(off) as *const _) };
        if ph.p_type != PT_LOAD {
            continue;
        }
        if (ph.p_offset as usize).saturating_add(ph.p_filesz as usize) > blob.len() {
            return Err("seg range");
        }
        let start = ph.p_vaddr as usize;
        let end = start.saturating_add(ph.p_memsz as usize);
        if end < start {
            return Err("overflow");
        }
        if start < min_vaddr {
            min_vaddr = start;
        }
        if end > max_vaddr {
            max_vaddr = end;
        }
    }
    if min_vaddr == usize::MAX {
        return Err("no loadable segs");
    }

    // 2) Allocate one RW buffer covering the span
    let page = 4096usize;
    let span_start = align_down(min_vaddr, page);
    let span_end = align_up(max_vaddr, page);
    let span_len = span_end.checked_sub(span_start).ok_or("span")?;

    use alloc::alloc::{Layout, alloc_zeroed};
    let layout = Layout::from_size_align(span_len, page.max(8)).map_err(|_| "layout")?;
    let base_dst = unsafe { alloc_zeroed(layout) };
    if base_dst.is_null() {
        return Err("oom");
    }

    // 3) Copy each PT_LOAD segment to base_dst + (p_vaddr - span_start)
    for i in 0..phnum {
        let off = phoff + i * phentsz;
        let ph: Elf64Phdr =
            unsafe { core::ptr::read_unaligned(blob.as_ptr().add(off) as *const _) };
        if ph.p_type != PT_LOAD {
            continue;
        }

        let file_off = ph.p_offset as usize;
        let file_sz = ph.p_filesz as usize;
        let vaddr = ph.p_vaddr as usize;
        let dst_off = vaddr.checked_sub(span_start).ok_or("dst off")?;

        unsafe {
            ptr::copy_nonoverlapping(blob.as_ptr().add(file_off), base_dst.add(dst_off), file_sz);
            // tail up to p_memsz is already zeroed by alloc_zeroed
        }
    }

    // 4) Adjust entry pointer: base + (e_entry - span_start)
    let entry = ehdr.e_entry as usize;
    let entry_off = entry.checked_sub(span_start).ok_or("entry underflow")?;
    let entry_ptr = unsafe { base_dst.add(entry_off) };
    let entry_fn: extern "C" fn() -> ! =
        unsafe { core::mem::transmute::<*mut u8, extern "C" fn() -> !>(entry_ptr) };

    Ok(Loaded { entry: entry_fn })
}
