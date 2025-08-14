#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use linked_list_allocator::LockedHeap;
use sel4_root_task::root_task;

mod elf;

// ===== Global allocator backed by a static heap =====
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    // keep it simple: log and suspend
    sel4::debug_println!(
        "alloc error: size={} align={}",
        layout.size(),
        layout.align()
    );
    sel4::init_thread::suspend_self()
}

// 512 KiB heap; tweak as needed
const HEAP_SIZE: usize = 512 * 1024;
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[root_task]
fn main(_bootinfo: &sel4::BootInfoPtr) -> ! {
    unsafe {
        let heap_ptr: *mut u8 = core::ptr::addr_of_mut!(HEAP_MEM) as *mut u8;
        ALLOCATOR.lock().init(heap_ptr, HEAP_SIZE);
    }

    sel4::debug_println!("zerok-sel4: loading payload…");

    // For now, include a raw ELF file (not a .kpkg yet)
    let payload: &[u8] = include_bytes!("../payload.elf");

    let loaded = unsafe { elf::load_elf64_pie_in_place(payload) }.expect("elf load");
    sel4::debug_println!("jumping to payload entry…");

    (loaded.entry)()
}
