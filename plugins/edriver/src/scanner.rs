// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rootkit anti-tampering scanner.
//
// The BPF programs in probes/process_rootkit.h are attached as uprobes to
// the two functions defined here.  When Rust calls them, the CPU registers
// carry the arguments; the BPF uprobe fires at function entry and reads those
// registers to snapshot kernel data.
//
// ABI: Rust `extern "C"` uses the System V AMD64 ABI on x86-64:
//   arg1 → rdi (PT_REGS_PARM1), arg2 → rsi (PT_REGS_PARM2)
// This replaces the old Go 1.17+ register ABI (ax/bx/cx) used previously.

use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::raw::c_char;

// ---------------------------------------------------------------------------
// Uprobe target functions
// ---------------------------------------------------------------------------
//
// These functions MUST remain #[no_mangle] extern "C" so that:
//   1. libbpf-rs can find their symbol in the binary at load time, and
//   2. the compiler emits a standard prologue that sets up the parameter
//      registers before the uprobe fires.
//
// `core::hint::black_box` prevents the optimiser from discarding the
// arguments before the uprobe has a chance to read the registers.

/// Uprobe target: syscall-table scanner.
///
/// For each entry, Rust passes the kernel address of `sys_call_table` and the
/// entry index.  The BPF program reads `table[index]` from kernel memory and
/// emits an ANTI_RKT_SCT event if the handler looks hooked.
///
/// # Safety
/// `table` is a kernel virtual address; it is never dereferenced in userspace.
#[no_mangle]
pub unsafe extern "C" fn trigger_sct_scan(table: *const u64, index: u64) {
    // The uprobe fires here and reads (table, index) from rdi/rsi.
    // black_box ensures the arguments are materialised in registers.
    core::hint::black_box((table, index));
}

/// Uprobe target: kernel-module scanner.
///
/// Rust passes a monotonically-increasing module index and the NUL-terminated
/// module name.  The BPF program emits an ANTI_RKT_MODULE event so that
/// userspace can compare the kernel-visible module list against `/proc/modules`.
///
/// # Safety
/// `name` must point to a valid NUL-terminated string for the duration of the
/// call; it is owned by a `CString` local in the calling frame.
#[no_mangle]
pub unsafe extern "C" fn trigger_module_scan(index: u64, name: *const c_char) {
    core::hint::black_box((index, name));
}

// ---------------------------------------------------------------------------
// Scanning logic
// ---------------------------------------------------------------------------

/// Search `/proc/kallsyms` for `sym_name` and return its address.
///
/// Returns `None` if the symbol is not found or the file is unreadable
/// (e.g. when running without CAP_SYSLOG / kptr_restrict > 1).
fn find_kallsym(sym_name: &str) -> Option<u64> {
    let file = fs::File::open("/proc/kallsyms").ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        let mut parts = line.split_whitespace();
        let addr_str = parts.next()?;
        let _kind = parts.next()?;
        let name = parts.next()?;
        if name == sym_name {
            return u64::from_str_radix(addr_str, 16).ok();
        }
    }
    None
}

/// Scan the live syscall table for hooked entries.
///
/// Reads `sys_call_table` from `/proc/kallsyms`, then calls
/// [`trigger_sct_scan`] once per entry (indices 0–511).  Each call triggers
/// the `uprobe/trigger_sct_scan` BPF program which emits a kernel-side event
/// with the actual handler address.
pub fn scan_syscall_table() {
    let addr = match find_kallsym("sys_call_table") {
        Some(a) if a != 0 => a,
        _ => {
            log::warn!("scan_syscall_table: sys_call_table not found in kallsyms");
            return;
        }
    };
    let table = addr as *const u64;
    for i in 0u64..512 {
        // SAFETY: table is a kernel address; trigger_sct_scan never
        // dereferences it in userspace — only the BPF uprobe does.
        unsafe { trigger_sct_scan(table, i) };
    }
}

/// Enumerate loaded kernel modules and report them via BPF uprobes.
///
/// Reads `/proc/modules` and calls [`trigger_module_scan`] for each line.
/// The BPF program records the name so userspace can detect hidden modules.
pub fn scan_modules() {
    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(e) => {
            log::warn!("scan_modules: failed to read /proc/modules: {e}");
            return;
        }
    };
    for (idx, line) in content.lines().enumerate() {
        let name = match line.split_whitespace().next() {
            Some(n) => n,
            None => continue,
        };
        // Build a NUL-terminated name; keep it alive across the call.
        let cname = match CString::new(name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // SAFETY: cname outlives the trigger_module_scan call.
        unsafe { trigger_module_scan(idx as u64, cname.as_ptr()) };
    }
}

/// Run a full rootkit scan: syscall table + loaded modules.
///
/// Intended to be called periodically (e.g. every 60 s) from the BPF manager
/// thread pool.  Both scans are independent; a failure in one does not abort
/// the other.
pub fn run_scan() {
    scan_syscall_table();
    scan_modules();
}
