use crate::{
    proto::SyscallContext,
    vm_syscalls::execute_vm_syscall
};
use prost::Message;
use std::ffi::c_int;


// Requires "stub-agave" feature to be enabled
// Similar to src/vm_syscalls.rs
#[no_mangle]
#[cfg(feature = "stub-agave")]
pub unsafe extern "C" fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let syscall_ctx = match SyscallContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let syscall_effects = match execute_vm_syscall(syscall_ctx) {
        Some(v) => v,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = syscall_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}