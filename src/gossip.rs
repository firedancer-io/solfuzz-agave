use std::ffi::c_int;

use bincode::Options;
use solana_gossip::protocol::Protocol;
use solana_sanitize::Sanitize;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_gossip_message_deserialize_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *const u8,
    in_sz: u64,
) -> c_int {
    let bincode_opts = bincode::options()
        .with_limit(1232)
        .with_fixint_encoding()
        .reject_trailing_bytes();

    let ok = if in_sz == 0 {
        bincode_opts
            .deserialize::<Protocol>(&[])
            .map(|msg| msg.sanitize().is_ok())
            .unwrap_or(false)
    } else if in_sz > 1232 || in_ptr.is_null() {
        false
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
        bincode_opts
            .deserialize::<Protocol>(bytes)
            .map(|msg| msg.sanitize().is_ok())
            .unwrap_or(false)
    };

    if out_psz.is_null() || out_ptr.is_null() {
        return 0;
    }
    let out_cap = unsafe { *out_psz } as usize;
    if out_cap < 1 {
        return 0;
    }
    unsafe {
        *out_ptr = ok as u8;
        *out_psz = 1;
    }
    1
}
