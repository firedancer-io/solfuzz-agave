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
    let bytes = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let ok = bincode::options()
        .with_limit(1232)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize::<Protocol>(bytes)
        .map(|msg| msg.sanitize().is_ok())
        .unwrap_or(false);

    let out = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    if out.is_empty() {
        return 0;
    }
    out[0] = ok as u8;
    unsafe { *out_psz = 1 };
    1
}
