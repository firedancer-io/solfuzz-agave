use crate::proto::{AcceptsShred, ShredBinary};
use prost::Message;
use solana_ledger::shred::Shred;
use std::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_shred_parse_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);

    let binary_shred = match ShredBinary::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };

    let shred_bytes = binary_shred.data;

    let accepts_shred = match Shred::new_from_serialized_shred(shred_bytes) {
        // Not sure why this memory leaks
        Ok(_) => AcceptsShred { valid: true },
        Err(_) => AcceptsShred { valid: false },
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_bytes = accepts_shred.encode_to_vec();
    if out_bytes.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_bytes.len()].copy_from_slice(&out_bytes);
    *out_psz = out_bytes.len() as u64;

    1
}
