use std::ffi::c_int;

use prost::Message;

/// Gossip v2 conformance harness: returns protobuf-encoded GossipEffects with
/// the full decoded message structure for differential comparison.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_gossip_decode_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *const u8,
    in_sz: u64,
) -> c_int {
    if out_psz.is_null() || out_ptr.is_null() {
        return 0;
    }
    let input = if in_sz == 0 {
        &[]
    } else if in_ptr.is_null() {
        return 0;
    } else {
        unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) }
    };

    let effects = solana_gossip::gossip_decode_to_effects(input);
    let out_vec = effects.encode_to_vec();
    let out_cap = unsafe { *out_psz } as usize;
    if out_vec.len() > out_cap {
        return 0;
    }
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };
    1
}

/// Legacy gossip v1 harness: returns a single byte (1 = valid, 0 = invalid).
/// Delegates to the v2 harness and extracts the `valid` field.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_gossip_message_deserialize_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *const u8,
    in_sz: u64,
) -> c_int {
    if out_psz.is_null() || out_ptr.is_null() {
        return 0;
    }
    let input = if in_sz == 0 {
        &[]
    } else if in_ptr.is_null() {
        return 0;
    } else {
        unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) }
    };

    let effects = solana_gossip::gossip_decode_to_effects(input);
    let out_cap = unsafe { *out_psz } as usize;
    if out_cap < 1 {
        return 0;
    }
    unsafe {
        *out_ptr = effects.valid as u8;
        *out_psz = 1;
    }
    1
}
