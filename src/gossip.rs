use std::ffi::c_int;

/// Gossip v2 conformance harness: returns protobuf-encoded GossipEffects with
/// the full decoded message structure for differential comparison.
///
/// NOTE: gossip_decode_to_effects is not available in solana-gossip v3.1.14.
/// This harness is stubbed out and always returns 0 (not supported).
/// TODO: Port gossip conformance patches from agave-v4.0.0-beta.6-patches
/// (gossip/src/protocol.rs, gossip/tests/conformance/) to enable this harness.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_gossip_decode_v1(
    _out_ptr: *mut u8,
    _out_psz: *mut u64,
    _in_ptr: *const u8,
    _in_sz: u64,
) -> c_int {
    0
}
