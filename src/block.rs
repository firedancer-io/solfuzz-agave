// Upstreamed: agave v4.3 carries this harness at runtime/src/conformance/block.rs
// (gated on solana-runtime's `conformance` feature). Kept as a re-export so the
// harness tracks agave instead of being re-ported on every version bump.
pub use solana_runtime::conformance::block::{execute_block, sol_compat_block_execute_v1};
