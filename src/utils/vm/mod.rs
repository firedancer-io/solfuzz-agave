pub mod err_map;
pub mod mem_regions;

/* Note: these contants are different for Firedancer vs Agave.
For both, the virtual stack is 64x pages of 4kB each, with 4kB gaps.
- Firedancer allocates 64 * (4+4)kB and wastes, i.e. gaps are phisical.
- Agave allocates the 64 * 4kB, i.e. gaps are virtual and handled by vm_to_host().
  - We need to x2 this size to include stack gaps, which are treated as physical gaps in the memory region based on this: https://github.com/solana-labs/rbpf/blob/57139e9e1fca4f01155f7d99bc55cdcc25b0bc04/src/jit.rs#L1476
    For some reason, Agave's rbpf::Config::stack_size() misses out on this: https://github.com/solana-labs/rbpf/blob/57139e9e1fca4f01155f7d99bc55cdcc25b0bc04/src/vm.rs#L90
  - FIXME: check that agave's rbpf::Config::stack_size()'s omission of this multiplier is wrong */
pub const STACK_SIZE: usize = 64 * 4_096 * 2;
pub const STACK_GAP_SIZE: u64 = 4_096;
pub const HEAP_MAX: usize = 256 * 1024;
