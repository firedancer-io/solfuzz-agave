pub mod err_map;
pub mod mem_regions;

/* Note: these contants are different for Firedancer vs Agave.
For both, the virtual stack is 64x pages of 4kB each, with 4kB gaps.
- Firedancer allocates 64 * (4+4)kB and wastes, i.e. gaps are phisical.
- Agave allocates the 64 * 4kB, i.e. gaps are virtual and handled by vm_to_host(). */
pub const STACK_SIZE: usize = 64 * 4_096;
pub const STACK_GAP_SIZE: u64 = 4_096;
pub const HEAP_MAX: usize = 256 * 1024;
