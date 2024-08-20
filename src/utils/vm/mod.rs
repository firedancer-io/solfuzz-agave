pub mod err_map;
pub mod mem_regions;

/*  FD_VM_STACK_MAX
https://github.com/firedancer-io/firedancer/blob/0ccc457b957f77838a9c642527b8f47532911c5a/src/flamenco/vm/fd_vm_base.h#L109 */
pub const STACK_SIZE: usize = 524288;
pub const HEAP_MAX: usize = 256*1024;
