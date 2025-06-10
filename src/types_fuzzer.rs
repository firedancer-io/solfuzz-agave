use crate::proto::{TypeContext, TypeEffects};
use crate::types::types_map_generated::TYPE_PROCESSORS;
use prost::Message;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_int;
use std::thread_local;

// Define a custom allocator that can detect and handle large allocations
struct LimitedAllocator {
    inner: System,
}

// Thread-local flag to determine if size limiting is active
thread_local! {
    static SIZE_LIMITING_ACTIVE: Cell<bool> = Cell::new(false);
}

unsafe impl GlobalAlloc for LimitedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Only check allocation size if limiting is active
        let mut should_limit = false;
        SIZE_LIMITING_ACTIVE.with(|active| {
            should_limit = active.get();
        });

        if should_limit {
            // Set a reasonable maximum allocation size
            const MAX_ALLOC: usize = 10 * 1024 * 1024; // 10 MB

            if layout.size() > MAX_ALLOC {
                panic!(
                    "Allocation of {} bytes exceeds limit of {} bytes",
                    layout.size(),
                    MAX_ALLOC
                );
            }
        }

        self.inner.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout)
    }
}

// Install our custom allocator as the global allocator
#[global_allocator]
static ALLOCATOR: LimitedAllocator = LimitedAllocator { inner: System };

// Helper struct that enables/disables allocation limiting within its scope
struct AllocationLimitGuard;

impl AllocationLimitGuard {
    fn new() -> Self {
        SIZE_LIMITING_ACTIVE.with(|active| {
            active.set(true);
        });
        AllocationLimitGuard
    }
}

impl Drop for AllocationLimitGuard {
    fn drop(&mut self) {
        SIZE_LIMITING_ACTIVE.with(|active| {
            active.set(false);
        });
    }
}

#[no_mangle]
pub unsafe extern "C" fn sol_compat_type_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    // Enable allocation limiting for this function
    let _guard = AllocationLimitGuard::new();

    /* Need this check since solfuzz may feed empty inputs */
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }

    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let type_ctx = match TypeContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let type_effects = match execute_type(type_ctx) {
        Some(effects) => effects,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = type_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

pub fn execute_type(input: TypeContext) -> Option<TypeEffects> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if input.content.is_empty() {
            return None;
        }

        let bincode_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(input.content.as_ptr(), input.content.len()) };

        TYPE_PROCESSORS
            .get(&bincode_slice[0])
            .map(|processor| processor(bincode_slice))
            .unwrap_or_else(|| None)
    }));

    // Handle any panic that might have occurred
    match result {
        Ok(effects) => effects,
        Err(_) => Some(TypeEffects {
            result: 1,
            ..Default::default()
        }),
    }
}
