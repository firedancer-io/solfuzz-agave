use crate::elf_loader::execute_elf_loader;

/// Macro to generate `sol_compat_*_execute_v2` FFI functions
///
/// This macro reduces code duplication for flatbuffer-based execution harnesses.
///
/// # Arguments
/// * `$fn_name` - The name of the C-compatible function to generate
/// * `$context_type` - The flatbuffers-generated context type (e.g., `TxnContext`)
/// * `$execute_fn` - The Rust function that performs the actual execution
/// * `$module_path` - The module path containing the flatbuffers types
///
/// # Example
/// ```ignore
/// define_sol_compat_execute_v2!(
///     sol_compat_txn_execute_v2,
///     TxnContext,
///     execute_transaction,
///     txn_generated
/// );
/// ```
macro_rules! define_sol_compat_execute_v2 {
    ($fn_name:ident, $context_type:ident, $execute_fn:ident, $module_path:path) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(
            out_ptr: *mut u8,
            out_psz: *mut u64,
            in_ptr: *mut u8,
            in_sz: u64,
        ) -> ::std::ffi::c_int {
            use $module_path as context_module;

            // Validate input pointers
            if in_ptr.is_null() || in_sz == 0 {
                return -1;
            }

            // Parse input slice as flatbuffers root
            let in_slice = ::std::slice::from_raw_parts(in_ptr, in_sz as usize);
            let context =
                ::flatbuffers::root_unchecked::<context_module::$context_type<'_>>(in_slice);

            // Setup output slice and build effects
            let out_slice = ::std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
            $crate::FBB.with(|fbb| {
                let mut effects_builder = fbb.borrow_mut();
                effects_builder.reset();
                $execute_fn(&context, &mut effects_builder);

                let out_data = effects_builder.finished_data();
                out_slice[..out_data.len()].copy_from_slice(out_data);
                *out_psz = out_data.len() as u64;
            });

            return 0;
        }
    };
}

/* ELF Loader */
define_sol_compat_execute_v2!(
    sol_compat_elf_loader_v2,
    ELFLoaderCtx,
    execute_elf_loader,
    crate::elf_generated
);
