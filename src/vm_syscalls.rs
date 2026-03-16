use crate::{
    utils::err_map::unpack_stable_result, utils::vm::mem_regions, utils::vm::HEAP_MAX,
    utils::vm::STACK_SIZE, InstrContext, SnapshotInvokeContext,
};
use prost::Message;
use protosol::protos::{SyscallContext, SyscallEffects};
use solana_compute_budget::compute_budget::SVMTransactionExecutionCost;
use solana_instruction::AccountMeta;
use solana_program_runtime::invoke_context::EnvironmentConfig;
use solana_program_runtime::serialization::serialize_parameters;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_program_runtime::{
    invoke_context::InvokeContext, loaded_programs::ProgramCacheForTxBatch,
};
use solana_pubkey::Pubkey;
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    ebpf::HOST_ALIGN,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, SBPFVersion},
    vm::{ContextObject, EbpfVm},
};
use solana_stable_layout::stable_vec::StableVec;
use solana_svm_feature_set::SVMFeatureSet;
use solana_svm_log_collector::LogCollector;
use solana_transaction_context::transaction::TransactionContext;
use std::ffi::c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_vm_syscall_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(syscall_context) = SyscallContext::decode(in_slice) else {
        return 0;
    };

    let Some(syscall_effects) = execute_vm_syscall(syscall_context) else {
        return 0;
    };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize) };
    let out_vec = syscall_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe { *out_psz = out_vec.len() as u64 };

    1
}

/* Drop the 'static objects created at the beginning of the function to avoid memory leaks */
fn cleanup_static_ptrs(
    transaction_context_ptr: usize,
    sysvar_cache_ptr: usize,
    program_cache_for_tx_batch_ptr: usize,
    runtime_features_ptr: usize,
    instr_ctx_ptr: usize,
    callback_context_ptr: usize,
    environments_ptr: usize,
) {
    unsafe {
        let _transaction_context_droppable =
            Box::from_raw(transaction_context_ptr as *mut TransactionContext);
        let _sysvar_cache_droppable = Box::from_raw(sysvar_cache_ptr as *mut SysvarCache);
        let _program_cache_for_tx_batch_droppable =
            Box::from_raw(program_cache_for_tx_batch_ptr as *mut ProgramCacheForTxBatch);
        let _runtime_features_droppable = Box::from_raw(runtime_features_ptr as *mut SVMFeatureSet);
        let _instr_ctx_droppable = Box::from_raw(instr_ctx_ptr as *mut InstrContext);
        let _callback_context_droppable =
            Box::from_raw(callback_context_ptr as *mut SnapshotInvokeContext);
        let _environments_droppable = Box::from_raw(
            environments_ptr
                as *mut solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments,
        );
    }
}

pub fn execute_vm_syscall(input: SyscallContext) -> Option<SyscallEffects> {
    let instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;
    let runtime_feature_set = instr_ctx.feature_set.runtime_features();
    let feature_set_snapshot = instr_ctx.feature_set.clone();

    // Extract values before moving/leaking
    let program_id = instr_ctx.instruction.program_id;
    let instruction_data = instr_ctx.instruction.data.to_vec();
    let instruction_accounts_snapshot: StableVec<AccountMeta> = instr_ctx
        .instruction
        .accounts
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();

    let instr_ctx = Box::leak(Box::new(instr_ctx));
    let instr_ctx_ptr = instr_ctx as *mut InstrContext as usize;

    let (
        transaction_context,
        sysvar_cache,
        program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
        environments,
    ) = crate::create_invoke_context_fields(instr_ctx)?;

    /* MemoryCowCallback requires moved objects to have the 'static lifetime
      so we promote them to 'static and drop at the end as we are sure they are not used anymore
    */
    let transaction_context = Box::leak(Box::new(transaction_context));
    let transaction_context_ptr = transaction_context as *mut TransactionContext as usize;
    let sysvar_cache = Box::leak(Box::new(sysvar_cache));
    let sysvar_cache_ptr = sysvar_cache as *mut SysvarCache as usize;
    let program_cache_for_tx_batch = Box::leak(Box::new(program_cache_for_tx_batch));
    let program_cache_for_tx_batch_ptr =
        program_cache_for_tx_batch as *mut ProgramCacheForTxBatch as usize;
    let runtime_features = Box::leak(Box::new(runtime_feature_set));
    let runtime_features_ptr = runtime_features as *const SVMFeatureSet as usize;

    if let Some(vm_ctx) = &input.vm_ctx {
        if let Some(return_data) = vm_ctx.return_data.clone() {
            let program_id = Pubkey::try_from(return_data.program_id).unwrap();
            transaction_context
                .set_return_data(program_id, return_data.data)
                .unwrap();
        }
    }

    let log_collector = LogCollector::new_ref();
    let instr_accounts =
        crate::get_instr_accounts(transaction_context, &instruction_accounts_snapshot);

    let environments = Box::leak(Box::new(environments));
    let environments_ptr = environments as *mut _ as usize;

    let callback_context = Box::leak(Box::new(SnapshotInvokeContext::new(feature_set_snapshot)));
    let callback_context_ptr = callback_context as *mut _ as usize;

    let mut invoke_ctx = InvokeContext::new(
        transaction_context,
        program_cache_for_tx_batch,
        EnvironmentConfig::new(
            blockhash,
            lamports_per_signature,
            callback_context,
            runtime_features,
            environments,
            environments,
            sysvar_cache,
        ),
        Some(log_collector.clone()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::new_with_defaults(
            runtime_features.increase_cpi_account_info_limit,
        ),
    );

    let program_idx = invoke_ctx
        .transaction_context
        .find_index_of_account(&program_id)
        .expect("invariant violation: program_id must be found in accounts");
    assert!(
        program_idx <= 255,
        "invariant violation: program_idx must be <= 255"
    );
    let direct_mapping = invoke_ctx.get_feature_set().account_data_direct_mapping;
    let stricter_abi_and_runtime_constraints = invoke_ctx
        .get_feature_set()
        .stricter_abi_and_runtime_constraints;
    invoke_ctx
        .transaction_context
        .configure_top_level_instruction_for_tests(program_idx, instr_accounts, instruction_data)
        .unwrap();

    match invoke_ctx.push() {
        Ok(_) => (),
        Err(_) => {
            cleanup_static_ptrs(
                transaction_context_ptr,
                sysvar_cache_ptr,
                program_cache_for_tx_batch_ptr,
                runtime_features_ptr,
                instr_ctx_ptr,
                callback_context_ptr,
                environments_ptr,
            );
            return None;
        }
    }

    let caller_instr_ctx = invoke_ctx
        .transaction_context
        .get_current_instruction_context()
        .unwrap();
    // Memory regions.
    // In Agave all memory regions are AlignedMemory::<HOST_ALIGN> == AlignedMemory::<16>,
    // i.e. they're all 16-byte aligned in the host.
    // The memory regions are:
    //   1. program rodata
    //   2. stack
    //   3. heap
    //   4. input data aka accounts
    // The stack gap size is 0 iff direct mapping is enabled.
    // serialize_parameters should never fail - the fuzzer now ensures
    // valid instruction account counts, so unwrap is safe here
    let (_aligned_memory, input_memory_regions, acc_metadatas, _instruction_data_offset) =
        serialize_parameters(
            &caller_instr_ctx,
            stricter_abi_and_runtime_constraints,
            direct_mapping,
        )
        .expect("invariant violation: serialize_parameters failed");

    let sbpf_version = SBPFVersion::V0;

    // Set up memory mapping
    let vm_ctx = input
        .vm_ctx
        .expect("invariant violation: vm_ctx must be present for every execution");
    // Follow FD harness behavior
    assert!(
        vm_ctx.heap_max as usize <= HEAP_MAX,
        "invariant violation: heap_max must be <= HEAP_MAX"
    );

    let config = environments.program_runtime_v1.get_config().clone();
    let Some((_, syscall_func)) = environments
        .program_runtime_v1
        .get_function_registry()
        .lookup_by_name(
            &input
                .syscall_invocation
                .clone()
                .unwrap_or_default()
                .function_name,
        )
    else {
        cleanup_static_ptrs(
            transaction_context_ptr,
            sysvar_cache_ptr,
            program_cache_for_tx_batch_ptr,
            runtime_features_ptr,
            instr_ctx_ptr,
            callback_context_ptr,
            environments_ptr,
        );
        return None;
    };

    let rodata = AlignedMemory::<HOST_ALIGN>::from(&vm_ctx.rodata);
    let mut stack = AlignedMemory::<HOST_ALIGN>::from(&vec![0; STACK_SIZE]);
    let mut heap = AlignedMemory::<HOST_ALIGN>::from(&vec![0; vm_ctx.heap_max as usize]);
    let rodata_stack_heap = vec![
        MemoryRegion::new_readonly(rodata.as_slice(), ebpf::MM_BYTECODE_START),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if sbpf_version.stack_frame_gaps() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ];
    let regions = rodata_stack_heap
        .into_iter()
        .chain(input_memory_regions)
        .collect();

    let Ok(memory_mapping) = MemoryMapping::new_with_access_violation_handler(
        regions,
        &config,
        sbpf_version,
        invoke_ctx
            .transaction_context
            .access_violation_handler(stricter_abi_and_runtime_constraints, direct_mapping),
    ) else {
        cleanup_static_ptrs(
            transaction_context_ptr,
            sysvar_cache_ptr,
            program_cache_for_tx_batch_ptr,
            runtime_features_ptr,
            instr_ctx_ptr,
            callback_context_ptr,
            environments_ptr,
        );
        return None;
    };

    invoke_ctx
        .set_syscall_context(solana_program_runtime::invoke_context::SyscallContext {
            allocator: solana_program_runtime::invoke_context::BpfAllocator::new(vm_ctx.heap_max),
            accounts_metadata: acc_metadatas,
        })
        .unwrap();

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_loader(config.clone()));
    let mut vm = EbpfVm::new(
        loader,
        sbpf_version,
        &mut invoke_ctx,
        memory_mapping,
        STACK_SIZE,
    );
    vm.registers[0] = vm_ctx.r0;
    vm.registers[1] = vm_ctx.r1;
    vm.registers[2] = vm_ctx.r2;
    vm.registers[3] = vm_ctx.r3;
    vm.registers[4] = vm_ctx.r4;
    vm.registers[5] = vm_ctx.r5;
    vm.registers[6] = vm_ctx.r6;
    vm.registers[7] = vm_ctx.r7;
    vm.registers[8] = vm_ctx.r8;
    vm.registers[9] = vm_ctx.r9;
    vm.registers[10] = vm_ctx.r10;
    vm.registers[11] = vm_ctx.r11;

    if let Some(syscall_invocation) = input.syscall_invocation {
        mem_regions::copy_memory_prefix(heap.as_slice_mut(), &syscall_invocation.heap_prefix);
        mem_regions::copy_memory_prefix(stack.as_slice_mut(), &syscall_invocation.stack_prefix);
    }

    // Invoke the syscall
    vm.invoke_function(syscall_func);

    // Unwrap and return the effects of the syscall
    let program_result = vm.program_result;
    let (error, error_kind, r0) =
        unpack_stable_result(program_result, vm.context_object_pointer, &program_id);

    cleanup_static_ptrs(
        transaction_context_ptr,
        sysvar_cache_ptr,
        program_cache_for_tx_batch_ptr,
        runtime_features_ptr,
        instr_ctx_ptr,
        callback_context_ptr,
        environments_ptr,
    );

    Some(SyscallEffects {
        // Register 0 doesn't seem to contain the result, maybe we're missing some code from agave.
        // Regardless, the result is available in vm.program_result, so we can return it from there.
        r0,
        // Registers are only for vm_interp
        r1: 0,
        r2: 0,
        r3: 0,
        r4: 0,
        r5: 0,
        r6: 0,
        r7: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        cu_avail: vm.context_object_pointer.get_remaining(),
        heap: heap.as_slice().into(),
        stack: stack.as_slice().into(),
        input_data_regions: mem_regions::extract_input_data_regions(&vm.memory_mapping),
        rodata: rodata.as_slice().into(),
        frame_count: vm.call_depth,
        error,
        error_kind: error_kind as i32,
        log: invoke_ctx
            .get_log_collector()?
            .borrow()
            .get_recorded_content()
            .join("\n")
            .into_bytes(),
        pc: 0,
    })
}
