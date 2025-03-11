use crate::{
    load_builtins,
    proto::{InstrEffects, SyscallContext, SyscallEffects},
    utils::{
        err_map::unpack_stable_result,
        vm::{mem_regions, HEAP_MAX, STACK_SIZE},
    },
    InstrContext,
};
use solana_bpf_loader_program::{
    serialization::serialize_parameters, syscalls::create_program_runtime_environment_v1,
};
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_feature_set::bpf_account_data_direct_mapping;
use solana_log_collector::LogCollector;
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    ebpf::HOST_ALIGN,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, SBPFVersion},
    vm::{ContextObject, EbpfVm},
};
use solana_program_runtime::{
    invoke_context::{EnvironmentConfig, InvokeContext},
    loaded_programs::ProgramCacheForTxBatch,
    mem_pool::VmMemoryPool,
    sysvar_cache::SysvarCache,
};
use solana_sdk::{
    account::{AccountSharedData, WritableAccount},
    entrypoint::MAX_PERMITTED_DATA_INCREASE,
    instruction::InstructionError,
    pubkey::Pubkey,
    rent::Rent,
    transaction_context::{
        IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
    },
};
use std::{cell::RefCell, rc::Rc, sync::Arc};

#[cfg(feature = "stub-agave")]
use {prost::Message, std::ffi::c_int};

// Requires "stub-agave" feature to be enabled
// Similar to src/vm_syscalls.rs
#[no_mangle]
#[cfg(feature = "stub-agave")]
pub unsafe extern "C" fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let syscall_ctx = match SyscallContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };
    let syscall_effects = match execute_vm_cpi_syscall(syscall_ctx) {
        Some(v) => v,
        None => return 0,
    };

    let out_slice = std::slice::from_raw_parts_mut(out_ptr, (*out_psz) as usize);
    let out_vec = syscall_effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    *out_psz = out_vec.len() as u64;

    1
}

// TODO: unify with other syscall harness after CPI fuzzing is stable
#[allow(dead_code)]
pub fn execute_vm_cpi_syscall(input: SyscallContext) -> Option<SyscallEffects> {
    let mut instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;

    let existing_pubkeys: Vec<_> = instr_ctx
        .accounts
        .iter()
        .map(|(pubkey, _)| pubkey)
        .collect();

    if !existing_pubkeys.contains(&&instr_ctx.instruction.program_id) {
        instr_ctx.accounts.push((
            instr_ctx.instruction.program_id,
            AccountSharedData::default().into(),
        ));
    }
    // Create invoke context
    // TODO: factor this into common code with lib.rs
    let mut transaction_accounts =
        Vec::<TransactionAccount>::with_capacity(instr_ctx.accounts.len() + 1);
    #[allow(deprecated)]
    instr_ctx
        .accounts
        .clone()
        .into_iter()
        .map(|(pubkey, account)| (pubkey, AccountSharedData::from(account)))
        .for_each(|x| transaction_accounts.push(x));

    let compute_budget = ComputeBudget {
        compute_unit_limit: instr_ctx.cu_avail,
        ..ComputeBudget::default()
    };
    let mut transaction_context = TransactionContext::new(
        transaction_accounts.clone(),
        Rent::default(),
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
    );

    // sigh ... What is this mess?
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    load_builtins(&mut program_cache_for_tx_batch, &instr_ctx.feature_set);

    let program_runtime_environment_v1 = create_program_runtime_environment_v1(
        &instr_ctx.feature_set,
        &ComputeBudget::default(),
        true,
        false,
    )
    .unwrap();
    let config = program_runtime_environment_v1.get_config();

    let sysvar_cache = SysvarCache::default();
    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = sysvar_cache
        .get_recent_blockhashes()
        .ok()
        .and_then(|x| (*x).last().cloned())
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    let environment_config = EnvironmentConfig::new(
        blockhash,
        lamports_per_signature,
        0,
        &|_| 0u64,
        Arc::new(instr_ctx.feature_set.clone()),
        &sysvar_cache,
    );
    let log_collector = LogCollector::new_ref();

    let invoke_context = RefCell::new(InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(log_collector.clone()),
        compute_budget,
    ));

    // Setup the instruction context in the invoke context
    let instr = &instr_ctx.instruction;
    let instr_accounts = crate::get_instr_accounts(&transaction_accounts, &instr.accounts);

    let program_idx_in_txn = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == instr_ctx.instruction.program_id)?
        as IndexOfAccount;

    let mut invoke_ctx = invoke_context.borrow_mut();
    let direct_mapping = invoke_ctx
        .get_feature_set()
        .is_active(&bpf_account_data_direct_mapping::id());

    invoke_ctx
        .transaction_context
        .get_next_instruction_context()
        .unwrap()
        .configure(
            &[program_idx_in_txn],
            instr_accounts.as_slice(),
            &instr.data,
        );
    drop(invoke_ctx);

    // Push the invoke context. This sets up the instruction context trace, which is used in the CPI Syscall.
    // Also pushes empty syscall context, which we will setup later
    let mut invoke_ctx = invoke_context.borrow_mut();

    match invoke_ctx.push() {
        Ok(_) => (),
        Err(_) => eprintln!("Failed to push invoke context"),
    }
    drop(invoke_ctx);

    let invoke_ctx = invoke_context.borrow_mut();
    let caller_instr_ctx = invoke_ctx
        .transaction_context
        .get_current_instruction_context()
        .unwrap();
    let (_aligned_memory, input_memory_regions, acc_metadatas) = serialize_parameters(
        invoke_ctx.transaction_context,
        caller_instr_ctx,
        !direct_mapping,
    )
    .unwrap();

    drop(invoke_ctx);

    // Setup syscall context in the invoke context
    let vm_ctx = input.vm_ctx.unwrap();

    let mut invoke_ctx: std::cell::RefMut<'_, InvokeContext<'_>> = invoke_context.borrow_mut();

    // Setup the CPI callback if there are exec effects
    #[cfg(feature = "stub-agave")]
    if let Some(exec_effects) = input.exec_effects {
        invoke_ctx.proc_instr_callback = Some(Box::new(
            move |txn_ctx: &mut TransactionContext,
                  instr_data: &[u8],
                  instr_accts: &[InstructionAccount],
                  prog_indices: &[IndexOfAccount]| {
                process_instruction_cpi_callback(
                    txn_ctx,
                    instr_data,
                    instr_accts,
                    prog_indices,
                    &exec_effects,
                )
            },
        ));
    }

    invoke_ctx
        .set_syscall_context(solana_program_runtime::invoke_context::SyscallContext {
            allocator: solana_program_runtime::invoke_context::BpfAllocator::new(vm_ctx.heap_max),
            accounts_metadata: acc_metadatas, // TODO: accounts metadata for direct mapping support
            trace_log: Vec::new(),
        })
        .unwrap();

    // Set up memory mapping
    let syscall_inv = input.syscall_invocation.unwrap();
    // Follow FD harness behavior for heap_max
    if vm_ctx.heap_max as usize > HEAP_MAX {
        return None;
    }

    let mut mempool = VmMemoryPool::new();
    let rodata = AlignedMemory::<HOST_ALIGN>::from(&vm_ctx.rodata);
    let syscall_fn_name = syscall_inv.function_name.clone();
    let mut stack = mempool.get_stack(STACK_SIZE);
    let mut heap = AlignedMemory::<HOST_ALIGN>::from(&vec![0; vm_ctx.heap_max as usize]);

    let rodata_stack_heap = vec![
        MemoryRegion::new_readonly(rodata.as_slice(), ebpf::MM_RODATA_START),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if config.enable_stack_frame_gaps {
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

    let sbpf_version = SBPFVersion::V0;

    let cow_cb_accounts = Rc::clone(invoke_ctx.transaction_context.accounts());
    let cow_cb = Box::new(move |index_in_transaction| {
        let mut account = cow_cb_accounts
            .try_borrow_mut(index_in_transaction as IndexOfAccount)
            .map_err(|_| ())?;
        cow_cb_accounts
            .touch(index_in_transaction as IndexOfAccount)
            .map_err(|_| ())?;

        if account.is_shared() {
            account.reserve(MAX_PERMITTED_DATA_INCREASE);
        }
        Ok(account.data_as_mut_slice().as_mut_ptr() as u64)
    });
    let memory_mapping = match MemoryMapping::new_with_cow(regions, cow_cb, config, sbpf_version) {
        Ok(mapping) => mapping,
        Err(_) => return None,
    };

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
    let mut vm = EbpfVm::new(
        loader,
        sbpf_version,
        &mut *invoke_ctx,
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

    mem_regions::copy_memory_prefix(heap.as_slice_mut(), &syscall_inv.heap_prefix);
    mem_regions::copy_memory_prefix(stack.as_slice_mut(), &syscall_inv.stack_prefix);

    // Invoke the syscall
    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry()
        .lookup_by_name(syscall_fn_name.as_slice())?;
    vm.invoke_function(syscall_func);

    // Unwrap and return the effects of the syscall
    let program_result = vm.program_result;
    let program_id = instr_ctx.instruction.program_id;
    let (error, error_kind, r0) =
        unpack_stable_result(program_result, vm.context_object_pointer, &program_id);
    Some(SyscallEffects {
        // Register 0 doesn't seem to contain the result, maybe we're missing some code from agave.
        // Regardless, the result is available in vm.program_result, so we can return it from there.
        error,
        error_kind: error_kind as i32,
        r0,
        cu_avail: vm.context_object_pointer.get_remaining(),
        heap: heap.as_slice().into(),
        stack: stack.as_slice().into(),
        rodata: rodata.as_slice().into(),
        input_data_regions: mem_regions::extract_input_data_regions(&vm.memory_mapping),
        frame_count: vm.call_depth,
        log: invoke_ctx
            .get_log_collector()?
            .borrow()
            .get_recorded_content()
            .join("\n")
            .into_bytes(),
        ..Default::default()
    })
}

#[allow(dead_code)]
fn process_instruction_cpi_callback(
    txn_ctx: &mut TransactionContext,
    instr_data: &[u8],
    instr_accts: &[InstructionAccount],
    prog_indices: &[IndexOfAccount],
    cpi_exec_effects: &InstrEffects,
) -> Result<(), InstructionError> {
    // Push the instruction context. Copied verbatim from InvokeContext::process_instruction
    txn_ctx
        .get_next_instruction_context()?
        .configure(prog_indices, instr_accts, instr_data);

    // Iterate through instruction accounts
    for instr_acct in instr_accts.iter() {
        let idx_in_txn = instr_acct.index_in_transaction;
        let acct_pubkey = txn_ctx.get_key_of_account_at_index(idx_in_txn)?;

        // Find (first) account in exec_effects.modified_accounts that matches the pubkey
        if let Some(acct_state) = cpi_exec_effects
            .modified_accounts
            .iter()
            .find(|modified| modified.address == acct_pubkey.to_bytes())
        {
            let Ok(acct_ref) = txn_ctx.get_account_at_index(idx_in_txn) else {
                continue;
            };
            let Ok(mut acct) = acct_ref.try_borrow_mut() else {
                continue;
            };

            // Update the account state
            acct.set_lamports(acct_state.lamports);
            acct.set_executable(acct_state.executable);
            acct.set_rent_epoch(acct_state.rent_epoch);
            if !acct_state.data.is_empty() {
                acct.set_data_from_slice(&acct_state.data);
            }

            if let Ok(new_owner_bytes) = <[u8; 32]>::try_from(acct_state.owner.clone()) {
                let new_owner = Pubkey::new_from_array(new_owner_bytes);
                acct.set_owner(new_owner);
            }
        }
    }
    Ok(())
}
