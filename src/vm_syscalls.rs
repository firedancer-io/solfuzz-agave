use crate::{
    load_builtins,
    proto::{SyscallContext, SyscallEffects},
    utils::err_map::unpack_stable_result,
    utils::vm::mem_regions,
    utils::vm::HEAP_MAX,
    utils::vm::STACK_SIZE,
    InstrContext,
};
use prost::Message;
use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_log_collector::LogCollector;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_program_runtime::{invoke_context::EnvironmentConfig, solana_rbpf::vm::ContextObject};
use solana_program_runtime::{
    invoke_context::InvokeContext,
    loaded_programs::ProgramCacheForTxBatch,
    mem_pool::VmMemoryPool,
    solana_rbpf::{
        aligned_memory::AlignedMemory,
        ebpf,
        ebpf::HOST_ALIGN,
        memory_region::{MemoryMapping, MemoryRegion},
        program::{BuiltinProgram, SBPFVersion},
        vm::EbpfVm,
    },
};
use solana_sdk::transaction_context::{TransactionAccount, TransactionContext};
use solana_sdk::{
    account::AccountSharedData,
    clock::Clock,
    epoch_schedule::EpochSchedule,
    rent::Rent,
    sysvar::{last_restart_slot, SysvarId},
};
use solana_sdk::{pubkey::Pubkey, transaction_context::IndexOfAccount};
use std::{ffi::c_int, sync::Arc};

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_syscall_execute_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let syscall_context = match SyscallContext::decode(in_slice) {
        Ok(context) => context,
        Err(_) => return 0,
    };

    let syscall_effects = match execute_vm_syscall(syscall_context) {
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

pub fn execute_vm_syscall(input: SyscallContext) -> Option<SyscallEffects> {
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

    let feature_set = instr_ctx.feature_set;

    let program_runtime_environment_v1 =
        create_program_runtime_environment_v1(&feature_set, &ComputeBudget::default(), true, false)
            .unwrap();
    let config = program_runtime_environment_v1.get_config();

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

    if let Some(vm_ctx) = &input.vm_ctx {
        if let Some(return_data) = vm_ctx.return_data.clone() {
            let program_id = Pubkey::try_from(return_data.program_id).unwrap();
            transaction_context
                .set_return_data(program_id, return_data.data)
                .unwrap();
        }
    }

    // sigh ... What is this mess?
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    load_builtins(&mut program_cache_for_tx_batch);

    let mut sysvar_cache = SysvarCache::default();

    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if let Some(account) = instr_ctx.accounts.iter().find(|(key, _)| key == pubkey) {
            if account.1.lamports > 0 {
                callbackback(&account.1.data);
            }
        }
    });

    // Any default values for missing sysvar values should be set here
    sysvar_cache.fill_missing_entries(|pubkey, callbackback| {
        if *pubkey == Clock::id() {
            // Set the default clock slot to something arbitrary beyond 0
            // This prevents DelayedVisibility errors when executing BPF programs
            let default_clock = Clock {
                slot: 10,
                ..Default::default()
            };
            let clock_data = bincode::serialize(&default_clock).unwrap();
            callbackback(&clock_data);
        }
        if *pubkey == EpochSchedule::id() {
            callbackback(&bincode::serialize(&EpochSchedule::default()).unwrap());
        }
        if *pubkey == Rent::id() {
            callbackback(&bincode::serialize(&Rent::default()).unwrap());
        }
        if *pubkey == last_restart_slot::id() {
            let slot_val = 5000_u64;
            callbackback(&bincode::serialize(&slot_val).unwrap());
        }
    });

    #[allow(deprecated)]
    let (blockhash, lamports_per_signature) = sysvar_cache
        .get_recent_blockhashes()
        .ok()
        .and_then(|x| (*x).last().cloned())
        .map(|x| (x.blockhash, x.fee_calculator.lamports_per_signature))
        .unwrap_or_default();

    let environment_config = EnvironmentConfig::new(
        blockhash,
        None,
        None,
        Arc::new(feature_set.clone()),
        lamports_per_signature,
        &sysvar_cache,
    );
    let log_collector = LogCollector::new_ref();
    let mut invoke_context = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        environment_config,
        Some(log_collector.clone()),
        compute_budget,
    );

    let instr = &instr_ctx.instruction;
    let instr_accounts = crate::get_instr_accounts(&transaction_accounts, &instr.accounts);

    let caller_instr_ctx = invoke_context
        .transaction_context
        .get_next_instruction_context()
        .unwrap();

    let program_idx_in_txn = transaction_accounts
        .iter()
        .position(|(pubkey, _)| *pubkey == instr_ctx.instruction.program_id)?
        as IndexOfAccount;

    caller_instr_ctx.configure(
        &[program_idx_in_txn],
        instr_accounts.as_slice(),
        &instr.data,
    );

    match invoke_context.push() {
        Ok(_) => (),
        Err(_) => eprintln!("Failed to push invoke context"),
    }
    invoke_context
        .set_syscall_context(solana_program_runtime::invoke_context::SyscallContext {
            allocator: solana_program_runtime::invoke_context::BpfAllocator::new(
                input.vm_ctx.clone().unwrap().heap_max,
            ),
            accounts_metadata: vec![], // TODO: accounts metadata for direct mapping support
            trace_log: Vec::new(),
        })
        .unwrap();
    // TODO: support different versions
    let sbpf_version = SBPFVersion::V0;

    // Set up memory mapping
    let vm_ctx = input.vm_ctx.unwrap();
    // Follow FD harness behavior
    if vm_ctx.heap_max as usize > HEAP_MAX {
        return None;
    }

    // Memory regions.
    // In Agave all memory regions are AlignedMemory::<HOST_ALIGN> == AlignedMemory::<16>,
    // i.e. they're all 16-byte aligned in the host.
    // The memory regions are:
    //   1. program rodata
    //   2. stack
    //   3. heap
    //   4. input data aka accounts
    // The stack gap is size is 0 iff direct mapping is enabled.
    // There's some extra quirks:
    //   - heap size is MIN_HEAP_FRAME_BYTES..=MAX_HEAP_FRAME_BYTES
    //   - input data (at least when direct mapping is off) is 1 single map of all
    //     serialized accounts (and each account is serialized to a multiple of 16 bytes)
    // In this implementation, however:
    //   - heap can be smaller than MIN_HEAP_FRAME_BYTES
    //   - input data is made of multiple regions, and regions don't necessarily have
    //     length multiple of 16, i.e. virtual addresses may be unaligned
    // These differences allow us to test more edge cases.
    let mut mempool = VmMemoryPool::new();
    let rodata = AlignedMemory::<HOST_ALIGN>::from(&vm_ctx.rodata);
    let mut stack = mempool.get_stack(STACK_SIZE);
    // let mut heap = mempool.get_heap(heap_max); // this would force MIN_HEAP_FRAME_BYTES
    let mut heap = AlignedMemory::<HOST_ALIGN>::from(&vec![0; vm_ctx.heap_max as usize]);
    let mut regions = vec![
        MemoryRegion::new_readonly(rodata.as_slice(), ebpf::MM_RODATA_START),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ];
    let mut aligned_regions = Vec::new();
    mem_regions::setup_input_regions(
        &mut regions,
        &mut aligned_regions,
        &vm_ctx.input_data_regions,
    );

    let memory_mapping = match MemoryMapping::new(regions, config, sbpf_version) {
        Ok(mapping) => mapping,
        Err(_) => return None,
    };

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
    let mut vm = EbpfVm::new(
        loader,
        sbpf_version,
        &mut invoke_context,
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

    if let Some(syscall_invocation) = input.syscall_invocation.clone() {
        mem_regions::copy_memory_prefix(heap.as_slice_mut(), &syscall_invocation.heap_prefix);
        mem_regions::copy_memory_prefix(stack.as_slice_mut(), &syscall_invocation.stack_prefix);
    }

    // Actually invoke the syscall

    // Invoke the syscall
    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry(sbpf_version)
        .lookup_by_name(&input.syscall_invocation?.function_name)?;
    vm.invoke_function(syscall_func);

    // Unwrap and return the effects of the syscall
    let program_id = instr_ctx.instruction.program_id;
    let program_result = vm.program_result;
    let (error, error_kind, r0) =
        unpack_stable_result(program_result, vm.context_object_pointer, &program_id);
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
        inputdata: vec![], // deprecated
        rodata: rodata.as_slice().into(),
        frame_count: vm.call_depth,
        error,
        error_kind: error_kind as i32,
        log: invoke_context
            .get_log_collector()?
            .borrow()
            .get_recorded_content()
            .join("\n")
            .into_bytes(),
        pc: 0,
    })
}
