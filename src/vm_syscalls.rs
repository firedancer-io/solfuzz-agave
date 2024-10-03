use crate::{
    load_builtins,
    proto::{SyscallContext, SyscallEffects},
    utils::err_map::unpack_stable_result,
    utils::vm::mem_regions,
    utils::vm::HEAP_MAX,
    utils::vm::STACK_GAP_SIZE,
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
    solana_rbpf::{
        ebpf,
        memory_region::{MemoryMapping, MemoryRegion},
        program::{BuiltinProgram, SBPFVersion},
        vm::EbpfVm,
    },
};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction_context::{TransactionAccount, TransactionContext};
use solana_sdk::{
    account::AccountSharedData, clock::Clock, epoch_schedule::EpochSchedule, rent::Rent,
    sysvar::SysvarId,
};
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

fn copy_memory_prefix(dst: &mut [u8], src: &[u8]) {
    let size = dst.len().min(src.len());
    dst[..size].copy_from_slice(&src[..size]);
}

fn execute_vm_syscall(input: SyscallContext) -> Option<SyscallEffects> {
    let instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;

    let feature_set = instr_ctx.feature_set;

    let program_runtime_environment_v1 =
        create_program_runtime_environment_v1(&feature_set, &ComputeBudget::default(), true, false)
            .unwrap();

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

    // TODO: support different versions
    let sbpf_version = &SBPFVersion::V1;

    // Set up memory mapping
    let vm_ctx = input.vm_ctx.unwrap();
    // Follow FD harness behavior
    if vm_ctx.heap_max as usize > HEAP_MAX {
        return None;
    }

    let rodata = vm_ctx.rodata;
    let mut stack = vec![0; STACK_SIZE];
    let mut heap = vec![0; vm_ctx.heap_max as usize];
    let mut regions = vec![
        MemoryRegion::new_readonly(&rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, STACK_GAP_SIZE),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
    ];
    let mut input_data_regions = vm_ctx.input_data_regions.clone();
    mem_regions::setup_input_regions(&mut regions, &mut input_data_regions);

    let memory_mapping = match MemoryMapping::new(
        regions,
        program_runtime_environment_v1.get_config(),
        sbpf_version,
    ) {
        Ok(mapping) => mapping,
        Err(_) => return None,
    };

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
    let mut vm = EbpfVm::new(
        loader,
        &SBPFVersion::V1,
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
        copy_memory_prefix(&mut heap, &syscall_invocation.heap_prefix);
        copy_memory_prefix(&mut stack, &syscall_invocation.stack_prefix);
    }

    // Actually invoke the syscall

    // Invoke the syscall
    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry()
        .lookup_by_name(&input.syscall_invocation?.function_name)?;
    vm.invoke_function(syscall_func);

    // Unwrap and return the effects of the syscall
    let program_id = instr_ctx.instruction.program_id;
    let program_result = vm.program_result;
    let (error, error_kind, r0) = unpack_stable_result(program_result, &vm.context_object_pointer, &program_id);
    Some(SyscallEffects {
        // Register 0 doesn't seem to contain the result, maybe we're missing some code from agave.
        // Regardless, the result is available in vm.program_result, so we can return it from there.
        r0,
        cu_avail: vm.context_object_pointer.get_remaining(),
        heap,
        stack,
        input_data_regions: mem_regions::extract_input_data_regions(&vm.memory_mapping),
        inputdata: vec![], // deprecated
        rodata,
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
