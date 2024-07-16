use crate::{
    load_builtins,
    proto::{SyscallContext, SyscallEffects},
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
        ebpf::{self, MM_INPUT_START},
        error::StableResult,
        memory_region::{MemoryMapping, MemoryRegion},
        program::{BuiltinProgram, SBPFVersion},
        vm::{Config, EbpfVm},
    },
};
use solana_sdk::transaction_context::{TransactionAccount, TransactionContext};
use solana_sdk::{account::AccountSharedData, rent::Rent};
use std::{ffi::c_int, sync::Arc};

const STACK_SIZE: usize = 524288; // FD_VM_STACK_MAX

const TRUNCATE_ERROR_WORDS: usize = 9;

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

fn truncate_error_str(s: String) -> String {
    s.split_whitespace()
        .take(TRUNCATE_ERROR_WORDS)
        .collect::<Vec<_>>()
        .join(" ")
}

fn execute_vm_syscall(input: SyscallContext) -> Option<SyscallEffects> {
    let instr_ctx: InstrContext = input.instr_ctx?.try_into().ok()?;
    let feature_set = instr_ctx.feature_set;

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
    load_builtins(&mut program_cache_for_tx_batch);

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
    let sbpf_version = &SBPFVersion::V2;

    // Set up memory mapping
    let vm_ctx = input.vm_ctx.unwrap();
    let rodata = vm_ctx.rodata;
    let mut stack = vec![0; STACK_SIZE];
    let heap_max = vm_ctx.heap_max;
    let mut heap = vec![0; heap_max as usize];
    let mut regions = vec![
        MemoryRegion::new_readonly(&rodata, ebpf::MM_PROGRAM_START),
        MemoryRegion::new_writable_gapped(&mut stack, ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
    ];
    let mut input_data_regions = vm_ctx.input_data_regions.clone();
    for input_data_region in &mut input_data_regions {
        if input_data_region.is_writable {
            regions.push(MemoryRegion::new_writable(
                input_data_region.content.as_mut_slice(),
                MM_INPUT_START + input_data_region.offset,
            ));
        } else {
            regions.push(MemoryRegion::new_readonly(
                input_data_region.content.as_slice(),
                MM_INPUT_START + input_data_region.offset,
            ));
        }
    }
    let config = &Config {
        aligned_memory_mapping: true,
        enable_sbpf_v2: true,
        ..Config::default()
    };
    let memory_mapping = MemoryMapping::new(regions, config, sbpf_version).unwrap();

    // Set up the vm instance
    let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
    let mut vm = EbpfVm::new(
        loader,
        &SBPFVersion::V2,
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
        heap.copy_from_slice(&syscall_invocation.heap_prefix);
    }

    // Actually invoke the syscall
    let program_runtime_environment_v1 =
        create_program_runtime_environment_v1(&feature_set, &ComputeBudget::default(), true, false)
            .unwrap();

    // Invoke the syscall
    let (_, syscall_func) = program_runtime_environment_v1
        .get_function_registry()
        .lookup_by_name(&input.syscall_invocation?.function_name)?;
    vm.invoke_function(syscall_func);

    // Unwrap and return the effects of the syscall
    let program_result = vm.program_result;
    Some(SyscallEffects {
        // Error matching.
        // Errors are `EbpfError`` and in particular we need to match EbpfError::Syscall == Box<dyn Error>.
        // In turn, the dynamic error can have multiple types, for example InstructionError or SyscallError.
        // And... we need to match them against Firedancer errors.
        // To make things as simple as possible, we match explicit error messages to Firedancer error numbers.
        // Unfortunately even this is not that simple, because most error messages contain dynamic fields.
        // So, the current solutio truncates the error message to TRUNCATE_ERROR_WORDS words, where the constant
        // is chosen to be large enough to distinguish errors, and small enough to avoid variable strings.
        error: match program_result {
            StableResult::Ok(_) => 0,
            StableResult::Err(ref ebpf_error) => {
                match truncate_error_str(ebpf_error.to_string()).as_str() {
                    // InstructionError
                    // https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/program/src/instruction.rs#L33
                    "Syscall error: Computational budget exceeded" => 16,
                    // SyscallError
                    // https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/programs/bpf_loader/src/syscalls/mod.rs#L77
                    "Syscall error: Hashing too many sequences" => 1,
                    "Syscall error: InvalidLength" => 1,
                    "Syscall error: InvalidAttribute" => 1,
                    // ??
                    "Syscall error: Access violation in program section at address" => 13,
                    "Syscall error: Access violation in stack section at address" => 13,
                    "Syscall error: Access violation in heap section at address" => 13,
                    "Syscall error: Access violation in unknown section at address" => 13,
                    // https://github.com/solana-labs/solana/blob/v1.18.12/sdk/program/src/poseidon.rs#L13
                    "Syscall error: Invalid parameters." => 1,
                    "Syscall error: Invalid endianness." => 1,
                    // EbpfError
                    // https://github.com/solana-labs/rbpf/blob/main/src/error.rs#L17
                    _ => -1,
                }
            }
        },
        // Register 0 doesn't seem to contain the result, maybe we're missing some code from agave.
        // Regardless, the result is available in vm.program_result, so we can return it from there.
        r0: match program_result {
            StableResult::Ok(n) => n,
            StableResult::Err(_) => 0,
        },
        cu_avail: vm.context_object_pointer.get_remaining(),
        heap,
        stack,
        inputdata: input_data_regions
            .iter()
            .flat_map(|region| region.content.clone())
            .collect(),
        frame_count: vm.call_depth,
        log: invoke_context
            .get_log_collector()?
            .borrow()
            .get_recorded_content()
            .iter()
            .fold(String::new(), |mut acc, s| {
                acc.push_str(s);
                acc
            })
            .into_bytes(),
    })
}
