use crate::{
    proto::{SyscallContext, SyscallEffects, VmContext},
    utils::{
        err_map,
        vm::{mem_regions, HEAP_MAX, STACK_SIZE},
    },
    InstrContext, SnapshotInvokeContext,
};
// feature removed from feature set surface in 3.0; direct mapping toggled via SVMFeatureSet flags
use agave_syscalls;
use bincode::Error;
use prost::Message;
use solana_compute_budget::compute_budget::SVMTransactionExecutionCost;
use solana_instruction::AccountMeta;
use solana_program_runtime::serialization::serialize_parameters;
use solana_program_runtime::{
    invoke_context::{EnvironmentConfig, InvokeContext},
    mem_pool::VmMemoryPool,
};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    declare_builtin_function,
    ebpf::{self, HOST_ALIGN},
    elf::Executable,
    error::{EbpfError, StableResult},
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::RegisterTraceEntry, // renamed in Agave v3.1
    verifier::RequisiteVerifier,
    vm::{ContextObject, EbpfVm},
};
use solana_stable_layout::stable_vec::StableVec;
use solana_svm_log_collector::LogCollector;
use std::ffi::c_int;

declare_builtin_function!(
    SyscallStub,
    fn rust(
        _invoke_context: &mut TestContextObject,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        // TODO: deduct CUs?
        Ok(0)
    }
);

/// Simple instruction meter for testing
#[derive(Debug, Clone, Default)]
pub struct TestContextObject {
    /// Contains the register state at every instruction in order of execution
    pub trace_log: Vec<RegisterTraceEntry>,
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

// Agave v3.1 moves register tracing into the runtime.
impl ContextObject for TestContextObject {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TestContextObject {
    /// Initialize with instruction meter
    pub fn new(remaining: u64) -> Self {
        Self {
            trace_log: Vec::new(),
            remaining,
        }
    }

    /// Compares an interpreter trace and a JIT trace.
    ///
    /// The log of the JIT can be longer because it only validates the instruction meter at branches.
    pub fn compare_trace_log(interpreter: &Self, jit: &Self) -> bool {
        let interpreter = interpreter.trace_log.as_slice();
        let mut jit = jit.trace_log.as_slice();
        if jit.len() > interpreter.len() {
            jit = &jit[0..interpreter.len()];
        }
        interpreter == jit
    }
}

/* Set to true to make debugging easier

WARNING: CU validation works differently in the
interpreter vs. JIT. You may get CU mismatches you
otherwise wouldn't see when fuzzing against the JIT.

FD targets conformance with the JIT, not interprerter. */
const USE_INTERPRETER: bool = false;

/* Set to true to dump registers[0..12] of every instruction
execution (dumped after execution). Please leave disabled
for fuzzing. */
const ENABLE_TRACE_DUMP: bool = false;

#[no_mangle]
pub unsafe extern "C" fn sol_compat_vm_interp_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if USE_INTERPRETER {
        eprintln!("WARNING: Using interpreter instead of the JIT. This is not the fuzz default.");
    }
    let in_slice = std::slice::from_raw_parts(in_ptr, in_sz as usize);
    let Ok(syscall_context) = SyscallContext::decode(in_slice) else {
        return 0;
    };

    let Some(syscall_effects) = execute_vm_interp(syscall_context) else {
        return 0;
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

pub fn vec_rtrim_zeros(v: &[u8]) -> Vec<u8> {
    if let Some(i) = v.iter().rposition(|x| *x != 0) {
        return v[..i.saturating_add(1)].into();
    }
    vec![]
}

// We are actually executing the JIT-compiled program here
pub fn execute_vm_interp(syscall_context: SyscallContext) -> Option<SyscallEffects> {
    let mut instr_ctx: InstrContext = syscall_context.instr_ctx?.try_into().ok()?;

    let Some(vm_ctx) = syscall_context.vm_ctx else {
        // Match FD behavior: skip test if vm_ctx is missing
        return None;
    };
    let sbpf_version = match vm_ctx.sbpf_version {
        1 => SBPFVersion::V1,
        2 => SBPFVersion::V2,
        3 => SBPFVersion::V3,
        _ => SBPFVersion::V0,
    };

    // Extract values before mutable borrow
    let program_id = instr_ctx.instruction.program_id;
    let instruction_data = instr_ctx.instruction.data.to_vec();
    let runtime_features = instr_ctx.feature_set.runtime_features();
    let feature_set_snapshot = instr_ctx.feature_set.clone();
    let instruction_accounts_snapshot: StableVec<AccountMeta> = instr_ctx
        .instruction
        .accounts
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();
    let initial_cu_avail = instr_ctx.cu_avail;

    let (
        mut transaction_context,
        sysvar_cache,
        mut program_cache_for_tx_batch,
        blockhash,
        lamports_per_signature,
        compute_budget,
    ) = crate::create_invoke_context_fields(&mut instr_ctx)?;

    let log_collector = LogCollector::new_ref();

    // Get accounts first (this borrow is released when instr_accounts is created)
    let instr_accounts =
        crate::get_instr_accounts(&transaction_context, &instruction_accounts_snapshot);

    // Create ProgramRuntimeEnvironments
    let program_runtime_environment_v1 = agave_syscalls::create_program_runtime_environment_v1(
        &runtime_features,
        &compute_budget.to_budget(),
        false,                                      /* deployment */
        std::env::var("ENABLE_VM_TRACING").is_ok(), /* debugging_features */
    )
    .unwrap();
    let environments = solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments {
        program_runtime_v1: std::sync::Arc::new(program_runtime_environment_v1),
        ..solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments::default()
    };

    // Now create EnvironmentConfig (accounts borrow is released, callback borrow is separate)
    let callback_context = SnapshotInvokeContext::new(feature_set_snapshot);

    let mut invoke_ctx = InvokeContext::new(
        &mut transaction_context,
        &mut program_cache_for_tx_batch,
        EnvironmentConfig::new(
            blockhash,
            lamports_per_signature,
            &callback_context,
            &runtime_features,
            &environments,
            &environments,
            &sysvar_cache,
        ),
        Some(log_collector.clone()),
        compute_budget.to_budget(),
        SVMTransactionExecutionCost::new_with_defaults(
            runtime_features.increase_cpi_account_info_limit,
        ),
    );

    let program_idx = invoke_ctx
        .transaction_context
        .find_index_of_account(&program_id)?;

    let direct_mapping = invoke_ctx.get_feature_set().account_data_direct_mapping;
    let stricter_abi_and_runtime_constraints = invoke_ctx
        .get_feature_set()
        .stricter_abi_and_runtime_constraints;
    let mask_out_rent_epoch_in_vm_serialization = invoke_ctx
        .get_feature_set()
        .mask_out_rent_epoch_in_vm_serialization;

    invoke_ctx
        .transaction_context
        .configure_next_instruction_for_tests(program_idx, instr_accounts, instruction_data)
        .unwrap();

    match invoke_ctx.push() {
        Ok(_) => (),
        Err(_) => return None,
    }

    let caller_instr_ctx = invoke_ctx
        .transaction_context
        .get_current_instruction_context()
        .unwrap();
    let serialize_result = serialize_parameters(
        &caller_instr_ctx,
        stricter_abi_and_runtime_constraints,
        direct_mapping,
        mask_out_rent_epoch_in_vm_serialization,
    );
    let (_aligned_memory, input_memory_regions, acc_metadatas, _instruction_data_offset) =
        match serialize_result {
            Ok(result) => result,
            Err(e) => {
                // Return effects with the serialization error
                let error = crate::utils::err_map::instr_err_to_num(&e) as i64;
                return Some(SyscallEffects {
                    error,
                    error_kind: crate::proto::ErrKind::Instruction as i32,
                    cu_avail: invoke_ctx.get_remaining(),
                    ..Default::default()
                });
            }
        };

    let mut config = environments.program_runtime_v1.get_config().clone();
    config.enable_register_tracing = true;
    config.enabled_sbpf_versions = SBPFVersion::V0..=sbpf_version;

    invoke_ctx
        .set_syscall_context(solana_program_runtime::invoke_context::SyscallContext {
            allocator: solana_program_runtime::invoke_context::BpfAllocator::new(vm_ctx.heap_max),
            accounts_metadata: acc_metadatas, // TODO: accounts metadata for direct mapping support
        })
        .unwrap();

    let mut loader = BuiltinProgram::new_loader(config.clone());

    // Stub syscalls
    // Note: unstubbed_runtime is "v1", so syscalls are only registered for version < V3,
    //       i.e. unstubbed_runtime.get_function_registry(sbpf_version) does NOT work.
    let syscall_reg = environments.program_runtime_v1.get_function_registry();
    for (_key, (name, _func)) in syscall_reg.iter() {
        loader
            .register_function(std::str::from_utf8(name).unwrap(), SyscallStub::vm)
            .unwrap();
    }
    let loader = std::sync::Arc::new(loader);

    let function_registry = setup_internal_fn_registry(&vm_ctx, sbpf_version);
    let mut executable =
        Executable::from_text_bytes(&vm_ctx.rodata, loader, sbpf_version, function_registry)
            .unwrap();

    if executable.verify::<RequisiteVerifier>().is_err() {
        return Some(SyscallEffects {
            error: -2,
            ..Default::default()
        });
    }

    if !USE_INTERPRETER && executable.jit_compile().is_err() {
        return Some(SyscallEffects {
            error: -3,
            ..Default::default()
        });
    }

    // Setup TestContextObject
    let mut context_obj = TestContextObject::new(initial_cu_avail);

    // setup memory
    let heap_max = (vm_ctx.heap_max as usize).min(HEAP_MAX);
    let syscall_inv = syscall_context.syscall_invocation.unwrap();

    let mut mempool = VmMemoryPool::new();
    let rodata = AlignedMemory::<HOST_ALIGN>::from(&vm_ctx.rodata);
    let mut stack = mempool.get_stack(STACK_SIZE);
    let mut heap = AlignedMemory::<HOST_ALIGN>::from(&vec![0; heap_max]);

    let rodata_stack_heap = vec![
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
        return None;
    };

    let mut vm = EbpfVm::new(
        executable.get_loader().clone(),
        executable.get_sbpf_version(),
        &mut context_obj,
        memory_mapping,
        STACK_SIZE,
    );

    // Setup registers.
    // r1, r10, r11 are initialized by EbpfVm::new (r10) or EbpfVm::execute_program (r11)
    // r1 is initialized in Agave at ebpf::MM_INPUT_START.
    // Modifying them will most like break execution.
    // In syscalls we allow override them (especially r1) because that simulates the fact
    // that a program partially executed before reaching the syscall.
    // Here we want to test what happens when the program starts from the beginning.
    vm.registers[0] = vm_ctx.r0;
    vm.registers[1] = ebpf::MM_INPUT_START;
    vm.registers[2] = vm_ctx.r2;
    vm.registers[3] = vm_ctx.r3;
    vm.registers[4] = vm_ctx.r4;
    vm.registers[5] = vm_ctx.r5;
    vm.registers[6] = vm_ctx.r6;
    vm.registers[7] = vm_ctx.r7;
    vm.registers[8] = vm_ctx.r8;
    vm.registers[9] = vm_ctx.r9;
    // vm.registers[10] = vm_ctx.r10; // do not override
    // vm.registers[11] = vm_ctx.r11; // do not override

    mem_regions::copy_memory_prefix(heap.as_slice_mut(), &syscall_inv.heap_prefix);
    mem_regions::copy_memory_prefix(stack.as_slice_mut(), &syscall_inv.stack_prefix);

    let (_, result) = vm.execute_program(
        &executable,
        USE_INTERPRETER, /* use JIT for fuzzing, interpreter for debugging */
    );

    // The runtime now owns the register trace. We need to take it out of the VM.
    let register_trace = std::mem::take(&mut vm.register_trace);

    // When a program fails, the register in trace_log are not properly
    // captured (they represent the state at the end of the previous ix).
    // For simplicity, we ignore them.
    let out_registers = match result {
        StableResult::Err(_) => &[0; 12],
        StableResult::Ok(_) => register_trace.last()?,
    };

    if ENABLE_TRACE_DUMP {
        eprintln!("Tracing: {:x?}", register_trace);
    }

    /* We do not compare VM state on CU errors since CU consumption is
    not precisely defined when VM faults. */
    if matches!(
        result,
        StableResult::Err(EbpfError::ExceededMaxInstructions)
    ) {
        return Some(SyscallEffects {
            error: err_map::ebpf_err_to_num(&EbpfError::ExceededMaxInstructions).into(),
            ..Default::default()
        });
    }

    Some(SyscallEffects {
        error: match result {
            StableResult::Ok(_) => 0,
            StableResult::Err(ref ebpf_err) => err_map::ebpf_err_to_num(ebpf_err).into(),
        },
        r0: out_registers[0],
        r1: out_registers[1],
        r2: out_registers[2],
        r3: out_registers[3],
        r4: out_registers[4],
        r5: out_registers[5],
        r6: out_registers[6],
        r7: out_registers[7],
        r8: out_registers[8],
        r9: out_registers[9],
        r10: out_registers[10],
        cu_avail: vm.context_object_pointer.get_remaining(),
        frame_count: vm.call_depth,
        heap: heap.as_slice().into(),
        /* Compress stack by removing right-most 0s, mainly to save 256kB space when stack is unused */
        stack: vec_rtrim_zeros(stack.as_slice()),
        rodata: rodata.as_slice().into(),
        input_data_regions: mem_regions::extract_input_data_regions(&vm.memory_mapping),
        log: vec![],
        pc: match register_trace.last() {
            Some(regs) => regs[11],
            None => vm.registers[11],
        },
        ..Default::default()
    })
}

/* This sets up a function registry based on a Firedancer-loaded SBPF program.
The key difference is call immediates are hashed based on their target pc,
not the function symbol. Firedancer maintains a bit vector of all valid call
destinations[1], which the interpreter uses during the CALL_IMM instruction.

To mimic that behavior here, we iterate through the valid call destinations
in vm_ctx.call_whitelist, and register the pc hash as an entry in the registry.

This effectively behaves the same as the FD bit vector, but with some technical
differences that may cause issues. Most notably, FunctionRegistry operates as
a AHashMap, while FD's bit vector is a simple array. Out of bounds queries are
non-issue here, but require explicit handling in FD. This causes a slight
difference in error checks in CALL_IMM, which we handle in process_result.

[1](https://github.com/firedancer-io/firedancer/blob/93cea434dfe2f728f2ab4746590972644c06b863/src/ballet/sbpf/fd_sbpf_loader.h#L27). */
fn setup_internal_fn_registry(
    vm_ctx: &VmContext,
    sbpf_version: SBPFVersion,
) -> FunctionRegistry<usize> {
    let mut fn_reg = FunctionRegistry::default();
    let max_pc = vm_ctx.rodata.len() / 8;

    // register entry point
    let entry_pc = (vm_ctx.entry_pc as usize).min(max_pc.saturating_sub(1));
    let hash = if sbpf_version.enable_stricter_elf_headers() {
        entry_pc as u32
    } else {
        ebpf::hash_symbol_name(b"entrypoint")
    };
    let _ = fn_reg.register_function(hash, b"entrypoint", entry_pc);

    let call_whitelist = &vm_ctx.call_whitelist;
    for (byte_idx, byte) in call_whitelist.iter().enumerate() {
        for bit_idx in 0..8 {
            if (byte & (1 << bit_idx)) != 0 {
                let pc = byte_idx.saturating_mul(8).saturating_add(bit_idx);
                // ignore invalid pc, i.e. assume the test was set up correctly.
                // registering fn beyond max_pc segfaults inside the JIT.
                if pc < max_pc {
                    let hash = if sbpf_version.enable_stricter_elf_headers() {
                        pc as u32
                    } else {
                        ebpf::hash_symbol_name(&u64::to_le_bytes(pc as u64))
                    };
                    let _ = fn_reg.register_function(hash, b"fn", pc);
                }
            }
        }
    }

    // https://github.com/anza-xyz/sbpf/blob/v0.11.1/src/elf.rs#L529
    // in vm v3, the function at 0 is always registered
    if sbpf_version.enable_stricter_elf_headers() {
        let _ = fn_reg.register_function(0, b"fn0", 0);
    }

    fn_reg
}
